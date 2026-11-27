/**
 * Postgres shard store — the shared state behind the coordinator.
 *
 * Lives on the SEASON pool (the same database as `bot_node_status` and the
 * dashboard session store), so active-active sharding needs **no new database**
 * and no extra service. Every node opens the same small table and the database
 * serialises the claims.
 */

const { seasonPool } = require('../../server/seasonDb');

const DDL = [
    `CREATE TABLE IF NOT EXISTS bot_shard_assignment (
        shard_id INTEGER PRIMARY KEY,
        owner_role VARCHAR(20) NOT NULL,
        owner_node VARCHAR(255) NOT NULL,
        epoch BIGINT NOT NULL DEFAULT 1,
        assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
        renewed_at TIMESTAMP NOT NULL DEFAULT NOW()
    )`,
    'CREATE INDEX IF NOT EXISTS bot_shard_assignment_owner_idx ON bot_shard_assignment (owner_role)',
    // Telemetry the status surfaces need. Added to the existing heartbeat table
    // so one row per node still describes the node completely.
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS shard_ids JSONB',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS shard_ready INTEGER',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS shard_total INTEGER',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS started_at TIMESTAMP',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS cpu_pct NUMERIC',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS ram_mb INTEGER',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS ram_total_mb INTEGER',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS pid INTEGER',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS version VARCHAR(32)',
    'ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS shard_updated_at TIMESTAMP',
];

let ready = null;

function ensureTables() {
    if (!ready) {
        ready = (async () => {
            for (const statement of DDL) {
                await seasonPool.query(statement);
            }
        })().catch((err) => {
            ready = null; // retry on the next call
            throw err;
        });
    }
    return ready;
}

function toShardIds(value) {
    if (Array.isArray(value)) return value.map(Number).filter(Number.isInteger);
    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed.map(Number).filter(Number.isInteger) : [];
        } catch (_) {
            return [];
        }
    }
    return [];
}

class PostgresShardStore {
    async listNodes() {
        await ensureTables();
        const { rows } = await seasonPool.query(`
            SELECT role, node_name, shard_ids,
                   EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) * 1000 AS age_ms
            FROM bot_node_status
        `);
        return (rows || []).map(row => ({
            role: String(row.role).toLowerCase(),
            nodeName: row.node_name,
            shardIds: toShardIds(row.shard_ids),
            ageMs: row.age_ms == null ? null : Math.round(Number(row.age_ms)),
        }));
    }

    async listAssignments() {
        await ensureTables();
        const { rows } = await seasonPool.query(`
            SELECT shard_id, owner_role, owner_node, epoch,
                   EXTRACT(EPOCH FROM (NOW() - renewed_at)) * 1000 AS age_ms
            FROM bot_shard_assignment
        `);
        return (rows || []).map(row => ({
            shardId: Number(row.shard_id),
            ownerRole: String(row.owner_role).toLowerCase(),
            ownerNode: row.owner_node,
            epoch: Number(row.epoch) || 0,
            ageMs: row.age_ms == null ? null : Math.round(Number(row.age_ms)),
        }));
    }

    /**
     * Atomically claim one shard. Returns false when a live peer still owns it,
     * which is what makes duplicate ownership impossible.
     */
    async claim(shardId, { role, nodeName, staleAfterMs }) {
        await ensureTables();
        const { rows } = await seasonPool.query(`
            INSERT INTO bot_shard_assignment (shard_id, owner_role, owner_node, epoch, assigned_at, renewed_at)
            VALUES ($1, $2, $3, 1, NOW(), NOW())
            ON CONFLICT (shard_id) DO UPDATE
               SET owner_role = EXCLUDED.owner_role,
                   owner_node = EXCLUDED.owner_node,
                   -- Fencing epoch: only a change of owner bumps it.
                   epoch = CASE WHEN bot_shard_assignment.owner_role = EXCLUDED.owner_role
                                THEN bot_shard_assignment.epoch
                                ELSE bot_shard_assignment.epoch + 1 END,
                   assigned_at = CASE WHEN bot_shard_assignment.owner_role = EXCLUDED.owner_role
                                      THEN bot_shard_assignment.assigned_at
                                      ELSE NOW() END,
                   renewed_at = NOW()
             WHERE bot_shard_assignment.owner_role = EXCLUDED.owner_role
                OR bot_shard_assignment.renewed_at < NOW() - ($4::int * INTERVAL '1 millisecond')
            RETURNING shard_id
        `, [shardId, role, nodeName, Math.max(0, Math.floor(staleAfterMs))]);
        return rows.length > 0;
    }

    async renew(shardIds, { role }) {
        if (!shardIds.length) return;
        await ensureTables();
        await seasonPool.query(`
            UPDATE bot_shard_assignment
               SET renewed_at = NOW()
             WHERE owner_role = $1 AND shard_id = ANY($2::int[])
        `, [role, shardIds]);
    }

    async release(shardIds, { role }) {
        if (!shardIds.length) return;
        await ensureTables();
        await seasonPool.query(`
            DELETE FROM bot_shard_assignment
             WHERE owner_role = $1 AND shard_id = ANY($2::int[])
        `, [role, shardIds]);
    }
}

module.exports = { PostgresShardStore, ensureTables, toShardIds };
