/**
 * Shard coordinator — the control plane that keeps every shard owned by
 * exactly one node.
 *
 * The coordinator is a *protocol*, not a service: the shared state lives in the
 * season database (`bot_shard_assignment`, next to the existing
 * `bot_node_status` heartbeat table), and every decision is a single atomic
 * statement. That keeps three 512 MB nodes cheap — no extra process, no extra
 * database, no message bus — while still giving a real control plane that can
 * be fronted by an HTTP endpoint later (see `SHARD_COORDINATOR_URL`).
 *
 * Safety rules:
 *  - A shard is only ever claimed by a node whose plan includes it, or as a
 *    takeover of a shard whose owner has stopped renewing for `staleAfterMs`.
 *  - A live owner is never preempted: `claim()` is an atomic upsert whose WHERE
 *    clause refuses to touch a row that was renewed recently.
 *  - Ownership carries an `epoch` that increments on every claim, so a stale
 *    writer can be detected (fencing) rather than silently overwriting.
 */

const { planAssignment, shardsFor, ownershipMap, validatePlan } = require('./assignment');
const { resolveNodeIdentity } = require('../nodeIdentity');

const DEFAULT_LOGGER = console;

class ShardCoordinator {
    /**
     * @param {object} options
     * @param {object} options.store        store implementation (see MemoryShardStore)
     * @param {string} [options.role]       this node's role (sn1|sn2|sn3)
     * @param {string} [options.nodeName]   display name reported to peers
     * @param {object} options.config       resolveShardConfig() output
     * @param {object} [options.logger]
     */
    constructor({ store, role, nodeName, config, logger = DEFAULT_LOGGER } = {}) {
        if (!store) throw new Error('ShardCoordinator requires a store');
        if (!config) throw new Error('ShardCoordinator requires a config');
        this.store = store;
        this.config = config;
        this.role = String(role || config.role || resolveNodeIdentity(process.env).role).toLowerCase();
        this.nodeName = nodeName || resolveNodeIdentity(process.env).nodeName;
        this.logger = logger;
        this._owned = [];
        this._lastPlan = null;
    }

    /** The static plan for the configured node list. */
    plan() {
        const plan = planAssignment({
            shardCount: this.config.shardCount,
            nodes: this.config.nodes,
            strategy: this.config.strategy,
        });
        const check = validatePlan(plan.plan, plan.shardCount);
        if (!check.ok) {
            this.logger.warn(`[SHARD] plan is inconsistent (missing=${check.missing.join(',') || '-'} duplicates=${check.duplicates.join(',') || '-'}) — falling back to this node's share only`);
        }
        this._lastPlan = plan;
        return plan;
    }

    /** The shards this node should own when every node is healthy. */
    desiredShards() {
        return shardsFor(this.plan().plan, this.role);
    }

    /**
     * Claim this node's share (and take over shards from nodes that stopped
     * renewing). Safe to call repeatedly — it is the coordinator tick.
     *
     * @returns {Promise<{ shardIds: number[], plan: object, owned: number[], takenOver: number[], released: number[], reason: string }>}
     */
    async claim() {
        const plan = this.plan();
        const desired = shardsFor(plan.plan, this.role);
        if (!desired.length) {
            return { shardIds: [], plan, owned: [], takenOver: [], released: [], reason: 'not_in_plan' };
        }

        const [assignments, nodes] = await Promise.all([
            this.store.listAssignments(),
            this.store.listNodes(),
        ]);

        const owners = new Map(assignments.map(row => [row.shardId, row]));
        const liveRoles = new Set(
            nodes.filter(n => n.ageMs != null && n.ageMs <= this.config.staleAfterMs).map(n => n.role),
        );
        const deadPeers = this.config.nodes.filter(role => role !== this.role && !liveRoles.has(role)).length;

        // Healthy fleet: stick to the plan share (plus one slot of slack).
        // A peer is down: absorb its shards, otherwise those guilds go unserved.
        const limit = deadPeers > 0 ? this.config.shardCount : this.config.maxPerNode;

        const candidates = [];
        // Takeover requires TWO signals: the shard lease has lapsed AND the
        // owning node is no longer heartbeating. A live node whose lease lapsed
        // (e.g. one missed renew) keeps its shards — the coordinator never
        // preempts a running owner, which is what makes duplicate ownership
        // impossible.
        const isAbandoned = (row) => {
            if (row.ownerRole === this.role) return false;
            const leaseLapsed = row.ageMs == null || row.ageMs > this.config.staleAfterMs;
            const ownerSilent = !liveRoles.has(row.ownerRole);
            return leaseLapsed && ownerSilent;
        };

        for (const shardId of desired) {
            const owner = owners.get(shardId);
            if (!owner || owner.ownerRole === this.role) candidates.push({ shardId, takeover: false });
            else if (isAbandoned(owner)) candidates.push({ shardId, takeover: true });
        }
        // A dead peer's shards are worth serving even when they are outside our
        // plan share, as long as we stay under the limit.
        for (const row of assignments) {
            if (!isAbandoned(row)) continue;
            if (!candidates.some(c => c.shardId === row.shardId)) candidates.push({ shardId: row.shardId, takeover: true });
        }
        candidates.sort((a, b) => Number(a.takeover) - Number(b.takeover) || a.shardId - b.shardId);

        const owned = [];
        const takenOver = [];
        for (const candidate of candidates) {
            if (owned.length >= limit) break;
            const won = await this.store.claim(candidate.shardId, {
                role: this.role,
                nodeName: this.nodeName,
                staleAfterMs: this.config.staleAfterMs,
            });
            if (won) {
                owned.push(candidate.shardId);
                if (candidate.takeover) takenOver.push(candidate.shardId);
            }
        }

        // Drop anything we still hold that we did not win in this round.
        const stale = this._owned.filter(id => !owned.includes(id));
        if (stale.length) {
            await this.store.release(stale, { role: this.role }).catch(() => {});
        }
        this._owned = owned.sort((a, b) => a - b);

        const reason = !owned.length ? 'no_shards_available' : (takenOver.length ? 'takeover' : 'plan');
        return {
            shardIds: [...this._owned],
            plan,
            owned: [...this._owned],
            takenOver,
            released: stale,
            reason,
        };
    }

    /** Refresh the lease on the shards we hold (called from the heartbeat). */
    async renew() {
        if (!this._owned.length) return [];
        await this.store.renew(this._owned, { role: this.role });
        return [...this._owned];
    }

    /** Release everything (graceful shutdown) so a peer can pick it up fast. */
    async release() {
        const held = [...this._owned];
        this._owned = [];
        if (held.length) await this.store.release(held, { role: this.role }).catch(() => {});
        return held;
    }

    /** Snapshot for the status surfaces (nodes + shard ownership). */
    async snapshot() {
        const [assignments, nodes] = await Promise.all([
            this.store.listAssignments(),
            this.store.listNodes(),
        ]);
        const plan = this.plan();
        return {
            plan: plan.plan,
            order: plan.order,
            shardCount: plan.shardCount,
            assignments,
            nodes,
            owners: Object.fromEntries([...ownershipMap(plan.plan)].map(([shardId, role]) => [shardId, role])),
            owned: [...this._owned],
        };
    }
}

/**
 * In-memory store used by tests and by a single-process fallback. It models the
 * exact semantics of the Postgres store: an unexpired claim cannot be taken.
 */
class MemoryShardStore {
    constructor({ now = () => Date.now() } = {}) {
        this.now = now;
        this.assignments = new Map(); // shardId -> { shardId, ownerRole, ownerNode, epoch, renewedAt }
        this.nodes = new Map(); // role -> { role, nodeName, lastHeartbeat }
    }

    setNode(role, { nodeName = role, ageMs = 0 } = {}) {
        this.nodes.set(role, { role, nodeName, lastHeartbeat: this.now() - ageMs });
        return this;
    }

    removeNode(role) {
        this.nodes.delete(role);
        return this;
    }

    async listNodes() {
        return [...this.nodes.values()].map(n => ({
            role: n.role,
            nodeName: n.nodeName,
            ageMs: Math.max(0, this.now() - n.lastHeartbeat),
        }));
    }

    async listAssignments() {
        return [...this.assignments.values()].map(a => ({
            shardId: a.shardId,
            ownerRole: a.ownerRole,
            ownerNode: a.ownerNode,
            epoch: a.epoch,
            ageMs: Math.max(0, this.now() - a.renewedAt),
        }));
    }

    async claim(shardId, { role, nodeName, staleAfterMs }) {
        const existing = this.assignments.get(shardId);
        if (existing && existing.ownerRole !== role && this.now() - existing.renewedAt <= staleAfterMs) {
            return false;
        }
        const sameOwner = existing && existing.ownerRole === role;
        this.assignments.set(shardId, {
            shardId,
            ownerRole: role,
            ownerNode: nodeName,
            // Fencing epoch: bumped only when a DIFFERENT node takes the shard,
            // so a re-claim by the owner is not churn.
            epoch: sameOwner ? existing.epoch : (existing?.epoch || 0) + 1,
            renewedAt: this.now(),
        });
        return true;
    }

    async renew(shardIds, { role }) {
        for (const shardId of shardIds) {
            const row = this.assignments.get(shardId);
            if (row && row.ownerRole === role) row.renewedAt = this.now();
        }
    }

    async release(shardIds, { role }) {
        for (const shardId of shardIds) {
            const row = this.assignments.get(shardId);
            if (row && row.ownerRole === role) this.assignments.delete(shardId);
        }
    }
}

module.exports = { ShardCoordinator, MemoryShardStore };
