const config = require('../config');
const { communityPool } = require('../server/communityDb');

/**
 * PrimeBot staff role service. Roles (ascending power):
 *   user < moderator < admin < developer < owner (superior — one role only)
 *
 * Stored in the `bot_roles` table on the COMMUNITY_DATABASE_URL pool
 * (server/communityDb.js → communityPool; falls back to DATABASE_URL), so all
 * bot failover nodes + the dashboard read the same rows. The table self-creates
 * here so it works even when drizzle-kit migrations were never applied to the
 * community database (mirrors betaManager's ensure pattern).
 *
 * The `owner` role is reserved for the ids hard-coded in config.developerIds
 * and can NEVER be assigned/removed via $dev add/remove — getRole() resolves
 * owner from config first, and the DB write paths reject 'owner'.
 */

const ROLE_ORDER = ['user', 'moderator', 'admin', 'developer', 'owner'];

const ROLE_INFO = {
    user: {
        label: 'User',
        emoji: '👤',
        color: '#99AAB5',
        description: 'The respective user of PrimeBot',
    },
    moderator: {
        label: 'Moderator',
        emoji: '🛡️',
        color: '#57F287',
        description: 'Moderator has the power to manage support server of PrimeBot',
    },
    admin: {
        label: 'Admin',
        emoji: '⚙️',
        color: '#FEE75C',
        description: 'Admin has the power to manage support server and manage hosting technology',
    },
    developer: {
        label: 'Developer',
        emoji: '🧑‍💻',
        color: '#5865F2',
        description: 'Developer has the power to manage the bot',
    },
    owner: {
        label: 'Owner',
        emoji: '👑',
        color: '#FFD700',
        description: 'The superior of the bot and support server',
    },
};

const ENSURE_ROLE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS bot_roles (
        user_id    VARCHAR(32) PRIMARY KEY,
        role       VARCHAR(20) NOT NULL,
        updated_by VARCHAR(32),
        updated_at TIMESTAMP DEFAULT NOW()
    );
`;

let _tableEnsured = false;
async function ensureRoleTable() {
    if (_tableEnsured) return;
    try {
        await communityPool.query(ENSURE_ROLE_TABLE_SQL);
        _tableEnsured = true;
    } catch (err) {
        console.error('[BOT ROLES] ensureRoleTable failed:', err.message);
    }
}

// Normalize a role name from user input (case/plural/synonyms tolerated).
// Returns the canonical lowercase role name, or null when unrecognized.
function normalizeRoleName(name) {
    if (!name || typeof name !== 'string') return null;
    const n = name.trim().toLowerCase().replace(/s$/, ''); // tolerate trailing plural "s"
    if (n === 'mod') return 'moderator';
    if (n === 'dev') return 'developer';
    return ROLE_ORDER.includes(n) ? n : null;
}

// Numeric power of a role name (user=0 … owner=4). Unknown → -1.
function roleLevel(name) {
    return ROLE_ORDER.indexOf(name);
}

// Is this user a config-seeded owner? config.developerIds is the owner's id list.
function isConfigOwner(userId) {
    return Array.isArray(config.developerIds) && config.developerIds.includes(userId);
}

/**
 * Resolve a user's role. Config owners always win; everyone else falls back to
 * the DB row, and a missing row means 'user'. Never throws — a DB failure
 * degrades to 'user'.
 */
async function getRole(userId) {
    if (isConfigOwner(userId)) return 'owner';
    await ensureRoleTable();
    try {
        const res = await communityPool.query('SELECT role FROM bot_roles WHERE user_id = $1', [userId]);
        const role = res.rows[0]?.role;
        return normalizeRoleName(role) || 'user';
    } catch (err) {
        console.error('[BOT ROLES] getRole DB error:', err.message);
        return 'user';
    }
}

async function getRoleInfo(userId) {
    const role = await getRole(userId);
    return { role, ...ROLE_INFO[role] };
}

/**
 * Assign a role to a user. 'owner' is reserved to config.developerIds and is
 * rejected here. Returns false for an invalid/owner role; true on success.
 */
async function setRole(userId, role, updatedBy = null) {
    const canonical = normalizeRoleName(role);
    if (!canonical || canonical === 'owner') return false;
    await ensureRoleTable();
    try {
        await communityPool.query(`
            INSERT INTO bot_roles (user_id, role, updated_by, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                role = EXCLUDED.role,
                updated_by = EXCLUDED.updated_by,
                updated_at = NOW()
        `, [userId, canonical, updatedBy]);
        return true;
    } catch (err) {
        console.error('[BOT ROLES] setRole DB error:', err.message);
        return false;
    }
}

/**
 * Remove a user's assigned role (falls back to 'user'). Refuses to remove the
 * config-seeded owner. Returns false in that case; true otherwise.
 */
async function removeRole(userId) {
    if (isConfigOwner(userId)) return false;
    await ensureRoleTable();
    try {
        await communityPool.query('DELETE FROM bot_roles WHERE user_id = $1', [userId]);
        return true;
    } catch (err) {
        console.error('[BOT ROLES] removeRole DB error:', err.message);
        return false;
    }
}

/** Every assigned (non-config) role row, ordered by power desc. */
async function listRoleRows() {
    await ensureRoleTable();
    try {
        const res = await communityPool.query('SELECT user_id, role, updated_by, updated_at FROM bot_roles');
        return res.rows
            .filter(r => normalizeRoleName(r.role))
            .sort((a, b) => roleLevel(b.role) - roleLevel(a.role));
    } catch (err) {
        console.error('[BOT ROLES] listRoleRows DB error:', err.message);
        return [];
    }
}

/** Can this user bypass dashboard beta/upcoming gates? developer+ or owner. */
async function canBypassFeatureGates(userId) {
    const role = await getRole(userId);
    return roleLevel(role) >= roleLevel('developer');
}

module.exports = {
    ROLE_ORDER,
    ROLE_INFO,
    normalizeRoleName,
    roleLevel,
    isConfigOwner,
    getRole,
    getRoleInfo,
    setRole,
    removeRole,
    listRoleRows,
    canBypassFeatureGates,
};
