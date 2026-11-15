/**
 * Single source of truth for "which shard node am I?".
 *
 * Every producer of a monitoring record (the failover heartbeat, the per-node
 * status pulse, the monitoring worker's lease id) and every reader (the status
 * API + dashboard) must agree on one stable identity per node. When they did
 * not, all three nodes wrote `nodeName: 'local'` into the same primary-keyed
 * `monitor_node_pulse` row and overwrote each other — which is why two healthy
 * standby nodes were reported as offline.
 *
 * The identity is deliberately NOT derived from `os.hostname()`: hosting panels
 * assign random container hostnames that change on every restart, so a stable
 * role-based name is used unless the operator sets NODE_ID / NODE_NAME.
 */

function normalizeNodeRole(rawRole) {
    const value = String(rawRole || 'sn1').trim().toLowerCase();
    if (value === 'sn2' || value === 'secondary' || value === 'secoundary') return 'sn2';
    if (value === 'sn3' || value === 'tertiary') return 'sn3';
    if (value === 'sn1' || value === 'primary') return 'sn1';
    return 'sn1';
}

const DEFAULT_NAME_BY_ROLE = { sn1: 'NR0008', sn2: 'NU3049', sn3: 'NUKN09' };

/**
 * Resolve this process's stable node identity.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ nodeId: string, nodeName: string, role: 'sn1'|'sn2'|'sn3' }}
 */
function resolveNodeIdentity(env = process.env) {
    const role = normalizeNodeRole(env.NODE_ROLE);
    const fallback = DEFAULT_NAME_BY_ROLE[role] || DEFAULT_NAME_BY_ROLE.sn1;
    const explicit = String(env.NODE_ID || env.NODE_NAME || '').trim();
    const nodeId = explicit || fallback;
    return { nodeId, nodeName: nodeId, role };
}

module.exports = { normalizeNodeRole, resolveNodeIdentity, DEFAULT_NAME_BY_ROLE };
