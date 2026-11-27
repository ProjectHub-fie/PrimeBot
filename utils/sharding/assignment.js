/**
 * Shard assignment planning — pure, deterministic, no I/O.
 *
 * The plan is a static, balanced split of `0..shardCount-1` across the
 * configured node roles. It is computed from the CONFIGURED node list (not the
 * live list) so three nodes that boot at different times still converge on the
 * same split: a late node claims only the shards the plan gives it, and those
 * are still unowned because no peer ever claims shards outside its own share.
 *
 * `balanced` is the default. `least-shards` and `load` are accepted names so a
 * load-aware strategy can be added later without touching the callers; today
 * they resolve to the balanced plan.
 */

const STRATEGIES = Object.freeze(['balanced', 'least-shards', 'load']);

function normalizeRole(role) {
    return String(role || '').trim().toLowerCase();
}

/**
 * @param {{ shardCount: number, nodes: string[], strategy?: string }} input
 * @returns {{ plan: Record<string, number[]>, order: string[], strategy: string, shardCount: number }}
 */
function planAssignment({ shardCount, nodes = [], strategy = 'balanced' } = {}) {
    const count = Math.max(0, Math.floor(Number(shardCount) || 0));
    const order = [...new Set((Array.isArray(nodes) ? nodes : []).map(normalizeRole).filter(Boolean))];
    const resolved = STRATEGIES.includes(normalizeRole(strategy)) ? normalizeRole(strategy) : 'balanced';

    const plan = {};
    for (const role of order) plan[role] = [];
    if (!count || !order.length) return { plan, order, strategy: resolved, shardCount: count };

    // Round-robin keeps every node within one shard of every other node for any
    // shard count (6 shards / 3 nodes -> 2 each; 7 -> 3/2/2).
    for (let shardId = 0; shardId < count; shardId++) {
        plan[order[shardId % order.length]].push(shardId);
    }
    return { plan, order, strategy: resolved, shardCount: count };
}

/** shardId -> role, for duplicate detection and totals. */
function ownershipMap(plan = {}) {
    const owners = new Map();
    for (const [role, shards] of Object.entries(plan)) {
        for (const shardId of shards) owners.set(shardId, role);
    }
    return owners;
}

/**
 * Validate a plan: every shard in range covered exactly once.
 * @returns {{ ok: boolean, missing: number[], duplicates: number[], outOfRange: number[] }}
 */
function validatePlan(plan = {}, shardCount = 0) {
    const seen = new Map();
    const outOfRange = [];
    for (const [role, shards] of Object.entries(plan)) {
        for (const shardId of shards) {
            if (!Number.isInteger(shardId) || shardId < 0 || shardId >= shardCount) outOfRange.push(shardId);
            seen.set(shardId, (seen.get(shardId) || 0) + 1);
        }
    }
    const duplicates = [...seen.entries()].filter(([, n]) => n > 1).map(([id]) => id).sort((a, b) => a - b);
    const missing = [];
    for (let i = 0; i < shardCount; i++) if (!seen.has(i)) missing.push(i);
    return { ok: !missing.length && !duplicates.length && !outOfRange.length, missing, duplicates, outOfRange };
}

/** The shards a role should own according to the plan. */
function shardsFor(plan = {}, role) {
    return [...(plan[normalizeRole(role)] || [])];
}

/** Per-role counts, handy for logs and the dashboard. */
function summarizePlan(plan = {}) {
    return Object.entries(plan).map(([role, shards]) => ({ role, shards: [...shards], count: shards.length }));
}

module.exports = {
    STRATEGIES,
    planAssignment,
    ownershipMap,
    validatePlan,
    shardsFor,
    summarizePlan,
    normalizeRole,
};
