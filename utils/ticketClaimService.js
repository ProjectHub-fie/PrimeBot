const { tclaimPool } = require('../server/tclaimDb');

/**
 * Ticket claim service — the single source of truth for claim mutations.
 *
 * Claim state lives in the dedicated `ticket_claims` table (TCLAIM_DATABASE_URL
 * pool; falls back to the main DATABASE_URL when unset):
 *   claimed_by      — Discord user id of the current claimer (null = unclaimed).
 *   claimed_at      — epoch ms when the ticket was claimed (null = unclaimed).
 *   claim_history    — JSONB array of { action, previous_claimer, new_claimer,
 *                        performed_by, timestamp } entries.
 *
 * All mutations are ATOMIC at the database level: they use a conditional
 * UPDATE ... WHERE claimed_by IS NULL (or WHERE claimed_by = $fromStaff)
 * and verify the row actually changed, so two moderators clicking Claim at
 * exactly the same moment can never both succeed. We never read-then-write
 * a claim state without the race-guarded UPDATE roundtrip appearing at the
 * write site.
 *
 * The `status` column mirrors the owning ticket instance's lifecycle so the
 * race guards stay within this single table/DB (a claim only succeeds while
 * status = 'open').
 *
 * The service is DB-level only — it never touches Discord so it stays
 * restart-safe and testable. Interactions are handled by TicketPanelManager
 * (utils/ticketManager.js) which calls these methods after permission checks
 * (utils/ticketPermissions.js)。
 */

const INITIAL_HISTORY = '[]';
const HISTORY_CLAIM = 'claimed';
const HISTORY_UNCLAIM = 'unclaimed';
const HISTORY_TRANSFER = 'transferred';
const HISTORY_OVERRIDE = 'overridden';

/** Validate a Discord snowflake id (accepts strings/numbers, rejects junk). */
function _validId(id) {
    if (id == null) return false;
    const s = String(id).trim();
    return /^\d{6,25}$/.test(s);
}

/** Normalize claim-history JSON from the DB into an array. */
function normalizeHistory(raw) {
    if (!raw) return [];
    try {
        const arr = Array.isArray(raw) ? raw : JSON.parse(String(raw));
        return Array.isArray(arr) ? arr.filter(e => e && typeof e === 'object') : [];
    } catch {
        return [];
    }
}

/** Serialize a history entry for the JSONB column. */
function _historyEntry(action, previousClaimer, newClaimer, performedBy, now) {
    return JSON.stringify([{
        action,
        previous_claimer: previousClaimer || null,
        new_claimer: newClaimer || null,
        performed_by: performedBy || null,
        timestamp: new Date(now).toISOString(),
    }]);
}

/** Fetch the current claim state + instance for a ticket channel. */
async function getTicketClaim(channelId) {
    if (!channelId) return null;
    const res = await tclaimPool.query(
        `SELECT id, guild_id, channel_id, user_id, status, claimed_by, claimed_at, claim_history
         FROM ticket_claims WHERE channel_id = $1`, [String(channelId)]
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
        id: r.id,
        guildId: r.guild_id,
        channelId: r.channel_id,
        userId: r.user_id,
        status: r.status || 'open',
        claimedBy: r.claimed_by || null,
        claimedAt: r.claimed_at ? Number(r.claimed_at) : null,
        claimHistory: normalizeHistory(r.claim_history),
    };
}

/** Fetch the ticket's claim history (newest first per spec ordering).). */
async function getTicketClaimHistory(channelId) {
    const claim = await getTicketClaim(channelId);
    return claim ? claim.claimHistory : [];
}

/**
 * Atomically claim a ticket. Only succeeds while the ticket is open AND
 * unclaimed (claimed_by IS NULL/empty). Returns the updated claim state,
 * or null when another staff member won the race / the ticket is no longer
 * claimable.
 *
 * @param {string} channelId - ticket channel id (ticket id)
 * @param {string} staffId  - new claimer user id
 * @param {string} performedBy - who performed the action (defaults staffId)
 * @param {number} [now] - epoch ms override (tests)
 */
async function claimTicket(channelId, staffId, { performedBy = null, now = Date.now() } = {}) {
    if (!_validId(channelId) || !_validId(staffId)) return null;
    const actor = _validId(performedBy) ? performedBy : staffId;
    const res = await tclaimPool.query(
        `UPDATE ticket_claims
         SET claimed_by = $1, claimed_at = $2,
             claim_history = COALESCE(claim_history, $3::jsonb) || $4::jsonb
         WHERE channel_id = $5
           AND status = 'open'
           AND (claimed_by IS NULL OR claimed_by = '')
         RETURNING claimed_by, claimed_at, claim_history`, [
        String(staffId), now, INITIAL_HISTORY, _historyEntry(HISTORY_CLAIM, null, String(staffId), actor, now), String(channelId),
    ]);
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
        claimedBy: r.claimed_by,
        claimedAt: Number(r.claimed_at),
        claimHistory: normalizeHistory(r.claim_history),
    };
}

/**
 * Atomically unclaim a ticket. Only succeeds while the ticket is open and the
 * given `claimantId` is the current claimer (or null/'' when forcing). Pass
 * `force:true` to clear any claimer (admin/ticket-manager override. Returns
 * the updated claim state, or null when nothing changed.
 */
async function unclaimTicket(channelId, claimantId = null, { performedBy = null, force = false, now = Date.now() } = {}) {
    if (!_validId(channelId)) return null;
    if (!force && !_validId(claimantId)) return null;
    const actor = _validId(performedBy) ? performedBy : (claimantId || null);
    const historyAction = force ? HISTORY_OVERRIDE : HISTORY_UNCLAIM;
    // Load the previous claimer for the history row (safe: no race here——
    // the conditional UPDATE below bears the concurrency guard).
    const before = await getTicketClaim(channelId);
    if (!before) return null;
    if (before.status !== 'open') return null;
    if (!force && String(before.claimedBy || '') !== String(claimantId)) return null;
    const prevClaimer = before.claimedBy;
    const res = await tclaimPool.query(
        `UPDATE ticket_claims
         SET claimed_by = NULL, claimed_at = NULL,
             claim_history = COALESCE(claim_history, $1::jsonb) || $2::jsonb
         WHERE channel_id = $3
           AND status = 'open'
           ${force ? 'AND claimed_by IS NOT NULL AND claimed_by <> \'\'' : 'AND claimed_by = $4'}
         RETURNING claimed_by, claimed_at, claim_history`, force
            ? [INITIAL_HISTORY, _historyEntry(historyAction, prevClaimer, null, actor, now), String(channelId)]
            : [INITIAL_HISTORY, _historyEntry(historyAction, prevClaimer, null, actor, now), String(channelId), String(claimantId)],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
        claimedBy: null,
        claimedAt: null,
        claimHistory: normalizeHistory(r.claim_history),
    };
}

/**
 * Atomically transfer / reassign the claim from the current claimer to a new
 * staff member. `claimantId` may be the current claimer's id (normal
 * transfer) or null/'' (force transfer — admin/ticket-manager override. The
 * conditional guard ensures the old claimer is who we expect (or any current
 * claimer when forcing), so racing transfers never double-apply. Returns
 * the updated claim state, or null when nothing changed / the target equals
 * the current claimer.
 */
async function transferTicketClaim(channelId, claimantId, toStaffId, { performedBy = null, force = false, now = Date.now() } = {}) {
    if (!_validId(channelId) || !_validId(toStaffId)) return null;
    if (!force && !_validId(claimantId)) return null;
    const actor = _validId(performedBy) ? performedBy : (claimantId || toStaffId);
    const before = await getTicketClaim(channelId);
    if (!before) return null;
    if (before.status !== 'open') return null;
    if (!force && String(before.claimedBy || '') !== String(claimantId)) return null;
    if (before.claimedBy && String(before.claimedBy) === String(toStaffId)) return null;
    const prevClaimer = before.claimedBy;
    const cond = force
        ? "AND claimed_by IS NOT NULL AND claimed_by <> ''"
        : 'AND claimed_by = $6';
    const params = force
        ? [String(toStaffId), now, INITIAL_HISTORY, _historyEntry(HISTORY_TRANSFER, prevClaimer, String(toStaffId), actor, now), String(channelId)]
        : [String(toStaffId), now, INITIAL_HISTORY, _historyEntry(HISTORY_TRANSFER, prevClaimer, String(toStaffId), actor, now), String(channelId), String(claimantId)];
    const res = await tclaimPool.query(
        `UPDATE ticket_claims
         SET claimed_by = $1, claimed_at = $2,
             claim_history = COALESCE(claim_history, $3::jsonb) || $4::jsonb
         WHERE channel_id = $5
           AND status = 'open'
           ${cond}
         RETURNING claimed_by, claimed_at, claim_history`, params
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
        claimedBy: r.claimed_by,
        claimedAt: Number(r.claimed_at),
        claimHistory: normalizeHistory(r.claim_history),
    };
}

module.exports = {
    claimTicket,
    unclaimTicket,
    transferTicketClaim,
    getTicketClaim,
    getTicketClaimHistory,
    normalizeHistory,
};