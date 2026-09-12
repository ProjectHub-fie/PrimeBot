// Unit tests for the ticket claim service + claim permission helpers.
// ticketClaimService writes ticket_claims through tclaimDb's raw pool (TCLAIM_DATABASE_URL.
// We stub tclaimPool.query with an in-memory store so the real conditional
// UPDATE SQL is exercised end-to-end (no Postgres needed in CI).
// ticketPermissions reads bot_roles through communityPool; that pool is
// stubbed empty (non-admin/support users degrade to role 'user').

const { test } = require('node:test');
const assert = require('node:assert');

const tclaimPool = require('../server/tclaimDb').tclaimPool;

let ticketTable = new Map();

function seedTicket(channelId, opts) {
    opts = opts || {};
    ticketTable.set(channelId, {
        id: ticketTable.size + 1,
        
        guild_id: '111',
        channel_id: channelId,
        user_id: opts.userId || '222333444555',
        status: opts.status || 'open',
        claimed_by: opts.claimedBy || null,
        claimed_at: opts.claimedAt || null,
        claim_history: opts.claimHistory || null,
    });
}

function makeTicketPoolStub() {
    ticketTable = new Map();
    tclaimPool.query = async (sql, params) => {
        params = params || [];
        const firstParam = params[0];
        if (sql.includes('FROM ticket_claims')) {
            const row = ticketTable.get(String(firstParam));
            return { rows: row ? [row] : [] };
        }
        if (sql.includes('SET claimed_by = NULL')) {
            // Unclaim (params: history, entry, channelId[, claimerId])
            const row = ticketTable.get(String(params[2]));
            if (!row || row.status !== 'open') return { rows: [] };
            const force = sql.includes('claimed_by IS NOT NULL');
            const claimerId = params.length > 3 ? String(params[3]) : null;
            if (!force && String(row.claimed_by || '') !== claimerId) return { rows: [] };
            if (force && (row.claimed_by == null || String(row.claimed_by) === '')) return { rows: [] };
            const history = row.claim_history ? JSON.parse(row.claim_history()) : [];
            history.push(JSON.parse(params[1])[0]);
            row.claimed_by = null;
            row.claimed_at = null;
            row.claim_history = JSON.stringify(history);
            return { rows: [row] };
        }
        if (sql.includes('SET claimed_by') && sql.includes('claimed_by IS NOT NULL') && params.length === 5) {
            // Force-transfer (params: toStaff, now, history, entry, channelId) — no claimer guard
            const row = ticketTable.get(String(params[4]));
            if (!row || row.status !== 'open') return { rows: [] };
            if (row.claimed_by == null || String(row.claimed_by) === '') return { rows: [] };
            const history = row.claim_history ? JSON.parse(row.claim_history()) : [];
            history.push(JSON.parse(params[3])[0]);
            row.claimed_by = String(params[0]);
            row.claimed_at = Number(params[1]);
            row.claim_history = JSON.stringify(history);
            return { rows: [row] };
        }
        if (sql.includes('SET claimed_by') && sql.includes('WHERE channel_id = $5') && params.length === 6) {
            // Transfer with claimer guard (params: toStaff, now, history, entry, channelId, claimerId)
            const row = ticketTable.get(String(params[4]));
            if (!row || row.status !== 'open') return { rows: [] };
            const claimerId = String(params[5]);
            if (String(row.claimed_by || '') !== claimerId) return { rows: [] };
            if (String(row.claimed_by) === String(params[0])) return { rows: [] };
            const history = row.claim_history ? JSON.parse(row.claim_history()) : [];
            history.push(JSON.parse(params[3])[0]);
            row.claimed_by = String(params[0]);
            row.claimed_at = Number(params[1]);
            row.claim_history = JSON.stringify(history);
            return { rows: [row] };
        }
        if (sql.includes('SET claimed_by')) {
            // Claim (params: staffId, now, history, entry, channelId) — guard: open AND unclaimed
            const row = ticketTable.get(String(params[4]));
            if (!row || row.status !== 'open') return { rows: [] };
            if (row.claimed_by != null && String(row.claimed_by) !== '') return { rows: [] };
            const history = row.claim_history ? JSON.parse(row.claim_history()) : [];
            history.push(JSON.parse(params[3])[0]);
            row.claimed_by = String(params[0]);
            row.claimed_at = Number(params[1]);
            row.claim_history = JSON.stringify(history);
            return { rows: [row] };
        }
        throw new Error('Unexpected SQL');
    };
}

const claimService = require('../utils/ticketClaimService');
const ticketPerms = require('../utils/ticketPermissions');

require('../server/communityDb').communityPool.query = async () => ({ rows: [] });

const panel = (opts) => {
    opts = opts || {};
    return { name: 'Support', supportRoleIds: opts.supportRoleIds || ['987654321000'] };
};
const member = (id, opts) => {
    opts = opts || {};
    return {
        id,
        user: { id },
        permissions: { has: () => !!opts.admin },
        roles: {
            cache: opts.supportRoleId ? new Map([[opts.supportRoleId, {}]]) : new Map(),
            has: (rid) => opts.supportRoleId && String(rid) === String(opts.supportRoleId),
        },
    };
};
const instance = (channelId, opts) => {
    opts = opts || {};
    return { channelId, status: opts.status || 'open', claimedBy: opts.claimedBy || null, userId: opts.userId || '222333444555' };
};

test('claimTicket assigns an open unclaimed ticket to a staff member', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444');
    const res = await claimService.claimTicket('111222333444', '555666777888', { performedBy: '555666777888' });
    assert.strictEqual(res.claimedBy, '555666777888');
    assert.ok(res.claimedAt);
    const hist = res.claimHistory;
    assert.strictEqual(hist.length, 1);
    assert.strictEqual(hist[0].action, 'claimed');
    assert.strictEqual(hist[0].new_claimer, '555666777888');
    assert.strictEqual(hist[0].previous_claimer, null);
    assert.strictEqual(hist[0].performed_by, '555666777888');
    assert.ok(hist[0].timestamp);
});

test('claimTicket on an already-claimed ticket fails (race winner wins)', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const res = await claimService.claimTicket('111222333444', '777888999000111222000');
    assert.strictEqual(res, null);
    const state = await claimService.getTicketClaim('111222333444');
    assert.strictEqual(state.claimedBy, '555666777888');
});

test('two simultaneous claims only first succeeds', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444');
    const results = await Promise.all([
        claimService.claimTicket('111222333444', '555666777888'),
        claimService.claimTicket('111222333444', '777888999000111222000'),
    ]);
    const winners = results.filter(Boolean);
    assert.strictEqual(winners.length, 1);
    const state = await claimService.getTicketClaim('111222333444');
    assert.ok(['555666777888', '777888999000111222000'].includes(state.claimedBy));
});

test('claimTicket on a closed ticket fails', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { status: 'closed' });
    assert.strictEqual(await claimService.claimTicket('111222333444', '555666777888'), null);
});

test('claimTicket rejects invalid ids', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444');
    assert.strictEqual(await claimService.claimTicket('111222333444', null), null);
    assert.strictEqual(await claimService.claimTicket('111222333444', 'abc'), null);
    assert.strictEqual(await claimService.claimTicket(null, '555666777888'), null);
});

test('unclaimTicket by the current claimer clears the claim', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const res = await claimService.unclaimTicket('111222333444', '555666777888', { performedBy: '555666777888' });
    assert.strictEqual(res.claimedBy, null);
    assert.strictEqual(res.claimedAt, null);
    assert.strictEqual(res.claimHistory.at(-1).action, 'unclaimed');
});

test('unclaimTicket non-claimer is refused; admins force-unclaim any claim', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const denied = await claimService.unclaimTicket('111222333444', '777888999000');
    assert.strictEqual(denied, null);
    const forced = await claimService.unclaimTicket('111222333444', null, { force: true, performedBy: '999000111222' });
    assert.strictEqual(forced.claimedBy, null);
    assert.strictEqual(forced.claimHistory.at(-1).action, 'overridden');
});

test('unclaimTicket on already-unclaimed force is a safe no-op', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444');
    const res = await claimService.unclaimTicket('111222333444', null, { force: true });
    assert.strictEqual(res, null);
});

test('transferTicketClaim reassigns the claim atomically', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const res = await claimService.transferTicketClaim('111222333444', '555666777888', '777888999000', { performedBy: '555666777888' });
    assert.strictEqual(res.claimedBy, '777888999000');
    assert.strictEqual(res.claimHistory.at(-1).action, 'transferred');
    assert.strictEqual(res.claimHistory.at(-1).previous_claimer, '555666777888');
    assert.strictEqual(res.claimHistory.at(-1).new_claimer, '777888999000');
});

test('transferTicketClaim refuses non-claimers; admin force-transfer works', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const denied = await claimService.transferTicketClaim('111222333444', '777888999000', '999000111222');
    assert.strictEqual(denied, null);
    const forced = await claimService.transferTicketClaim('111222333444', null, '999000111222', { force: true, performedBy: '999000111222' });
    assert.strictEqual(forced.claimedBy, '999000111222');
    assert.strictEqual(forced.claimHistory.at(-1).action, 'transferred');
});

test('transferTicketClaim to the current claimer is a no-op', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const res = await claimService.transferTicketClaim('111222333444', '555666777888', '555666777888');
    assert.strictEqual(res, null);
});

// ── Permissions (in-memory helpers with numeric snowflake ids) ──
test('canManageTicket lets support role holders, admins, and developers through', async () => {
    const p = panel({});
    const supportOk = await ticketPerms.canManageTicket({}, member('222333444555', { supportRoleId: '987654321000' }), p);
    assert.strictEqual(supportOk, true);
    const adminOk = await ticketPerms.canManageTicket({}, member('333444555666', { admin: true }), p);
    assert.strictEqual(adminOk, true);
    const plainOk = await ticketPerms.canManageTicket({}, member('777888999000'), p);
    assert.strictEqual(plainOk, false);
    const noMember = await ticketPerms.canManageTicket({}, null, p);
    assert.strictEqual(noMember, false);
});

test('canClaimTicket rejects non-staff, ticket author, already-claimed, closed', async () => {
    const p = panel({});
    const staff = member('555666777888', { supportRoleId: '987654321000' });
    assert.strictEqual(await ticketPerms.canClaimTicket({}, staff, p, instance('111222333444')), true);
    assert.strictEqual(await ticketPerms.canClaimTicket({}, member('777888999000'), p, instance('111222333444')), false);
    assert.strictEqual(await ticketPerms.canClaimTicket({}, staff, p, instance('111222333444', { userId: '555666777888' })), false);
    assert.strictEqual(await ticketPerms.canClaimTicket({}, staff, p, instance('111222333444', { claimedBy: '999000111222' })), false);
    assert.strictEqual(await ticketPerms.canClaimTicket({}, staff, p, instance('111222333444', { status: 'closed' })), false);
});

test('canUnclaimTicket lets the claimer unclaim; others need admin force', async () => {
    const p = panel({});
    const claimed = instance('111222333444', { claimedBy: '555666777888' });
    assert.strictEqual((await ticketPerms.canUnclaimTicket({}, member('555666777888', { supportRoleId: '987654321000' }), p, claimed)).allowed, true);
    const other = await ticketPerms.canUnclaimTicket({}, member('777888999000', { supportRoleId: '987654321000' }), p, claimed);
    assert.strictEqual(other.allowed, false);
    const admin = await ticketPerms.canUnclaimTicket({}, member('999000111222', { admin: true }), p, claimed);
    assert.strictEqual(admin.allowed, true);
    assert.strictEqual(admin.force, true);
});

test('canTransferTicketClaim lets claimer transfer;others need admin force; self-transfer refused', async () => {
    const p = panel({});
    const claimed = instance('111222333444', { claimedBy: '555666777888' });
    const via = await ticketPerms.canTransferTicketClaim({}, member('555666777888', { supportRoleId: '987654321000' }), p, claimed);
    assert.strictEqual(via.allowed, true);
    assert.strictEqual(via.force, undefined);
    const other = await ticketPerms.canTransferTicketClaim({}, member('777888999000', { supportRoleId: '987654321000' }), p, claimed);
    assert.strictEqual(other.allowed, false);
    const admin = await ticketPerms.canTransferTicketClaim({}, member('999000111222', { admin: true }), p, claimed, '777888999000');
    assert.strictEqual(admin.allowed, true);
    const self = await ticketPerms.canTransferTicketClaim({}, member('999000111222', { admin: true }), p, claimed, '999000111222');
    assert.strictEqual(self.allowed, false);
});

test('claim permission edge cases: stale channel returns null; getTicketClaimHistory mirrors state', async () => {
    makeTicketPoolStub();
    seedTicket('111222333444', { claimedBy: '555666777888', claimedAt: Date.now() });
    const state = await claimService.getTicketClaim('111222333444');
    assert.strictEqual(state.claimedBy, '555666777888');
    assert.strictEqual(await claimService.getTicketClaim('000000000000'), null);
    const hist = await claimService.getTicketClaimHistory('111222333444');
assert.strictEqual(hist.length, 0);
});