/* Badges page (beta) — shows the badge catalog and a live ledger of awarded
 * badges. Admins of beta servers can award achievement/special badges to a
 * member (by user id) and revoke any awarded badge row.
 *
 * Non-beta servers see the locked overlay and this script exits early.
 */

const GUILD_ID = window.guildData?.guildId;

// Non-beta servers see a locked, blurred panel; do nothing.
if (document.querySelector('.beta-locked-wrap.locked')) {
  // Nothing to wire — the overlay covers the form.
} else {

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

const TYPE_LABEL = {
  level: 'Level',
  achievement: 'Achievement',
  special: 'Special',
};

function badgeLedgerRowHTML(b) {
  return `
    <tr>
      <td class="bdg-emoji">${esc(b.badgeEmoji || '🏅')}</td>
      <td class="bdg-name">${esc(b.badgeName || '')}</td>
      <td class="bdg-type"><span class="tag ${b.badgeType}">${esc(TYPE_LABEL[b.badgeType] || b.badgeType)}</span></td>
      <td class="bdg-user"><code>${esc(b.userId || '')}</code></td>
      <td class="bdg-time">${esc(formatTime(b.earnedAt))}</td>
      <td class="bdg-actions"><button class="btn btn-secondary btn-sm badge-revoke-btn" data-row-id="${esc(b.id)}">Revoke</button></td>
    </tr>`;
}

function renderBadges(badges) {
  const wrap = document.getElementById('badges-list');
  if (!wrap) return;
  if (!Array.isArray(badges) || badges.length === 0) {
    wrap.innerHTML = `<p class="live-empty">No badges awarded in this server yet.</p>`;
    return;
  }
  wrap.innerHTML = `
    <div class="wlog-wrap">
      <table class="wlog-table badge-table">
        <thead>
          <tr><th>Badge</th><th>Name</th><th>Type</th><th>Member ID</th><th>Awarded</th><th></th></tr>
        </thead>
        <tbody>${badges.map(badgeLedgerRowHTML).join('')}</tbody>
      </table>
    </div>`;
  bindRevokeButtons();
}

async function loadBadges() {
  try {
    const { badges } = await api(`/api/guilds/${GUILD_ID}/badges`);
    renderBadges(badges);
  } catch (err) {
    const wrap = document.getElementById('badges-list');
    if (wrap) wrap.innerHTML = `<p class="live-empty">Failed to load badges: ${esc(err.message || '')}</p>`;
  }
}

function bindRevokeButtons() {
  document.querySelectorAll('.badge-revoke-btn').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const rowId = btn.dataset.rowId;
      if (!confirm('Revoke this badge from the member?')) return;
      btn.disabled = true;
      try {
        await api(`/api/guilds/${GUILD_ID}/badges/${rowId}`, { method: 'DELETE' });
        toast('Badge revoked', 'success');
        await loadBadges();
      } catch (err) {
        toast(err.message || 'Failed to revoke badge', 'error');
        btn.disabled = false;
      }
    });
  });
}

// ── Award modal ────────────────────────────────────────────────────────────
// Clicking "Award to member…" on a badge card opens a small modal asking for a
// member's user id, then POSTs /badges/award.

let pendingBadge = null;

function openAwardModal(btn) {
  pendingBadge = {
    badgeId: btn.dataset.badgeId,
    badgeType: btn.dataset.badgeType,
  };
  const card = btn.closest('.badge-card');
  const name = card?.querySelector('.badge-name')?.textContent || 'badge';
  const emoji = card?.querySelector('.badge-emoji')?.textContent || '🏅';
  const modal = document.getElementById('badge-modal');
  if (!modal) return;
  modal.innerHTML = `
    <div class="modal floating-window">
      <div class="modal-head">
        <span><span class="modal-emoji">${esc(emoji)}</span> Award ${esc(name)}</span>
        <button class="modal-close" id="badge-modal-close" aria-label="Close">✕</button>
      </div>
      <div class="modal-body">
        <p class="modal-desc">Enter the Discord member ID to award this ${esc(pendingBadge.badgeType)} badge to.</p>
        <div class="field">
          <label class="field-label" for="badge-award-userid">Member ID</label>
          <input type="text" id="badge-award-userid" placeholder="123456789012345678" />
          <div class="field-hint">Right-click a member → Copy User ID (enable Developer Mode in Discord settings).</div>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-secondary" id="badge-modal-cancel">Cancel</button>
        <button class="btn btn-primary" id="badge-modal-confirm">Award badge</button>
      </div>
    </div>`;
  modal.classList.remove('hidden');
  const close = () => { modal.classList.add('hidden'); pendingBadge = null; };
  document.getElementById('badge-modal-close')?.addEventListener('click', close);
  document.getElementById('badge-modal-cancel')?.addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  document.getElementById('badge-modal-confirm')?.addEventListener('click', async () => {
    const userId = document.getElementById('badge-award-userid').value.trim();
    if (!/^\d{17,20}$/.test(userId)) {
      toast('Enter a valid Discord user ID (17-20 digits).', 'error');
      return;
    }
    const confirmBtn = document.getElementById('badge-modal-confirm');
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Awarding…';
    try {
      const { badges } = await api(`/api/guilds/${GUILD_ID}/badges/award`, {
        method: 'POST',
        body: JSON.stringify({ userId, badgeType: pendingBadge.badgeType, badgeId: pendingBadge.badgeId }),
      });
      toast('Badge awarded', 'success');
      close();
      renderBadges(badges);
    } catch (err) {
      toast(err.message || 'Failed to award badge', 'error');
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Award badge';
    }
  });
  document.getElementById('badge-award-userid')?.focus();
}

document.querySelectorAll('.badge-award-btn').forEach(btn => {
  btn.addEventListener('click', () => openAwardModal(btn));
});

document.getElementById('badges-refresh')?.addEventListener('click', (e) => {
  e.preventDefault();
  loadBadges();
});

loadBadges();

} // end non-beta guard
