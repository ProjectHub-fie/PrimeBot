/* Event Management — manage page (/guild/:id/events/:id).
 *
 * Tabbed management (Overview / Participants / Announcements / Reminders /
 * Settings / Activity Log), client-side countdown, participant actions,
 * announcement publish/update, lifecycle actions and a confirmation dialog for
 * destructive operations. Settings persist through the shared floating save bar.
 */

(function () {
  'use strict';

  const GUILD_ID = window.guildData && window.guildData.guildId;
  const EVENT_ID = $('#ev-manage') ? $('#ev-manage').dataset.eventId : null;
  if (!GUILD_ID || !EVENT_ID) return;
  const BASE = `/api/guilds/${GUILD_ID}/events/${EVENT_ID}`;

  function $(s, r = document) { return r.querySelector(s); }
  function $$(s, r = document) { return Array.from(r.querySelectorAll(s)); }

  const root = $('#ev-manage');
  let EVENT = (window.guildData && window.guildData.event) || {};
  let PARTICIPANTS = (window.guildData && window.guildData.eventParticipants) || [];

  // ── Tabs ──────────────────────────────────────────────────────────────────
  function showTab(key) {
    $$('.ev-mtab').forEach(b => b.classList.toggle('active', b.dataset.tab === key));
    $$('.ev-mpanel').forEach(p => p.classList.toggle('hidden', p.dataset.tab !== key));
    if (key === 'activity') loadActivity();
  }
  $$('.ev-mtab').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  const initialTab = new URLSearchParams(location.search).get('tab');
  if (initialTab && $$('.ev-mtab').some(b => b.dataset.tab === initialTab)) showTab(initialTab);

  // ── Live countdown (client-side only) ─────────────────────────────────────
  function humanize(ms) {
    if (ms <= 0) return 'Starting…';
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    const pad = n => String(n).padStart(2, '0');
    return d > 0 ? `${d}d ${pad(h)}h ${pad(m)}m ${pad(sec)}s` : `${pad(h)}h ${pad(m)}m ${pad(sec)}s`;
  }
  function tick() {
    const now = Date.now();
    $$('[data-ev-countdown]').forEach(el => {
      const start = new Date(el.dataset.evCountdown).getTime();
      const v = el.querySelector('.ev-countdown-value');
      if (!v || !Number.isFinite(start)) return;
      const diff = start - now;
      if (diff <= 0) { el.classList.add('ev-countdown-live'); v.textContent = 'Live now'; return; }
      v.textContent = humanize(diff);
    });
  }
  tick();
  setInterval(tick, 1000);

  // ── Confirmation dialog ───────────────────────────────────────────────────
  function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
    return new Promise(resolve => {
      const overlay = document.createElement('div');
      overlay.className = 'ev-modal-overlay';
      overlay.innerHTML = `
        <div class="ev-modal" role="dialog" aria-modal="true">
          <h3>${esc(title)}</h3>
          <p>${esc(message)}</p>
          <div class="ev-modal-actions">
            <button class="btn btn-secondary" data-act="cancel">Cancel</button>
            <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-act="ok">${esc(confirmLabel)}</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      const close = (val) => { overlay.remove(); resolve(val); };
      overlay.querySelector('[data-act="cancel"]').addEventListener('click', () => close(false));
      overlay.querySelector('[data-act="ok"]').addEventListener('click', () => close(true));
      overlay.addEventListener('click', (e) => { if (e.target === overlay) close(false); });
    });
  }

  async function reload() { window.location.reload(); }

  // ── Lifecycle actions ─────────────────────────────────────────────────────
  async function patchEvent(patch, msg) {
    const data = await api(BASE, { method: 'PATCH', body: JSON.stringify(patch) });
    if (data && data.event) EVENT = data.event;
    if (msg) toast(msg);
    return data;
  }

  const publishBtn = $('#ev-publish');
  if (publishBtn) publishBtn.addEventListener('click', async () => {
    try {
      await api(`${BASE}/publish`, { method: 'POST', body: JSON.stringify({}) });
      toast('Event published'); reload();
    } catch (e) { toast(e.message, 'error'); }
  });

  const openRegBtn = $('#ev-open-reg');
  if (openRegBtn) openRegBtn.addEventListener('click', async () => {
    try { await patchEvent({ status: 'registration_open' }, 'Registration opened'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  const closeRegBtn = $('#ev-close-reg');
  if (closeRegBtn) closeRegBtn.addEventListener('click', async () => {
    try { await patchEvent({ status: 'registration_closed' }, 'Registration closed'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  const completeBtn = $('#ev-complete');
  if (completeBtn) completeBtn.addEventListener('click', async () => {
    try { await api(`${BASE}/complete`, { method: 'POST', body: JSON.stringify({}) }); toast('Event completed'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  const cancelBtn = $('#ev-cancel');
  if (cancelBtn) cancelBtn.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Cancel Event?',
      message: 'This will cancel registration and notify participants. Future reminders stop.',
      confirmLabel: 'Cancel Event',
      danger: true,
    });
    if (!ok) return;
    try {
      await api(`${BASE}/cancel`, { method: 'POST', body: JSON.stringify({ notify: true }) });
      toast('Event cancelled'); reload();
    } catch (e) { toast(e.message, 'error'); }
  });

  const deleteBtn = $('#ev-delete');
  if (deleteBtn) deleteBtn.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Delete event?',
      message: 'This permanently deletes the event, its participants and its activity log. This cannot be undone.',
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await api(BASE, { method: 'DELETE' });
      toast('Event deleted');
      window.location.assign(`/guild/${GUILD_ID}/events`);
    } catch (e) { toast(e.message, 'error'); }
  });

  const dupBtn = $('#ev-duplicate');
  if (dupBtn) dupBtn.addEventListener('click', async () => {
    try {
      const res = await api(`${BASE}/duplicate`, { method: 'POST', body: JSON.stringify({}) });
      toast('Event duplicated');
      const id = res.event && res.event.id;
      window.location.assign(`/guild/${GUILD_ID}/events/${id}`);
    } catch (e) { toast(e.message, 'error'); }
  });

  // ── Announcements ─────────────────────────────────────────────────────────
  const pubAnn = $('#ev-publish-announce');
  if (pubAnn) pubAnn.addEventListener('click', () => publishAnnouncement());
  const publishAnnouncement = async () => {
    try {
      await patchEvent({ announcementChannelId: $('#ev-manage-channel').value || null });
      await api(`${BASE}/announce`, { method: 'POST', body: JSON.stringify({}) });
      toast('Announcement posted'); reload();
    } catch (e) { toast(e.message, 'error'); }
  };
  const updAnn = $('#ev-update-announcement');
  if (updAnn) updAnn.addEventListener('click', async () => {
    try {
      await patchEvent({ announcementChannelId: $('#ev-manage-channel').value || null });
      await api(`${BASE}/announce`, { method: 'PATCH', body: JSON.stringify({}) });
      toast('Announcement updated in place');
    } catch (e) { toast(e.message, 'error'); }
  });

  // ── Participants ──────────────────────────────────────────────────────────
  function collectParticipantPayload() {
    return {
      name: $('#ev-s-name') ? $('#ev-s-name').value : undefined,
      type: $('#ev-s-type') ? $('#ev-s-type').value : undefined,
      description: $('#ev-s-desc') ? $('#ev-s-desc').value : undefined,
      registrationMode: $('#ev-s-mode') ? $('#ev-s-mode').value : undefined,
      maxParticipants: $('#ev-s-max') && $('#ev-s-max').value ? Number($('#ev-s-max').value) : null,
      waitlistEnabled: $('#ev-s-waitlist') ? $('#ev-s-waitlist').checked : undefined,
      trackAttendance: $('#ev-s-attendance') ? $('#ev-s-attendance').checked : undefined,
      participantRoleId: $('#ev-s-participant-role') ? ($('#ev-s-participant-role').value || null) : undefined,
      winnerRoleId: $('#ev-s-winner-role') ? ($('#ev-s-winner-role').value || null) : undefined,
      eventManagerRoleId: $('#ev-s-manager-role') ? ($('#ev-s-manager-role').value || null) : undefined,
      eventPermissions: $$('.ev-perm').filter(c => c.checked).map(c => c.value),
      reminders: $$('.ev-manage-reminder').filter(c => c.checked).map(c => c.value),
    };
  }

  async function saveSettings() {
    const payload = collectParticipantPayload();
    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);
    // Drop null only where the user cleared an optional field intentionally.
    const data = await api(BASE, { method: 'PATCH', body: JSON.stringify(payload) });
    if (data && data.event) EVENT = data.event;
  }

  window.saveBar.register(() => saveSettings());
  window.saveBar.track(root);

  // Add participant.
  const addBtn = $('#ev-add-pt');
  if (addBtn) addBtn.addEventListener('click', async () => {
    const userId = $('#ev-add-pt-id').value.trim();
    if (!/^\d{15,22}$/.test(userId)) { toast('Enter a valid user ID', 'error'); return; }
    try {
      await api(`${BASE}/participants`, { method: 'POST', body: JSON.stringify({ userId }) });
      toast('Participant added'); reload();
    } catch (e) { toast(e.message, 'error'); }
  });

  // Row actions (delegated).
  const tbody = $('#ev-pt-table') ? $('#ev-pt-table').querySelector('tbody') : null;
  if (tbody) tbody.addEventListener('click', async (e) => {
    const tr = e.target.closest('tr[data-user-id]');
    if (!tr) return;
    const userId = tr.dataset.userId;
    if (e.target.closest('.ev-pt-remove')) {
      const ok = await confirmDialog({ title: 'Remove participant?', message: 'They will be removed and the next waiting member promoted.', confirmLabel: 'Remove', danger: true });
      if (!ok) return;
      try { await api(`${BASE}/participants/${userId}`, { method: 'DELETE' }); toast('Participant removed'); reload(); }
      catch (err) { toast(err.message, 'error'); }
    } else if (e.target.closest('.ev-pt-checkin')) {
      const cur = tr.dataset.attendance || 'unknown';
      const next = cur === 'present' ? 'absent' : 'present';
      try { await api(`${BASE}/participants/${userId}`, { method: 'PATCH', body: JSON.stringify({ attendanceStatus: next }) }); toast('Attendance updated'); reload(); }
      catch (err) { toast(err.message, 'error'); }
    } else if (e.target.closest('.ev-pt-promote')) {
      try { await api(`${BASE}/participants/${userId}`, { method: 'PATCH', body: JSON.stringify({ status: 'registered' }) }); toast('Promoted from waiting list'); reload(); }
      catch (err) { toast(err.message, 'error'); }
    }
  });

  // Participant search / filter (client-side; the list arrived with the page).
  function filterParticipants() {
    if (!tbody) return;
    const q = ($('#ev-pt-search') || {}).value ? $('#ev-pt-search').value.trim().toLowerCase() : '';
    const f = ($('#ev-pt-filter') || {}).value || '';
    $$('tr[data-user-id]', tbody).forEach(tr => {
      const txt = tr.textContent.toLowerCase();
      const att = tr.dataset.attendance || 'unknown';
      const status = tr.dataset.status;
      let match = !q || txt.includes(q);
      if (match && f) {
        if (f === 'present' || f === 'absent') match = att === f;
        else match = status === f;
      }
      tr.classList.toggle('hidden', !match);
    });
  }
  ['ev-pt-search', 'ev-pt-filter'].forEach(id => { const el = document.getElementById(id); if (el) el.addEventListener('input', filterParticipants); });

  // ── Activity log ──────────────────────────────────────────────────────────
  async function loadActivity() {
    const list = $('#ev-activity-list');
    if (!list) return;
    try {
      const data = await api(`${BASE}/activity`);
      const rows = (data.activity || []).map(a => `
        <li class="ev-activity-row"><span class="ev-activity-dot"></span><span class="ev-activity-body">
          <span class="ev-activity-action">${esc(a.action.replace(/_/g, ' '))}</span>
          ${a.detail ? `<span class="ev-activity-detail">${esc(a.detail)}</span>` : ''}
          <span class="ev-activity-meta">${a.username ? esc(a.username) + ' · ' : ''}${esc(new Date(a.createdAt).toLocaleString())}</span>
        </span></li>`).join('');
      list.innerHTML = rows || '<li class="ev-muted">No activity yet.</li>';
    } catch (e) { /* degrade silently */ }
  }
})();
