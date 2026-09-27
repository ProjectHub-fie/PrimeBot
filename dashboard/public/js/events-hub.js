/* Event Management hub (/guild/:id/events).
 *
 * The page is server-rendered (hero, stats, cards). This script only adds:
 *   • a purely client-side live countdown on every card/hero (zero network
 *     requests — a single 1s timer that re-renders local text);
 *   • client-side search / status filter / sort over the rendered cards;
 *   • a Refresh button that re-fetches the list from the API and re-renders.
 *
 * No Neon query ever happens on a countdown tick. The initial list arrives with
 * the HTML, so the page rendered no API call at all.
 */

(function () {
  'use strict';

  const GUILD_ID = window.guildData && window.guildData.guildId;
  if (!GUILD_ID) return;

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  // ── Live countdowns (client-side only) ────────────────────────────────────
  function humanize(ms) {
    if (ms <= 0) return 'Starting…';
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return d > 0 ? `${d}d ${pad(h)}h ${pad(m)}m ${pad(sec)}s` : `${pad(h)}h ${pad(m)}m ${pad(sec)}s`;
  }

  function tickCountdowns() {
    const now = Date.now();
    $$('[data-ev-countdown]').forEach(el => {
      const start = new Date(el.dataset.evCountdown).getTime();
      if (!Number.isFinite(start)) return;
      const valueEl = el.querySelector('.ev-countdown-value');
      if (!valueEl) return;
      const diff = start - now;
      if (diff <= 0) {
        // The event is due; mark it live locally and stop updating this node.
        el.classList.add('ev-countdown-live');
        valueEl.textContent = 'Live now';
        return;
      }
      valueEl.textContent = humanize(diff);
    });
  }
  tickCountdowns();
  const countdownTimer = setInterval(tickCountdowns, 1000);

  // ── Client-side search / filter / sort ────────────────────────────────────
  function cardName(card) {
    const t = card.querySelector('.ev-card-title');
    return t ? t.textContent.trim().toLowerCase() : '';
  }
  function cardStatus(card) {
    const b = card.querySelector('.ev-badge');
    if (!b) return '';
    // The badge class encodes the status: ev-badge-<status>.
    const m = Array.from(b.classList).find(c => c.startsWith('ev-badge-'));
    return m ? m.replace('ev-badge-', '') : '';
  }
  function cardStart(card) {
    const c = card.querySelector('[data-ev-countdown]');
    if (!c) return Infinity;
    const t = new Date(c.dataset.evCountdown).getTime();
    return Number.isFinite(t) ? t : Infinity;
  }
  function cardParticipants(card) {
    const el = card.querySelector('[data-ev-countdown]');
    void el;
    const txt = card.querySelector('.ev-card-participants');
    const m = txt && txt.textContent.match(/(\d+)\s+participant/);
    return m ? parseInt(m[1], 10) : 0;
  }

  function applyFilters() {
    const list = $('#ev-list');
    if (!list) return;
    const q = ($('#ev-search') || {}).value ? $('#ev-search').value.trim().toLowerCase() : '';
    const status = ($('#ev-filter-status') || {}).value || '';
    const sort = ($('#ev-sort') || {}).value || 'start';

    const cards = $$('.ev-card', list);
    let visible = 0;
    cards.forEach(card => {
      const matchQ = !q || cardName(card).includes(q);
      const matchS = !status || cardStatus(card) === status;
      const show = matchQ && matchS;
      card.classList.toggle('hidden', !show);
      if (show) visible++;
    });

    // Sort the visible cards (DOM reorder only).
    const sorted = cards.slice().sort((a, b) => {
      if (sort === 'participants') return cardParticipants(b) - cardParticipants(a);
      if (sort === 'created') return (Number(b.dataset.evId) || 0) - (Number(a.dataset.evId) || 0);
      return cardStart(a) - cardStart(b);
    });
    for (const c of sorted) list.appendChild(c);

    let empty = $('#ev-filter-empty');
    if (visible === 0 && cards.length > 0) {
      if (!empty) {
        empty = document.createElement('p');
        empty.id = 'ev-filter-empty';
        empty.className = 'ev-muted';
        empty.textContent = 'No events match your filters.';
        list.appendChild(empty);
      }
      empty.classList.remove('hidden');
    } else if (empty) {
      empty.classList.add('hidden');
    }
  }

  ['ev-search', 'ev-filter-status', 'ev-sort'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', applyFilters);
    if (el) el.addEventListener('change', applyFilters);
  });

  // ── Refresh from the API ──────────────────────────────────────────────────
  function renderCard(ev) {
    const type = (window.__EVENT_TYPES || []).find(t => t.key === ev.type) || { label: 'Custom', iconName: 'star' };
    const statuses = window.__EVENT_STATUSES || [];
    const st = statuses.find(s => s.key === ev.status) || { label: ev.status, icon: 'info' };
    const when = ev.startAt ? new Date(ev.startAt).toLocaleString('en-US', { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—';
    const count = ev.participantCount == null ? '—' : ev.participantCount;
    const pctv = ev.maxParticipants ? Math.min(100, Math.round((ev.participantCount || 0) / ev.maxParticipants * 100)) : 0;
    const cover = ev.imageUrl
      ? `style="background-image:url('${esc(ev.imageUrl)}')"`
      : '';
    const coverInner = ev.imageUrl ? '' : `<div class="ev-card-cover-fallback">${svgIcon(type.iconName)}</div>`;
    const cd = ev.status === 'completed' ? '<div class="ev-countdown ev-countdown-done">✔ Completed</div>'
      : ev.status === 'cancelled' ? '<div class="ev-countdown ev-countdown-cancelled">Cancelled</div>'
      : ev.startAt ? `<div class="ev-countdown" data-ev-countdown="${esc(ev.startAt)}"><span class="ev-countdown-label">Starts in</span><span class="ev-countdown-value">—</span></div>`
      : '<div class="ev-countdown ev-countdown-none">Not scheduled</div>';
    return `
      <div class="ev-card" data-ev-id="${ev.id}">
        <div class="ev-card-cover" ${cover}>
          ${coverInner}
          <div class="ev-card-cover-badges"><span class="ev-badge ev-badge-${esc(st.key)}">${svgIcon(st.icon)} ${esc(st.label)}</span></div>
        </div>
        <div class="ev-card-body">
          <div class="ev-card-title">${svgIcon(type.iconName)} ${esc(ev.name)}</div>
          <div class="ev-card-meta"><span class="ev-type-chip">${svgIcon(type.iconName)} ${esc(type.label)}</span></div>
          <div class="ev-card-when">${svgIcon('clock')} ${esc(when)}</div>
          ${cd}
          <div class="ev-card-participants">
            ${svgIcon('users')} ${count} participant${count === 1 ? '' : 's'}
            ${ev.maxParticipants ? `<div class="ev-progress"><div class="ev-progress-bar" style="width:${pctv}%"></div></div><div class="ev-progress-text">${count} / ${ev.maxParticipants}</div>` : ''}
          </div>
        </div>
        <div class="ev-card-actions">
          <a class="btn btn-primary" href="/guild/${esc(GUILD_ID)}/events/${ev.id}">${svgIcon('settings')} Manage</a>
          <a class="btn btn-secondary" href="/guild/${esc(GUILD_ID)}/events/${ev.id}?tab=overview">${svgIcon('eye')} View</a>
        </div>
      </div>`;
  }

  async function refresh() {
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/events?limit=100&sort=start`);
      const list = $('#ev-list');
      if (!list) return;
      const events = data.events || [];
      list.innerHTML = events.length
        ? events.map(renderCard).join('')
        : '<div class="ev-empty"><div class="ev-empty-emoji">🎉</div><h3>No events yet</h3><p>Create your first community event.</p><a class="btn btn-primary" href="/guild/' + esc(GUILD_ID) + '/events/new">Create Event</a></div>';
      tickCountdowns();
      applyFilters();
      toast('Events refreshed');
    } catch (e) {
      toast(e.message || 'Failed to refresh events', 'error');
    }
  }
  const refreshBtn = $('#ev-refresh-upcoming');
  if (refreshBtn) refreshBtn.addEventListener('click', (e) => { e.preventDefault(); refresh(); });
  const refreshBtn2 = $('#ev-refresh-all');
  if (refreshBtn2) refreshBtn2.addEventListener('click', (e) => { e.preventDefault(); refresh(); });

  applyFilters();
})();
