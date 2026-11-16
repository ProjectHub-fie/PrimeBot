/**
 * 24/7 Radio dashboard page client.
 *
 * Wrapped in an IIFE so none of its top-level bindings leak into the classic
 * script scope (a duplicate top-level `const` from another page script would be
 * a SyntaxError that kills this whole file — see the audit-log `const GUILD_ID`
 * gotcha in AGENTS.md).
 *
 * The page markup is server-rendered; this script only adds interactivity:
 * section switching, station add/delete, the session toggle and the live
 * control buttons (which call the bot-facing API).
 */
(function () {
  'use strict';

  const data = window.guildData || {};
  const guildId = data.guildId;
  const state = {
    session: data.radioSession || null,
    stations: Array.isArray(data.radioStations) ? data.radioStations : [],
  };

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function toast(msg, type) {
    if (window.toast) window.toast(msg, type);
    else console.log('[RADIO]', msg);
  }

  async function api(path, options) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      ...options,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
    return json;
  }

  // ── Section switching ──────────────────────────────────────────────────────
  function initSections() {
    const buttons = $$('.rd-section-btn');
    const sections = $$('.rd-section');
    const show = (key) => {
      buttons.forEach(b => b.classList.toggle('active', b.dataset.section === key));
      sections.forEach(s => s.classList.toggle('active', s.dataset.section === key));
    };
    buttons.forEach(b => b.addEventListener('click', () => show(b.dataset.section)));
    show('overview');
  }

  // ── Station management ─────────────────────────────────────────────────────
  function renderStationCard(s) {
    const el = document.createElement('div');
    el.className = 'rd-station-card';
    el.dataset.id = s.id;
    const global = !s.guildId ? '<span class="rd-pill rd-pill-global">Global</span>' : '';
    const actions = s.guildId ? `
      <div class="rd-station-actions">
        <button type="button" class="btn btn-secondary btn-sm rd-station-toggle" data-id="${s.id}" data-enabled="${s.enabled}">${s.enabled ? 'Disable' : 'Enable'}</button>
        <button type="button" class="btn btn-danger btn-sm rd-station-delete" data-id="${s.id}">Delete</button>
      </div>` : '';
    el.innerHTML = `
      <div class="rd-station-head">
        <span class="rd-station-name"></span>${global}
        <span class="rd-pill ${s.enabled ? 'rd-pill-play' : 'rd-pill-off'}">${s.enabled ? 'Enabled' : 'Disabled'}</span>
      </div>
      <div class="rd-station-desc"></div>
      <div class="rd-station-meta">
        <span class="rd-chip">${s.source}</span>
        ${s.genre ? `<span class="rd-chip">${s.genre}</span>` : ''}
        <code class="rd-station-ref"></code>
      </div>${actions}`;
    $('.rd-station-name', el).textContent = s.name;
    $('.rd-station-desc', el).textContent = s.description || '';
    $('.rd-station-ref', el).textContent = s.reference;
    return el;
  }

  async function refreshStations() {
    const res = await api(`/api/guilds/${guildId}/radio`);
    state.stations = res.stations || [];
    state.session = res.session || state.session;
    const list = $('#rd-stations');
    if (list) {
      list.innerHTML = '';
      if (!state.stations.length) list.innerHTML = '<p class="card-desc">No stations configured.</p>';
      state.stations.forEach(s => list.appendChild(renderStationCard(s)));
      bindStationActions();
      populateStationSelect();
    }
  }

  function openStationModal() {
    const tpl = $('#rd-station-form-template');
    const overlay = $('#rd-station-modal');
    if (!tpl || !overlay) return;
    overlay.innerHTML = '';
    overlay.appendChild(tpl.content.cloneNode(true));
    overlay.classList.remove('hidden');
    const close = () => overlay.classList.add('hidden');
    $$('[data-close]', overlay).forEach(b => b.addEventListener('click', close));
    $('#rd-station-save', overlay).addEventListener('click', async () => {
      const errEl = $('#rd-station-error', overlay);
      errEl.classList.add('hidden');
      const body = {
        id: $('#rd-station-id', overlay).value.trim(),
        name: $('#rd-station-name', overlay).value.trim(),
        description: $('#rd-station-desc', overlay).value.trim(),
        source: $('#rd-station-source', overlay).value,
        reference: $('#rd-station-ref', overlay).value.trim(),
      };
      try {
        await api(`/api/guilds/${guildId}/radio/station`, { method: 'POST', body: JSON.stringify(body) });
        close();
        toast('Station added.', 'success');
        refreshStations();
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    });
  }

  function bindStationActions() {
    $$('.rd-station-toggle').forEach(btn => btn.addEventListener('click', async () => {
      const s = state.stations.find(x => x.id === btn.dataset.id);
      if (!s) return;
      try {
        await api(`/api/guilds/${guildId}/radio/station`, {
          method: 'POST',
          body: JSON.stringify({ ...s, enabled: btn.dataset.enabled !== 'true' }),
        });
        refreshStations();
      } catch (err) { toast(err.message, 'error'); }
    }));
    $$('.rd-station-delete').forEach(btn => btn.addEventListener('click', async () => {
      if (!window.confirm('Delete this station?')) return;
      try {
        await api(`/api/guilds/${guildId}/radio/station/${btn.dataset.id}`, { method: 'DELETE' });
        toast('Station deleted.', 'success');
        refreshStations();
      } catch (err) { toast(err.message, 'error'); }
    }));
  }

  function populateStationSelect() {
    const sel = $('#rd-station-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">— none —</option>' + state.stations
      .filter(s => s.enabled)
      .map(s => `<option value="${s.id}"${state.session && state.session.stationId === s.id ? ' selected' : ''}>${s.name}</option>`)
      .join('');
  }

  // ── Session controls ───────────────────────────────────────────────────────
  function bindSessionControls() {
    const enabledEl = $('#rd-enabled');
    const channelEl = $('#rd-channel-select');
    const stationEl = $('#rd-station-select');
    const volumeEl = $('#rd-volume');
    const volumeOut = $('#rd-volume-out');

    async function save(patch) {
      try {
        const res = await api(`/api/guilds/${guildId}/radio`, { method: 'PATCH', body: JSON.stringify(patch) });
        state.session = res.session;
        toast('Radio updated.', 'success');
      } catch (err) {
        toast(err.message, 'error');
        if (enabledEl) enabledEl.checked = !!(state.session && state.session.enabled);
      }
    }

    if (enabledEl) enabledEl.addEventListener('change', () => save({ enabled: enabledEl.checked }));
    if (channelEl) channelEl.addEventListener('change', () => save({ channelId: channelEl.value }));
    if (stationEl) stationEl.addEventListener('change', () => save({ stationId: stationEl.value }));
    if (volumeEl && volumeOut) {
      volumeEl.addEventListener('input', () => { volumeOut.textContent = volumeEl.value; });
      volumeEl.addEventListener('change', () => toast('Volume changes apply from Discord with /radio volume.', 'info'));
    }

    // Live control buttons — these persist the intended state; the BOT performs
    // the actual voice operation through the shared session table.
    const btnStart = $('#rd-btn-start');
    const btnStop = $('#rd-btn-stop');
    if (btnStart) btnStart.addEventListener('click', () => save({ enabled: true, channelId: channelEl && channelEl.value }));
    if (btnStop) btnStop.addEventListener('click', () => save({ enabled: false }));
  }

  function init() {
    initSections();
    bindStationActions();
    populateStationSelect();
    bindSessionControls();
    const addBtn = $('#rd-add-station');
    if (addBtn) addBtn.addEventListener('click', openStationModal);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
