/* YouTube Notifications (Creator Hub) — dashboard client.
 *
 * Interactivity for the server-rendered page: section switching, add/remove
 * creators, enable/pause, the announcement-template editor, test announcements
 * and history refresh. All state is persisted server-side via
 * /api/guilds/:id/youtube — nothing is kept only in the browser.
 *
 * Wrapped in an IIFE so it never redeclares a top-level binding another page
 * script owns (the classic-script const-collision footgun).
 */
(function () {
  const GUILD_ID = window.guildData && window.guildData.guildId;
  if (!GUILD_ID) return;

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const api = window.api;
  const toast = window.toast;
  const esc = window.esc;

  let subs = [];
  let editingId = null;

  // The server renders the whole page from guild._config, so the initial
  // subscription/announcement state is already in the HTML — no API round-trip
  // needed on first load (that used to re-run requireGuildAdmin on every view:
  // another Discord REST call + ~4 more YouTube queries per page visit).
  // load() is still wired to the Refresh buttons to re-fetch on demand.
  function initialSubs() {
    try {
      const node = document.getElementById('yt-creators');
      if (!node) return [];
      return Array.from(node.querySelectorAll('script.yt-sub-data'))
        .map(el => { try { return JSON.parse(el.textContent); } catch { return null; } })
        .filter(Boolean);
    } catch { return []; }
  }
  const subsFromServer = initialSubs();
  if (subsFromServer.length) subs = subsFromServer;

  // ── Section switching ─────────────────────────────────────────────────────
  function showSection(key) {
    $$('.yt-section').forEach(s => { s.hidden = s.dataset.section !== key; });
    $$('.yt-section-btn').forEach(b => b.classList.toggle('active', b.dataset.section === key));
    try { history.replaceState(null, '', `?section=${encodeURIComponent(key)}`); } catch (_) {}
  }
  function initSections() {
    $('#yt-sections')?.addEventListener('click', (e) => {
      const btn = e.target.closest('.yt-section-btn');
      if (btn) showSection(btn.dataset.section);
    });
    const initial = new URLSearchParams(location.search).get('section');
    const valid = $$('.yt-section-btn').map(b => b.dataset.section);
    showSection(valid.includes(initial) ? initial : 'overview');
  }

  // ── Data loading ──────────────────────────────────────────────────────────
  async function load() {
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/youtube`);
      subs = data.subscriptions || [];
      renderCreators();
      renderStats(data.stats || {});
      renderHistory(data.announcements || []);
      renderTemplatePicker();
    } catch (err) {
      toast(err.message || 'Failed to load YouTube subscriptions.', 'error');
    }
  }

  function subById(id) { return subs.find(s => String(s.id) === String(id)); }

  function renderStats(stats) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('yt-stat-total', stats.totalSubscriptions ?? subs.length);
    set('yt-stat-active', stats.activeSubscriptions ?? 0);
    set('yt-stat-sent', stats.announcementsSent ?? 0);
    set('yt-stat-failed', stats.announcementsFailed ?? 0);
    set('yt-stat-paused', stats.pausedSubscriptions ?? 0);
    set('yt-stat-errored', stats.erroredSubscriptions ?? 0);
  }

  function pill(s) {
    if (!s.enabled) return '<span class="yt-pill yt-pill-off">Disabled</span>';
    if (s.paused) return '<span class="yt-pill yt-pill-pause">Paused</span>';
    if (s.lastError) return '<span class="yt-pill yt-pill-err">Error</span>';
    if (!s.baselineDone) return '<span class="yt-pill yt-pill-base">Baselining</span>';
    return '<span class="yt-pill yt-pill-on">Active</span>';
  }

  function fmtDate(v) {
    if (!v) return '—';
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  }

  function creatorCard(s) {
    const avatar = s.avatarUrl
      ? `<img class="yt-avatar" src="${esc(s.avatarUrl)}" alt="" onerror="this.style.display='none'"/>`
      : `<span class="yt-avatar yt-avatar-fallback">${esc((s.channelName || '?')[0].toUpperCase())}</span>`;
    return `<div class="yt-creator card" data-id="${esc(String(s.id))}">
      <div class="yt-creator-head">
        ${avatar}
        <div class="yt-creator-info">
          <div class="yt-creator-name">${esc(s.channelName || s.youtubeChannelId)}</div>
          <div class="yt-creator-meta"><a href="${esc(s.channelUrl || '#')}" target="_blank" rel="noopener">${esc(s.youtubeChannelId)}</a>${s.groupName ? ` · <span class="yt-group">${esc(s.groupName)}</span>` : ''}</div>
          <div class="yt-creator-status">${pill(s)} <span class="yt-creator-chan">${s.discordChannelId ? `#${esc(s.discordChannelId)}` : 'no channel set'}</span></div>
        </div>
        <div class="yt-creator-actions">
          <button class="btn btn-sm" data-act="test">Test</button>
          <button class="btn btn-sm" data-act="edit">Edit</button>
          <button class="btn btn-sm" data-act="pause">${s.paused ? 'Resume' : 'Pause'}</button>
          <button class="btn btn-sm" data-act="toggle">${s.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-danger" data-act="remove">Remove</button>
        </div>
      </div>
      <div class="yt-creator-sub">
        <span>Last check: <b>${esc(fmtDate(s.lastCheckedAt))}</b></span>
        <span>Last success: <b>${esc(fmtDate(s.lastSuccessAt))}</b></span>
        <span>Last video: <b>${esc(s.lastVideoId || '—')}</b></span>
        ${s.lastError ? `<span class="yt-err">Last error: ${esc(s.lastError)}</span>` : ''}
      </div>
    </div>`;
  }

  function renderCreators() {
    const wrap = $('#yt-creators');
    if (!wrap) return;
    const filter = ($('#yt-search')?.value || '').toLowerCase();
    const list = subs.filter(s => !filter || (s.channelName || '').toLowerCase().includes(filter) || s.youtubeChannelId.includes(filter));
    wrap.innerHTML = list.length
      ? list.map(creatorCard).join('')
      : `<div class="yt-empty">${window.svgIcon('youtube')}<p>No creators ${filter ? 'match your filter' : 'subscribed yet'}.</p></div>`;
  }

  function renderHistory(announcements) {
    const body = $('#yt-history-body');
    if (!body) return;
    if (!announcements.length) { body.innerHTML = `<tr><td colspan="4" class="yt-empty-cell">No announcements yet.</td></tr>`; return; }
    body.innerHTML = announcements.map(a => `<tr>
      <td><a href="${esc(a.videoUrl || '#')}" target="_blank" rel="noopener">${esc((a.videoTitle || a.videoId).slice(0, 60))}</a></td>
      <td>${esc(a.youtubeChannelId)}</td>
      <td><span class="yt-pill yt-pill-${a.status === 'sent' ? 'on' : (a.status === 'failed' ? 'err' : 'pause')}">${esc(a.status)}</span></td>
      <td>${esc(fmtDate(a.createdAt))}</td></tr>`).join('');
  }

  // ── Add a creator ─────────────────────────────────────────────────────────
  async function addCreator() {
    const input = $('#yt-add-input');
    const channel = $('#yt-add-channel');
    const group = $('#yt-add-group');
    const ref = (input?.value || '').trim();
    if (!ref) { toast('Paste a YouTube channel URL, ID or @handle.', 'error'); return; }
    const btn = $('#yt-add-btn');
    if (btn) btn.disabled = true;
    try {
      await api(`/api/guilds/${GUILD_ID}/youtube`, {
        method: 'POST',
        body: { reference: ref, channelId: channel?.value || null, groupName: group?.value || null },
      });
      toast('Creator added — monitoring new uploads.', 'success');
      if (input) input.value = '';
      if (group) group.value = '';
      await load();
    } catch (err) {
      toast(err.message || 'Failed to add the creator.', 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ── Per-creator actions ───────────────────────────────────────────────────
  async function patchSub(id, body, okMsg) {
    try {
      await api(`/api/guilds/${GUILD_ID}/youtube/${id}`, { method: 'PATCH', body });
      if (okMsg) toast(okMsg, 'success');
      await load();
    } catch (err) {
      toast(err.message || 'Update failed.', 'error');
    }
  }

  async function onCreatorAction(e) {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const card = btn.closest('.yt-creator');
    const id = card?.dataset.id;
    const sub = subById(id);
    if (!sub) return;
    const act = btn.dataset.act;
    if (act === 'toggle') return patchSub(id, { enabled: !sub.enabled }, sub.enabled ? 'Monitoring disabled.' : 'Monitoring enabled.');
    if (act === 'pause') return patchSub(id, { paused: !sub.paused }, sub.paused ? 'Monitoring resumed.' : 'Monitoring paused.');
    if (act === 'remove') {
      if (!confirm(`Remove ${sub.channelName || sub.youtubeChannelId}? Its announcement history is kept.`)) return;
      try {
        await api(`/api/guilds/${GUILD_ID}/youtube/${id}`, { method: 'DELETE' });
        toast('Creator removed.', 'success');
        await load();
      } catch (err) { toast(err.message || 'Remove failed.', 'error'); }
      return;
    }
    if (act === 'edit') { openTemplateEditor(sub); return; }
    if (act === 'test') {
      btn.disabled = true;
      try {
        await api(`/api/guilds/${GUILD_ID}/youtube/${id}/test`, { method: 'POST', body: {} });
        toast('Test announcement sent.', 'success');
      } catch (err) { toast(err.message || 'Test failed.', 'error'); }
      finally { btn.disabled = false; }
      return;
    }
  }

  // ── Announcement template editor ──────────────────────────────────────────
  function renderTemplatePicker() {
    const sel = $('#yt-template-picker');
    if (!sel) return;
    const current = editingId;
    sel.innerHTML = `<option value="">— Choose a creator —</option>` + subs.map(s =>
      `<option value="${esc(String(s.id))}"${String(current) === String(s.id) ? ' selected' : ''}>${esc(s.channelName || s.youtubeChannelId)}</option>`).join('');
  }

  function fillTemplateForm(sub) {
    const t = Object.assign({
      title: '', message: '', description: '', footer: '', color: '#FF0000',
      showCreator: true, showThumbnail: true, showTimestamp: true, showVideoUrl: true,
      mentionRoleId: null, contentMentions: false,
    }, sub.template || {});
    $('#yt-template-name').textContent = sub.channelName || sub.youtubeChannelId;
    $('#yt-tpl-title').value = t.title || '';
    $('#yt-tpl-description').value = t.description || '';
    $('#yt-tpl-message').value = t.message || '';
    $('#yt-tpl-footer').value = t.footer || '';
    $('#yt-tpl-color').value = t.color || '#FF0000';
    $('#yt-tpl-color-text').value = t.color || '#FF0000';
    $('#yt-tpl-role').value = t.mentionRoleId || '';
    $('#yt-tpl-showcreator').checked = t.showCreator !== false;
    $('#yt-tpl-showthumb').checked = t.showThumbnail !== false;
    $('#yt-tpl-showtime').checked = t.showTimestamp !== false;
    $('#yt-tpl-showurl').checked = t.showVideoUrl !== false;
    $('#yt-tpl-mentioneveryone').checked = t.contentMentions === true;
  }

  function openTemplateEditor(sub) {
    editingId = sub.id;
    $('#yt-template-empty').hidden = true;
    $('#yt-template-form').hidden = false;
    fillTemplateForm(sub);
    renderTemplatePicker();
    showSection('template');
  }

  async function saveTemplate() {
    if (!editingId) { toast('Choose a creator first.', 'error'); return; }
    const template = {
      title: $('#yt-tpl-title').value,
      description: $('#yt-tpl-description').value,
      message: $('#yt-tpl-message').value,
      footer: $('#yt-tpl-footer').value,
      color: $('#yt-tpl-color-text').value || $('#yt-tpl-color').value,
      mentionRoleId: $('#yt-tpl-role').value || null,
      showCreator: $('#yt-tpl-showcreator').checked,
      showThumbnail: $('#yt-tpl-showthumb').checked,
      showTimestamp: $('#yt-tpl-showtime').checked,
      showVideoUrl: $('#yt-tpl-showurl').checked,
      contentMentions: $('#yt-tpl-mentioneveryone').checked,
    };
    try {
      await api(`/api/guilds/${GUILD_ID}/youtube/${editingId}`, { method: 'PATCH', body: { template } });
      toast('Announcement saved.', 'success');
      await load();
    } catch (err) {
      toast(err.message || 'Save failed.', 'error');
    }
  }

  function resetTemplate() {
    $('#yt-tpl-title').value = '{creator} just uploaded a new video!';
    $('#yt-tpl-description').value = '{videoTitle}';
    $('#yt-tpl-message').value = '';
    $('#yt-tpl-footer').value = 'PrimeBot • YouTube Notifications';
    $('#yt-tpl-color').value = '#FF0000';
    $('#yt-tpl-color-text').value = '#FF0000';
    $('#yt-tpl-role').value = '';
    $('#yt-tpl-showcreator').checked = true;
    $('#yt-tpl-showthumb').checked = true;
    $('#yt-tpl-showtime').checked = true;
    $('#yt-tpl-showurl').checked = true;
    $('#yt-tpl-mentioneveryone').checked = false;
  }

  // ── Wiring ────────────────────────────────────────────────────────────────
  function init() {
    initSections();
    $('#yt-add-btn')?.addEventListener('click', addCreator);
    $('#yt-add-input')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') addCreator(); });
    $('#yt-creators')?.addEventListener('click', onCreatorAction);
    $('#yt-search')?.addEventListener('input', renderCreators);
    $('#yt-refresh')?.addEventListener('click', load);
    $('#yt-history-refresh')?.addEventListener('click', load);
    $('#yt-template-picker')?.addEventListener('change', (e) => {
      const sub = subById(e.target.value);
      if (sub) openTemplateEditor(sub);
    });
    $('#yt-tpl-save')?.addEventListener('click', saveTemplate);
    $('#yt-tpl-reset')?.addEventListener('click', resetTemplate);
    // Keep the color text input in sync with the picker.
    $('#yt-tpl-color')?.addEventListener('input', (e) => { const t = $('#yt-tpl-color-text'); if (t) t.value = e.target.value; });
    $('#yt-tpl-color-text')?.addEventListener('input', (e) => { const c = $('#yt-tpl-color'); if (c && /^#[0-9a-fA-F]{6}$/.test(e.target.value)) c.value = e.target.value; });
    // The server already rendered the current subscriptions/stats/history —
    // only wire the template picker to those creators. The Refresh buttons
    // call load() to re-fetch on demand.
    renderTemplatePicker();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
