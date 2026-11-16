/**
 * Music dashboard page client.
 *
 * Wrapped in an IIFE so none of its top-level bindings leak into the classic
 * script scope (a duplicate top-level `const` from another page script would be
 * a SyntaxError that kills this whole file — see the audit-log `const GUILD_ID`
 * gotcha in AGENTS.md).
 *
 * The page markup is server-rendered; this script only adds interactivity:
 * the 24/7 settings (enable/disable, channel, DJ role, volume, max queue) and
 * the playlist view/delete actions. Section switching + the radio station /
 * session controls are handled by dashboard/public/js/radio.js (loaded on this
 * page too, because radio lives inside the Music tab).
 */
(function () {
  'use strict';

  const data = window.guildData || {};
  const guildId = data.guildId;
  if (!guildId) return;

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function toast(msg, type) {
    if (window.toast) window.toast(msg, type);
    else console.log('[MUSIC]', msg);
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

  // ── 24/7 settings ──────────────────────────────────────────────────────────
  function bindSettings() {
    const enabledEl = $('#mu-247-enabled');
    const channelEl = $('#mu-247-channel');
    const djEl = $('#mu-dj-role');
    const volumeEl = $('#mu-default-volume');
    const volumeOut = $('#mu-default-volume-out');
    const maxQueueEl = $('#mu-max-queue');

    if (volumeEl && volumeOut) {
      volumeEl.addEventListener('input', () => { volumeOut.textContent = volumeEl.value; });
    }

    async function save(patch, okMsg) {
      try {
        const res = await api(`/api/guilds/${guildId}/music`, { method: 'PATCH', body: JSON.stringify(patch) });
        toast(okMsg || 'Music settings saved.', 'success');
        return res.settings;
      } catch (err) {
        toast(err.message, 'error');
        if (enabledEl) enabledEl.checked = !!(data.musicSettings && data.musicSettings.twentyFourSevenEnabled);
        throw err;
      }
    }

    if (enabledEl) enabledEl.addEventListener('change', () => save({ twentyFourSevenEnabled: enabledEl.checked }, enabledEl.checked ? '24/7 enabled.' : '24/7 disabled.'));
    if (channelEl) channelEl.addEventListener('change', () => save({ twentyFourSevenChannelId: channelEl.value || null }, '24/7 channel updated.'));
    if (djEl) djEl.addEventListener('change', () => save({ djRoleId: djEl.value || null }, 'DJ role updated.'));
    if (volumeEl) volumeEl.addEventListener('change', () => save({ defaultVolume: parseInt(volumeEl.value, 10) }, 'Default volume updated.'));
    if (maxQueueEl) maxQueueEl.addEventListener('change', () => save({ maxQueue: parseInt(maxQueueEl.value, 10) }, 'Maximum queue size updated.'));
  }

  // ── Playlists ──────────────────────────────────────────────────────────────
  async function viewPlaylist(id) {
    const overlay = $('#mu-playlist-modal');
    const tpl = $('#mu-playlist-template');
    if (!overlay || !tpl) return;
    overlay.innerHTML = '';
    overlay.appendChild(tpl.content.cloneNode(true));
    overlay.classList.remove('hidden');
    $$('[data-close]', overlay).forEach(b => b.addEventListener('click', () => overlay.classList.add('hidden')));
    try {
      const res = await api(`/api/guilds/${guildId}/music/playlists/${id}`);
      $('#mu-pl-title', overlay).textContent = res.playlist ? res.playlist.name : 'Playlist';
      const tracks = res.tracks || [];
      $('#mu-pl-body', overlay).innerHTML = tracks.length
        ? `<ol>${tracks.map(t => `<li>${escapeHtml(t.title || 'Unknown')}${t.artist ? ' — ' + escapeHtml(t.artist) : ''}</li>`).join('')}</ol>`
        : 'This playlist is empty.';
    } catch (err) {
      $('#mu-pl-body', overlay).textContent = err.message;
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function bindPlaylists() {
    $$('.mu-playlist-view').forEach(btn => btn.addEventListener('click', () => viewPlaylist(btn.dataset.id)));
    $$('.mu-playlist-delete').forEach(btn => btn.addEventListener('click', async () => {
      if (!window.confirm('Delete this playlist?')) return;
      try {
        await api(`/api/guilds/${guildId}/music/playlists/${btn.dataset.id}`, { method: 'DELETE' });
        toast('Playlist deleted.', 'success');
        window.location.reload();
      } catch (err) { toast(err.message, 'error'); }
    }));
  }

  bindSettings();
  bindPlaylists();
})();
