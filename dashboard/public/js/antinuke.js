/* Anti-Nuke page (upcoming feature).
 *
 * The page is behind the shared "Coming Soon……" overlay, so this script exits
 * immediately when the overlay is present (the same guard every upcoming page
 * uses). The bindings below are ready for the day the flag is removed.
 */

(function () {
  'use strict';

  const GUILD_ID = window.guildData && window.guildData.guildId;
  const ACTIONS = window.__ANTINUKE_ACTIONS || [];
  const RESPONSES = window.__ANTINUKE_RESPONSES || [];
  const SETTINGS = window.__ANTINUKE_SETTINGS || {};

  if (!GUILD_ID) return;
  if (document.querySelector('.upcoming-locked-wrap.locked, .beta-locked-wrap.locked')) return;

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function renderTrustedRoles() {
    const el = document.getElementById('an-trusted-roles');
    if (!el) return;
    const trusted = new Set(SETTINGS.trustedRoleIds || []);
    const roles = (window.guildData.roles || []);
    el.innerHTML = roles.length ? roles.map(r =>
      `<label class="switch mini"><input type="checkbox" class="an-trusted-role" value="${esc(r.id)}" ${trusted.has(r.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(r.name)}</span></label>`
    ).join('') : '<div class="field-hint">No roles loaded.</div>';
  }

  function collect() {
    const watched = {};
    $$('.an-watch-card').forEach(card => {
      const key = card.dataset.action;
      if (!ACTIONS.some(a => a.key === key)) return;
      watched[key] = {
        enabled: $('.an-watch-enabled', card) ? $('.an-watch-enabled', card).checked : false,
        threshold: parseInt(($('.an-watch-threshold', card) || {}).value, 10) || undefined,
        seconds: parseInt(($('.an-watch-seconds', card) || {}).value, 10) || undefined,
      };
    });
    return {
      enabled: $('#an-enabled') ? $('#an-enabled').checked : false,
      dryRun: $('#an-dry-run') ? $('#an-dry-run').checked : true,
      alertChannelId: ($('#an-alert-channel') || {}).value || null,
      responses: $$('.an-response-cb').filter(cb => cb.checked).map(cb => cb.value),
      trustedRoleIds: $$('.an-trusted-role').filter(cb => cb.checked).map(cb => cb.value),
      trustedUserIds: SETTINGS.trustedUserIds || [],
      watched,
    };
  }

  async function save() {
    const body = collect();
    if (!body.responses.length) {
      window.toast('Select at least one response action', 'error');
      throw new Error('No response action selected');
    }
    const data = await api(`/api/guilds/${GUILD_ID}/antinuke`, { method: 'PATCH', body: JSON.stringify(body) });
    if (data && data.antiNuke) Object.assign(SETTINGS, data.antiNuke);
  }

  renderTrustedRoles();
  window.saveBar.register(() => save());
  window.saveBar.track(document.querySelector('.an-page') || document.body);
})();