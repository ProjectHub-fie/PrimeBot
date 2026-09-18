/* Automod page — premium moderation control panel.
 *
 * Responsibilities:
 *   • section navigation + deep links (?section=incidents)
 *   • the rule builder (add / remove / edit / duplicate)
 *   • exemptions + warning-ladder editors
 *   • rule tester, presets, incident center (search + filter + pagination),
 *     analytics charts, warnings/appeals tables
 *   • ONE batched save via the floating save bar (no per-toggle writes)
 *
 * Everything renders from window.__AUTOMOD_* + #guild-data, so the page never
 * needs a config fetch just to draw itself.
 */

(function () {
  'use strict';

  const GUILD_ID = window.guildData && window.guildData.guildId;
  const RULES = window.__AUTOMOD_RULES || [];
  const ACTIONS = window.__AUTOMOD_ACTIONS || [];
  const SEVERITIES = window.__AUTOMOD_SEVERITIES || [];
  const PRESETS = window.__AUTOMOD_PRESETS || [];
  const SETTINGS = window.__AUTOMOD_SETTINGS || {};
  const WARN_ACTIONS = ACTIONS.filter(a => ['warn', 'timeout', 'kick', 'ban'].includes(a.key));
  const SEV_BY_KEY = Object.fromEntries(SEVERITIES.map(s => [s.key, s]));

  if (!GUILD_ID) return;
  // Upcoming/beta overlays blur an inert copy of the page; don't run behind it.
  if (document.querySelector('.upcoming-locked-wrap.locked, .beta-locked-wrap.locked')) return;

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ── Small render helpers ──────────────────────────────────────────────────

  function sevBadge(sev) {
    const meta = SEV_BY_KEY[sev] || SEV_BY_KEY.medium;
    return `<span class="am-sev am-sev-${esc(meta.key)}">${window.svgIcon(meta.iconName)} ${esc(meta.label)}</span>`;
  }

  function actionLabel(key) {
    const a = ACTIONS.find(x => x.key === key);
    return a ? a.label : key;
  }

  function skeleton(rows = 4) {
    return `<div class="am-skeleton">${Array.from({ length: rows }, () => '<div class="am-skel-row"></div>').join('')}</div>`;
  }

  function emptyState(icon, title, text) {
    return `<div class="am-empty"><div class="am-empty-icon">${window.svgIcon(icon)}</div>
      <div class="am-empty-title">${esc(title)}</div><div class="am-empty-text">${esc(text)}</div></div>`;
  }

  function errorState(message, retryAttr) {
    return `<div class="am-error"><div class="am-error-icon">${window.svgIcon('alertTriangle')}</div>
      <div class="am-error-text">${esc(message)}</div>
      ${retryAttr ? `<button class="btn btn-secondary" ${retryAttr} type="button">${window.svgIcon('refresh')} Try again</button>` : ''}</div>`;
  }

  function confirmDialog({ title, text, confirmLabel = 'Confirm', danger = false }) {
    return new Promise(resolve => {
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.innerHTML = `
        <div class="modal floating-window am-confirm" role="dialog" aria-modal="true" aria-label="${esc(title)}">
          <div class="modal-head"><h3>${window.svgIcon(danger ? 'alertTriangle' : 'info')} ${esc(title)}</h3>
            <button class="modal-close" type="button" aria-label="Close">${window.svgIcon('x')}</button></div>
          <div class="modal-body"><p class="modal-desc">${esc(text)}</p>
            <div class="modal-actions">
              <button class="btn btn-secondary" data-cancel type="button">Cancel</button>
              <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-confirm type="button">${esc(confirmLabel)}</button>
            </div></div>
        </div>`;
      document.body.appendChild(overlay);
      const done = (val) => { overlay.remove(); document.removeEventListener('keydown', onKey); resolve(val); };
      const onKey = (e) => { if (e.key === 'Escape') done(false); };
      document.addEventListener('keydown', onKey);
      $('[data-cancel]', overlay).addEventListener('click', () => done(false));
      $('.modal-close', overlay).addEventListener('click', () => done(false));
      overlay.addEventListener('click', (e) => { if (e.target === overlay) done(false); });
      $('[data-confirm]', overlay).addEventListener('click', () => done(true));
      $('[data-confirm]', overlay).focus();
    });
  }

  // ── Rule card rendering (mirrors render/automod-page.js) ──────────────────
  //
  // Param inputs come from the shared RULE_PARAMS catalog injected as
  // window.__AUTOMOD_PARAMS, so this renderer and the server renderer can never
  // drift: adding a rule parameter is a one-line change in automodRules.js.

  const PARAMS = window.__AUTOMOD_PARAMS || {};

  function paramDefs(type) {
    const meta = RULES.find(r => r.key === type);
    if (!meta) return [];
    return (meta.params || []).map(key => {
      const def = PARAMS[key];
      if (!def) return null;
      return (def.labelByRule && def.labelByRule[type]) ? Object.assign({}, def, { label: def.labelByRule[type] }) : def;
    }).filter(Boolean);
  }

  function paramValue(rule, def) {
    const raw = rule ? rule[def.valueKey] : undefined;
    if (def.type === 'list') return (Array.isArray(raw) ? raw : []).map(String).join(', ');
    if (def.type === 'switch') return raw === undefined ? def.defaultOn === true : raw === true;
    return raw === undefined || raw === null ? '' : String(raw);
  }

  function paramInputs(rule, meta) {
    return paramDefs(meta.key).map(def => {
      if (def.type === 'switch') {
        return `<label class="switch mini am-inline-switch">
          <input type="checkbox" class="${esc(def.cssClass)}" ${paramValue(rule, def) === true ? 'checked' : ''}/>
          <span class="switch-text">${esc(def.label)}</span></label>`;
      }
      if (def.type === 'number') {
        return `<label class="am-field am-field-num"><span class="am-field-label">${esc(def.label)}</span>
          <input type="number" class="${esc(def.cssClass)}" value="${esc(paramValue(rule, def))}"
                 min="${def.min ?? ''}" max="${def.max ?? ''}" placeholder="${esc(def.placeholder || '')}" /></label>`;
      }
      return `<label class="am-field"><span class="am-field-label">${esc(def.label)}</span>
        <input type="text" class="${esc(def.cssClass)}" value="${esc(paramValue(rule, def))}"
               placeholder="${esc(def.placeholder || '')}" /></label>`;
    }).join('');
  }

  function ruleCardHTML(rule = {}) {
    const meta = RULES.find(r => r.key === rule.type) || RULES[0];
    if (!meta) return '';
    const selected = Array.isArray(rule.actions) && rule.actions.length ? rule.actions
      : (rule.action ? [rule.action] : ['delete']);
    const actionChecks = ACTIONS.map(a => `
      <label class="switch mini am-action-label" title="${esc(a.label)}">
        <input type="checkbox" class="am-action" value="${esc(a.key)}" ${selected.includes(a.key) ? 'checked' : ''}/>
        <span class="switch-text">${window.svgIcon(a.iconName)} ${esc(a.label)}</span>
      </label>`).join('');
    const sev = rule.severity || meta.severity || 'medium';
    const sevOpts = SEVERITIES.map(s => `<option value="${esc(s.key)}" ${sev === s.key ? 'selected' : ''}>${esc(s.label)}</option>`).join('');
    return `
      <div class="am-rule-card" data-type="${esc(meta.key)}" data-category="${esc(meta.category || '')}">
        <div class="am-rule-head">
          <label class="switch am-rule-toggle" title="Enable or disable this rule">
            <input type="checkbox" class="am-enabled" ${rule.enabled !== false ? 'checked' : ''}/><span class="slider"></span>
          </label>
          <span class="am-rule-icon">${window.svgIcon(meta.iconName)}</span>
          <div class="am-rule-title">
            <div class="am-rule-name">${esc(meta.label)}</div>
            <div class="am-rule-cat">${esc(meta.category || 'General')}</div>
          </div>
          <div class="am-rule-head-actions">
            ${sevBadge(sev)}
            <button type="button" class="am-icon-btn am-rule-test" title="Test this rule">${window.svgIcon('flask')}</button>
            <button type="button" class="am-icon-btn am-rule-dup" title="Duplicate this rule">${window.svgIcon('copy')}</button>
            <button type="button" class="am-icon-btn am-remove" title="Remove this rule">${window.svgIcon('x')}</button>
          </div>
        </div>
        <p class="am-rule-desc">${esc(meta.description || '')}</p>
        <div class="am-rule-params">
          <label class="am-field am-field-num"><span class="am-field-label">Severity</span><select class="am-severity">${sevOpts}</select></label>
          <label class="am-field am-field-num"><span class="am-field-label">Cooldown (s)</span>
            <input type="number" class="am-cooldown" value="${rule.cooldown || 0}" min="0" max="3600" title="Skip repeat actions for the same member for this many seconds" /></label>
          ${paramInputs(rule, meta)}
        </div>
        <div class="am-rule-actions-label">Then apply</div>
        <div class="am-actions-group">${actionChecks}</div>
        <div class="am-rule-perrule">
          <button type="button" class="am-link-btn am-rule-exempt-toggle">${window.svgIcon('userCheck')} Per-rule exemptions</button>
          <div class="am-rule-exempt" hidden>
            <label class="am-field"><span class="am-field-label">Exempt roles (IDs, comma-separated)</span>
              <input type="text" class="am-exempt-roles" value="${esc((rule.exemptRoleIds || []).join(', '))}" placeholder="role ids" /></label>
            <label class="am-field"><span class="am-field-label">Exempt channels (IDs, comma-separated)</span>
              <input type="text" class="am-exempt-channels" value="${esc((rule.exemptChannelIds || []).join(', '))}" placeholder="channel ids" /></label>
          </div>
        </div>
      </div>`;
  }

  function collectRules(scope) {
    const out = [];
    $$('.am-rule-card', scope || document).forEach(card => {
      const type = card.dataset.type;
      if (!type) return;
      const actions = $$('.am-action', card).filter(cb => cb.checked).map(cb => cb.value);
      const rule = {
        type,
        enabled: $('.am-enabled', card) ? $('.am-enabled', card).checked : true,
        actions: actions.length ? actions : ['delete'],
        severity: $('.am-severity', card) ? $('.am-severity', card).value : 'medium',
      };
      const cooldown = parseInt((($('.am-cooldown', card) || {}).value), 10);
      if (Number.isFinite(cooldown) && cooldown > 0) rule.cooldown = cooldown;
      // Every rule-specific field is read through the shared param catalog, so a
      // new parameter is picked up automatically on save.
      for (const def of paramDefs(type)) {
        const el = $(`.${def.cssClass}`, card);
        if (!el) continue;
        if (def.type === 'switch') {
          rule[def.valueKey] = el.checked;
        } else if (def.type === 'number') {
          const n = parseInt(el.value, 10);
          if (Number.isFinite(n)) rule[def.valueKey] = n;
        } else {
          const list = el.value.split(',').map(s => s.trim()).filter(Boolean);
          if (list.length) {
            rule[def.valueKey] = list.map(v => {
              let out2 = def.lowercase === false ? v : v.toLowerCase();
              if (def.stripDot) out2 = out2.replace(/^\./, '');
              return out2;
            });
          }
        }
      }
      // Per-rule exemptions are not part of the param catalog (they are a
      // first-class rule field).
      const exRoles = ($('.am-exempt-roles', card) || {}).value || '';
      const exChans = ($('.am-exempt-channels', card) || {}).value || '';
      const roleList = exRoles.split(',').map(s => s.trim()).filter(Boolean);
      const chanList = exChans.split(',').map(s => s.trim()).filter(Boolean);
      if (roleList.length) rule.exemptRoleIds = roleList;
      if (chanList.length) rule.exemptChannelIds = chanList;
      out.push(rule);
    });
    return out;
  }

  // ── Sections ──────────────────────────────────────────────────────────────

  function showSection(key, { push = true } = {}) {
    if (!$(`.am-section[data-section="${key}"]`)) key = 'overview';
    $$('.am-section').forEach(sec => { sec.hidden = sec.dataset.section !== key; });
    $$('.am-section-btn').forEach(btn => {
      const on = btn.dataset.section === key;
      btn.classList.toggle('active', on);
      btn.setAttribute('aria-current', on ? 'true' : 'false');
    });
    if (push && window.history && window.history.replaceState) {
      const url = new URL(window.location.href);
      url.searchParams.set('section', key);
      window.history.replaceState({}, '', url);
    }
    if (key === 'incidents') refreshIncidents();
    if (key === 'analytics') refreshAnalytics();
    if (key === 'warnings') refreshWarnings();
  }

  $('#am-sections')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.am-section-btn');
    if (btn) showSection(btn.dataset.section);
  });

  // ── Rule list wiring ──────────────────────────────────────────────────────

  function syncRuleLists() {
    // The master list is the source of truth for saving; the per-section lists
    // are views of it, filtered by category.
    const master = document.getElementById('am-rules-all');
    if (!master) return;
    const CATEGORY_SECTION = { 'Anti-Spam': 'spam', 'Content Protection': 'content', 'Raid Protection': 'raid' };
    ['am-rules-spam', 'am-rules-content', 'am-rules-raid'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const section = id.replace('am-rules-', '');
      const cards = $$('.am-rule-card', master).filter(c => CATEGORY_SECTION[c.dataset.category] === section);
      el.innerHTML = cards.length ? cards.map(c => c.outerHTML).join('')
        : emptyState('shield', 'No rules in this section', 'Add one from the Rules tab.');
    });
  }

  function bindRuleInteractions() {
    document.addEventListener('click', async (e) => {
      const addBtn = e.target.closest('#am-add-rule');
      if (addBtn) {
        const type = $('#am-add-type') ? $('#am-add-type').value : 'invites';
        const list = document.getElementById('am-rules-all');
        if (!list) return;
        const empty = $('.am-empty', list);
        if (empty) empty.remove();
        list.insertAdjacentHTML('beforeend', ruleCardHTML({ type, enabled: true, actions: ['delete'] }));
        syncRuleLists();
        window.saveBar.markDirty();
        const added = list.lastElementChild;
        if (added) added.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        return;
      }

      const removeBtn = e.target.closest('.am-remove');
      if (removeBtn) {
        const card = removeBtn.closest('.am-rule-card');
        if (!card) return;
        const name = ($('.am-rule-name', card) || {}).textContent || 'this rule';
        const ok = await confirmDialog({
          title: 'Remove rule', danger: true, confirmLabel: 'Remove',
          text: `Remove "${name}" from this server? You'll still need to save to apply the change.`,
        });
        if (!ok) return;
        card.remove();
        const master = document.getElementById('am-rules-all');
        if (master && !$('.am-rule-card', master)) master.innerHTML = emptyState('shield', 'No rules yet', 'Add a protection rule to start moderating this server automatically.');
        syncRuleLists();
        window.saveBar.markDirty();
        return;
      }

      const dupBtn = e.target.closest('.am-rule-dup');
      if (dupBtn) {
        const card = dupBtn.closest('.am-rule-card');
        if (!card) return;
        const copy = document.createElement('div');
        copy.innerHTML = card.outerHTML;
        const clone = copy.firstElementChild;
        clone.dataset.duplicate = 'true';
        card.after(clone);
        syncRuleLists();
        window.saveBar.markDirty();
        window.toast('Rule duplicated — save to apply', 'success');
        return;
      }

      const testBtn = e.target.closest('.am-rule-test');
      if (testBtn) {
        const card = testBtn.closest('.am-rule-card');
        const type = card && card.dataset.type;
        const meta = RULES.find(r => r.key === type);
        showSection('overview');
        const input = $('#am-test-content');
        if (input) { input.focus(); input.select(); }
        window.toast(`Test mode: paste a sample message to check "${meta ? meta.label : type}"`, 'success');
        return;
      }

      const exemptToggle = e.target.closest('.am-rule-exempt-toggle');
      if (exemptToggle) {
        const box = exemptToggle.parentElement.querySelector('.am-rule-exempt');
        if (box) box.hidden = !box.hidden;
        return;
      }

      const ladderAdd = e.target.closest('#am-ladder-add');
      if (ladderAdd) {
        const ladder = $('#am-ladder');
        if (!ladder) return;
        const counts = $$('.am-ladder-count', ladder).map(i => parseInt(i.value, 10) || 1);
        const next = (counts.length ? Math.max(...counts) : 1) + 1;
        const row = document.createElement('div');
        row.className = 'am-ladder-row';
        row.setAttribute('data-ladder-row', '');
        row.innerHTML = `
          <span class="am-ladder-at">At</span>
          <input type="number" class="am-ladder-count" value="${next}" min="1" max="100" aria-label="Warning count" />
          <span class="am-ladder-warn">warnings →</span>
          <select class="am-ladder-action" aria-label="Escalation action">
            ${WARN_ACTIONS.map(a => `<option value="${esc(a.key)}">${esc(a.label)}</option>`).join('')}
          </select>
          <button type="button" class="am-icon-btn am-ladder-remove" title="Remove this step">${window.svgIcon('x')}</button>`;
        ladder.appendChild(row);
        window.saveBar.markDirty();
        return;
      }

      const ladderRemove = e.target.closest('.am-ladder-remove');
      if (ladderRemove) {
        if ($$('.am-ladder-row').length <= 1) { window.toast('Keep at least one escalation step', 'error'); return; }
        ladderRemove.closest('.am-ladder-row').remove();
        window.saveBar.markDirty();
        return;
      }

      const presetBtn = e.target.closest('.am-preset-apply');
      if (presetBtn) {
        const key = presetBtn.dataset.preset;
        const preset = PRESETS.find(p => p.key === key);
        if (!preset) return;
        const ok = await confirmDialog({
          title: `Apply the ${preset.label} preset?`,
          text: 'This replaces your current rule list. Your log channel, exemptions, warnings and other settings are kept.',
          confirmLabel: 'Apply preset',
        });
        if (!ok) return;
        presetBtn.disabled = true;
        try {
          const data = await api(`/api/guilds/${GUILD_ID}/automod/preset`, { method: 'POST', body: JSON.stringify({ preset: key }) });
          renderFromSettings(data.automod);
          window.toast(`${preset.label} preset applied`, 'success');
        } catch (err) {
          window.toast(err.message || 'Failed to apply the preset', 'error');
        } finally {
          presetBtn.disabled = false;
        }
      }
    });

    // Any edit inside the page dirties the save bar (one batched save).
    document.addEventListener('change', (e) => {
      if (e.target.closest('.am-page')) window.saveBar.markDirty();
    });
    document.addEventListener('input', (e) => {
      if (e.target.closest('.am-page') && e.target.type !== 'search') window.saveBar.markDirty();
    });
  }

  /** Re-render rule lists + overview chips from a settings object. */
  function renderFromSettings(s) {
    const rules = (s && Array.isArray(s.rules)) ? s.rules : [];
    const master = document.getElementById('am-rules-all');
    if (master) master.innerHTML = rules.length ? rules.map(ruleCardHTML).join('')
      : emptyState('shield', 'No rules yet', 'Add a protection rule to start moderating this server automatically.');
    syncRuleLists();
    const overview = document.getElementById('am-overview-rules');
    if (overview) {
      overview.innerHTML = rules.length ? rules.map(r => {
        const meta = RULES.find(x => x.key === r.type) || RULES[0];
        return `<div class="am-chip ${r.enabled !== false ? '' : 'am-chip-off'}">${window.svgIcon(meta.iconName)} ${esc(meta.label)}</div>`;
      }).join('') : '<div class="field-hint">No rules configured yet.</div>';
    }
    const stat = document.querySelector('#am-stats .am-stat-value');
    if (stat) stat.textContent = `${rules.filter(r => r.enabled !== false).length} / ${rules.length}`;
  }

  // ── Exemptions ────────────────────────────────────────────────────────────

  function renderExemptLists() {
    const s = SETTINGS;
    const roleSet = new Set(s.exemptRoleIds || []);
    const chanSet = new Set(s.exemptChannelIds || []);
    const roles = (window.guildData.roles || []).map(r =>
      `<label class="switch mini"><input type="checkbox" class="am-exempt-role" value="${esc(r.id)}" ${roleSet.has(r.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(r.name)}</span></label>`
    ).join('') || '<div class="field-hint">No roles loaded.</div>';
    const channels = (window.guildData.channels || []).map(c =>
      `<label class="switch mini"><input type="checkbox" class="am-exempt-channel" value="${esc(c.id)}" ${chanSet.has(c.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(c.name)}</span></label>`
    ).join('') || '<div class="field-hint">No channels loaded.</div>';
    const users = (s.exemptUserIds || []).map(id =>
      `<div class="am-exempt-user" data-id="${esc(id)}"><code>${esc(id)}</code><button type="button" class="am-icon-btn am-exempt-user-remove" title="Remove">${window.svgIcon('x')}</button></div>`
    ).join('') || '<div class="field-hint">No exempt members.</div>';
    const rolesEl = document.getElementById('am-exempt-roles');
    const chanEl = document.getElementById('am-exempt-channels');
    const userEl = document.getElementById('am-exempt-users');
    if (rolesEl) rolesEl.innerHTML = roles;
    if (chanEl) chanEl.innerHTML = channels;
    if (userEl) {
      userEl.innerHTML = users + `
        <div class="am-add-row">
          <input type="text" id="am-exempt-user-input" placeholder="User ID" inputmode="numeric" />
          <button class="btn btn-secondary" id="am-exempt-user-add" type="button">${window.svgIcon('plus')} Add member</button>
        </div>`;
    }
  }

  document.addEventListener('click', (e) => {
    if (e.target.closest('#am-exempt-user-add')) {
      const input = document.getElementById('am-exempt-user-input');
      const id = ((input && input.value) || '').trim();
      if (!/^\d{15,22}$/.test(id)) { window.toast('Enter a valid Discord user ID', 'error'); return; }
      const list = document.getElementById('am-exempt-users');
      if (list && !$(`.am-exempt-user[data-id="${id}"]`, list)) {
        list.insertAdjacentHTML('afterbegin',
          `<div class="am-exempt-user" data-id="${esc(id)}"><code>${esc(id)}</code><button type="button" class="am-icon-btn am-exempt-user-remove" title="Remove">${window.svgIcon('x')}</button></div>`);
      }
      input.value = '';
      window.saveBar.markDirty();
    }
    const rm = e.target.closest('.am-exempt-user-remove');
    if (rm) { rm.closest('.am-exempt-user').remove(); window.saveBar.markDirty(); }
  });

  // ── Rule tester ───────────────────────────────────────────────────────────

  function renderTestResult(result) {
    const el = document.getElementById('am-test-result');
    if (!el) return;
    if (!result) { el.innerHTML = ''; return; }
    if (result.enabled === false) {
      el.innerHTML = `<div class="am-test-note am-test-note-warn">${window.svgIcon('info')} AutoMod is disabled, so this message would not be scanned.</div>`;
      return;
    }
    const matches = result.matches || [];
    const skipped = result.skipped || [];
    const header = `<div class="am-test-summary">
        ${matches.length
          ? `<span class="am-pill am-pill-off">${window.svgIcon('shieldAlert')} ${matches.length} rule${matches.length === 1 ? '' : 's'} matched</span>`
          : `<span class="am-pill am-pill-on">${window.svgIcon('check')} No rules matched</span>`}
        ${result.dryRun ? `<span class="am-pill am-pill-warn">${window.svgIcon('flask')} Dry run — no action would be taken</span>` : ''}
      </div>`;
    const cards = matches.map(m => `
      <div class="am-test-match">
        <div class="am-test-match-head">
          <span class="am-rule-icon">${window.svgIcon(m.icon || 'shield')}</span>
          <span class="am-test-match-name">${esc(m.label || m.type)}</span>
          ${m.severity ? sevBadge(m.severity) : ''}
        </div>
        ${m.error ? `<div class="am-test-note am-test-note-warn">${window.svgIcon('alertTriangle')} ${esc(m.error)}</div>` : ''}
        ${m.reason ? `<div class="am-test-reason">${esc(m.reason)}</div>` : ''}
        ${(m.actionLabels && m.actionLabels.length) ? `<div class="am-test-actions">Would: ${m.actionLabels.map(a => `<span class="am-chip">${esc(a)}</span>`).join('')}</div>` : ''}
      </div>`).join('');
    const skippedNote = skipped.length
      ? `<div class="am-test-note">${window.svgIcon('info')} Skipped: ${esc(skipped.join(', '))} (a more specific rule matched first).</div>` : '';
    el.innerHTML = header + cards + skippedNote;
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('#am-run-test');
    if (!btn) return;
    const input = document.getElementById('am-test-content');
    const content = ((input && input.value) || '').trim();
    if (!content) { window.toast('Enter a sample message first', 'error'); return; }
    const el = document.getElementById('am-test-result');
    if (el) el.innerHTML = skeleton(2);
    btn.disabled = true;
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod/test`, { method: 'POST', body: JSON.stringify({ content }) });
      renderTestResult(data.result);
    } catch (err) {
      if (el) el.innerHTML = errorState(err.message || 'Failed to test the message');
    } finally {
      btn.disabled = false;
    }
  });

  // ── Incident center ───────────────────────────────────────────────────────

  const incidents = { offset: 0, limit: 25, total: 0 };

  function incidentFilters() {
    return {
      search: ($('#am-inc-search') || {}).value || '',
      rule: ($('#am-inc-rule') || {}).value || '',
      severity: ($('#am-inc-severity') || {}).value || '',
      action: ($('#am-inc-action') || {}).value || '',
      days: ($('#am-inc-days') || {}).value || '',
    };
  }

  async function refreshIncidents({ resetOffset = false } = {}) {
    const el = document.getElementById('am-incidents-list');
    if (!el) return;
    if (resetOffset) incidents.offset = 0;
    el.innerHTML = skeleton(5);
    const f = incidentFilters();
    const params = new URLSearchParams();
    if (f.search) params.set('search', f.search);
    if (f.rule) params.set('rule', f.rule);
    if (f.severity) params.set('severity', f.severity);
    if (f.action) params.set('action', f.action);
    if (f.days) params.set('days', f.days);
    params.set('limit', incidents.limit);
    params.set('offset', incidents.offset);
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod/incidents?${params}`);
      incidents.total = data.total || 0;
      const rows = data.incidents || [];
      if (rows.length === 0) {
        const unfiltered = !f.search && !f.rule && !f.severity && !f.action && !f.days;
        el.innerHTML = emptyState('inbox', 'No incidents',
          unfiltered ? 'Nothing has been actioned yet. Incidents appear here as rules fire.' : 'No incidents match these filters.');
      } else {
        el.innerHTML = `<table class="am-table">
          <thead><tr><th>User</th><th>Rule</th><th>Action</th><th>Severity</th><th>Channel</th><th>Time</th></tr></thead>
          <tbody>${rows.map(r => `
            <tr>
              <td data-label="User">${r.userId ? `<code>${esc(r.username || r.userId)}</code>` : '—'}</td>
              <td data-label="Rule">${esc(r.ruleLabel || r.ruleType)}</td>
              <td data-label="Action">${(r.actions || []).map(a => `<span class="am-chip am-chip-sm">${esc(actionLabel(a))}</span>`).join(' ') || '—'}${r.dryRun ? ' <span class="am-chip am-chip-sm am-chip-warn">dry run</span>' : ''}</td>
              <td data-label="Severity">${sevBadge(r.severity)}</td>
              <td data-label="Channel">${r.channelId ? `<code>${esc(r.channelId)}</code>` : '—'}</td>
              <td data-label="Time">${esc(r.createdAt ? new Date(r.createdAt).toLocaleString() : '—')}</td>
            </tr>`).join('')}</tbody></table>`;
      }
      renderIncidentPager();
    } catch (err) {
      el.innerHTML = errorState(err.message || 'Unable to load incidents', 'data-retry="incidents"');
    }
  }

  function renderIncidentPager() {
    const el = document.getElementById('am-incidents-pager');
    if (!el) return;
    const { offset, limit, total } = incidents;
    if (total <= limit) {
      el.innerHTML = total ? `<span class="am-pager-info">${total} incident${total === 1 ? '' : 's'}</span>` : '';
      return;
    }
    const page = Math.floor(offset / limit) + 1;
    const pages = Math.ceil(total / limit);
    el.innerHTML = `
      <span class="am-pager-info">${total} incidents · page ${page} / ${pages}</span>
      <div class="am-pager-btns">
        <button class="btn btn-secondary" data-inc-prev type="button" ${offset === 0 ? 'disabled' : ''}>${window.svgIcon('arrowLeft')} Prev</button>
        <button class="btn btn-secondary" data-inc-next type="button" ${offset + limit >= total ? 'disabled' : ''}>Next ${window.svgIcon('arrowRight')}</button>
      </div>`;
  }

  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-inc-prev]')) { incidents.offset = Math.max(0, incidents.offset - incidents.limit); refreshIncidents(); }
    if (e.target.closest('[data-inc-next]')) { incidents.offset += incidents.limit; refreshIncidents(); }
    if (e.target.closest('[data-retry="incidents"]')) refreshIncidents();
    if (e.target.closest('[data-retry="analytics"]')) refreshAnalytics();
  });

  let incSearchTimer = null;
  document.addEventListener('input', (e) => {
    if (e.target.id === 'am-inc-search') {
      clearTimeout(incSearchTimer);
      incSearchTimer = setTimeout(() => refreshIncidents({ resetOffset: true }), 300);
    }
  });
  document.addEventListener('change', (e) => {
    if (['am-inc-rule', 'am-inc-severity', 'am-inc-action', 'am-inc-days'].includes(e.target.id)) {
      refreshIncidents({ resetOffset: true });
    }
  });

  // ── Analytics ─────────────────────────────────────────────────────────────

  function statCardHTML(label, value, icon) {
    return `<div class="am-stat"><div class="am-stat-icon">${window.svgIcon(icon)}</div>
      <div class="am-stat-body"><div class="am-stat-label">${esc(label)}</div>
      <div class="am-stat-value">${esc(String(value))}</div></div></div>`;
  }

  function donut(segments, { size = 132, thickness = 16 } = {}) {
    const total = segments.reduce((sum, s) => sum + s.value, 0);
    const r = (size - thickness) / 2;
    const c = 2 * Math.PI * r;
    if (!total) {
      return `<svg viewBox="0 0 ${size} ${size}" class="am-donut" role="img" aria-label="No data">
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="${thickness}"/>
      </svg>`;
    }
    let acc = 0;
    const rings = segments.filter(s => s.value > 0).map(s => {
      const len = (s.value / total) * c;
      const el = `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${thickness}"
        stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-acc}" transform="rotate(-90 ${size / 2} ${size / 2})"/>`;
      acc += len;
      return el;
    }).join('');
    return `<svg viewBox="0 0 ${size} ${size}" class="am-donut" role="img" aria-label="Distribution">${rings}</svg>`;
  }

  function barChart(points) {
    if (!points.length) return emptyState('chart', 'No data yet', 'Violations will be charted here as rules fire.');
    const max = Math.max(...points.map(p => p.count), 1);
    return `<div class="am-bars" role="img" aria-label="Violations over time">
      ${points.map(p => `<div class="am-bar" title="${esc(p.label)}: ${p.count}">
        <div class="am-bar-fill" style="height:${Math.max(2, Math.round((p.count / max) * 100))}%"></div>
        <div class="am-bar-label">${esc(p.short || '')}</div>
      </div>`).join('')}
    </div>`;
  }

  function breakdown(title, rows, { color = 'var(--accent)' } = {}) {
    const max = rows.reduce((m, r) => Math.max(m, r.value), 0) || 1;
    return `<div class="am-breakdown">
      <div class="am-breakdown-title">${esc(title)}</div>
      ${rows.length ? rows.map(r => `
        <div class="am-breakdown-row">
          <span class="am-breakdown-label" title="${esc(r.label)}">${esc(r.label)}</span>
          <span class="am-breakdown-track"><span class="am-breakdown-fill" style="width:${Math.round((r.value / max) * 100)}%;background:${color}"></span></span>
          <span class="am-breakdown-value">${r.value}</span>
        </div>`).join('') : '<div class="field-hint">No data.</div>'}
    </div>`;
  }

  async function refreshAnalytics() {
    const el = document.getElementById('am-analytics');
    if (!el) return;
    el.innerHTML = skeleton(4);
    const days = ($('#am-an-days') || {}).value || '30';
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod/analytics?days=${encodeURIComponent(days)}`);
      const a = data.analytics || {};
      const totals = a.totals || {};
      const sevSegments = (a.bySeverity || []).map(s => ({
        label: s.label || s.key, value: s.value,
        color: (SEV_BY_KEY[s.key] && SEV_BY_KEY[s.key].colorHex) || '#5865F2',
      }));
      const sevTotal = sevSegments.reduce((sum, s) => sum + s.value, 0);
      el.innerHTML = `
        <div class="am-analytics-stats">
          ${statCardHTML('Threats Blocked', totals.blocked || 0, 'shieldAlert')}
          ${statCardHTML('Warnings', totals.warn || 0, 'alertTriangle')}
          ${statCardHTML('Timeouts', totals.timeout || 0, 'mute')}
          ${statCardHTML('Kicks', totals.kick || 0, 'userX')}
          ${statCardHTML('Bans', totals.ban || 0, 'ban')}
          ${statCardHTML('Deleted Messages', totals.delete || 0, 'trash')}
        </div>
        <div class="am-grid-2">
          <div class="am-chart-card">
            <div class="am-breakdown-title">Violations over time</div>
            ${barChart(a.overTime || [])}
          </div>
          <div class="am-chart-card">
            <div class="am-breakdown-title">Severity distribution</div>
            <div class="am-donut-wrap">
              ${donut(sevSegments)}
              <div class="am-donut-legend">
                ${sevSegments.length ? sevSegments.map(s => `<div class="am-legend-row"><span class="am-legend-dot" style="background:${s.color}"></span>${esc(s.label)} <strong>${s.value}</strong> <span class="am-legend-pct">${sevTotal ? Math.round((s.value / sevTotal) * 100) : 0}%</span></div>`).join('') : '<div class="field-hint">No data.</div>'}
              </div>
            </div>
          </div>
        </div>
        <div class="am-grid-3">
          ${breakdown('Top triggered rules', (a.topRules || []).map(r => ({ label: r.label || r.key, value: r.value })))}
          ${breakdown('Top affected channels', (a.byChannel || []).map(r => ({ label: r.label || r.channelId, value: r.value })), { color: 'var(--yellow, #FEE75C)' })}
          ${breakdown('Actions taken', (a.byAction || []).map(r => ({ label: actionLabel(r.key), value: r.value })), { color: 'var(--green, #57F287)' })}
        </div>`;
    } catch (err) {
      el.innerHTML = errorState(err.message || 'Unable to load analytics', 'data-retry="analytics"');
    }
  }

  document.addEventListener('change', (e) => {
    if (e.target.id === 'am-an-days') refreshAnalytics();
  });

  // ── Warnings + appeals ────────────────────────────────────────────────────

  async function refreshWarnings() {
    const el = document.getElementById('am-warnings-list');
    if (!el) return;
    el.innerHTML = skeleton(3);
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod/warnings`);
      const warnings = data.warnings || [];
      if (!warnings.length) {
        el.innerHTML = emptyState('check', 'No warnings', 'No warnings have been recorded in this server.');
        return;
      }
      el.innerHTML = `<table class="am-table">
        <thead><tr><th>User</th><th>Rule</th><th>Reason</th><th>Moderator</th><th>Time</th></tr></thead>
        <tbody>${warnings.slice(0, 100).map(w => `
          <tr>
            <td data-label="User">${w.userId ? `<code>${esc(w.userId)}</code>` : '—'}</td>
            <td data-label="Rule">${esc(w.ruleType || 'manual')}</td>
            <td data-label="Reason">${esc(w.reason || '—')}</td>
            <td data-label="Moderator">${w.moderatorId === 'automod' || !w.moderatorId ? 'Automod' : `<code>${esc(w.moderatorId)}</code>`}</td>
            <td data-label="Time">${esc(w.createdAt ? new Date(w.createdAt).toLocaleString() : '—')}</td>
          </tr>`).join('')}</tbody></table>`;
    } catch (err) {
      el.innerHTML = errorState(err.message || 'Unable to load warnings', 'data-retry="warnings"');
    }
  }

  async function refreshAppeals() {
    const el = document.getElementById('am-appeals-list');
    if (!el) return;
    el.innerHTML = skeleton(2);
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod/appeals`);
      const appeals = data.appeals || [];
      if (!appeals.length) {
        el.innerHTML = emptyState('envelope', 'No appeals', 'Appeals filed by members will show up here.');
        return;
      }
      el.innerHTML = appeals.map(a => {
        const when = a.createdAt ? new Date(a.createdAt).toLocaleString() : '—';
        const status = a.status === 'approved' ? '<span class="tag on">Approved</span>'
          : a.status === 'denied' ? '<span class="tag off">Denied</span>'
          : '<span class="tag prefix">Pending</span>';
        const decide = a.status === 'pending' ? `
          <div class="am-appeal-decide">
            <input type="text" class="am-appeal-note" data-id="${esc(a.id)}" placeholder="note (optional)" />
            <button class="btn btn-primary am-appeal-approve" data-id="${esc(a.id)}" type="button">Approve</button>
            <button class="btn btn-secondary am-appeal-deny" data-id="${esc(a.id)}" type="button">Deny</button>
          </div>`
          : `<div class="field-hint">Decided by ${esc(a.decidedBy || 'moderator')}${a.decisionNote ? ': ' + esc(a.decisionNote) : ''}${a.reversed ? ' · action reversed' : ''}</div>`;
        return `<div class="rr-menu-card">
          <div class="card-title"><span>${esc(a.action)} · ${esc(a.reason || '')}</span></div>
          <div class="rr-meta"><span><strong>User:</strong> <code>${esc(a.userId || 'unknown')}</code></span>
            <span><strong>Status:</strong> ${status}</span><span><strong>When:</strong> ${esc(when)}</span></div>
          ${decide}</div>`;
      }).join('');
    } catch (err) {
      el.innerHTML = errorState(err.message || 'Unable to load appeals', 'data-retry="appeals"');
    }
  }

  document.addEventListener('click', async (e) => {
    const approve = e.target.closest('.am-appeal-approve');
    const deny = e.target.closest('.am-appeal-deny');
    if (!approve && !deny) {
      if (e.target.closest('[data-retry="warnings"]')) refreshWarnings();
      if (e.target.closest('[data-retry="appeals"]')) refreshAppeals();
      return;
    }
    const btn = approve || deny;
    const id = btn.dataset.id;
    const note = ($(`.am-appeal-note[data-id="${id}"]`) || {}).value || '';
    btn.disabled = true;
    try {
      await api(`/api/guilds/${GUILD_ID}/automod/appeals/${id}`, {
        method: 'PATCH', body: JSON.stringify({ approved: Boolean(approve), note }),
      });
      window.toast(approve ? 'Appeal approved' : 'Appeal denied', 'success');
      refreshAppeals();
    } catch (err) {
      btn.disabled = false;
      window.toast(err.message || 'Failed to update the appeal', 'error');
    }
  });

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.am-refresh');
    if (!btn) return;
    if (btn.dataset.refresh === 'warnings') refreshWarnings();
    if (btn.dataset.refresh === 'incidents') refreshIncidents();
    if (btn.dataset.refresh === 'analytics') refreshAnalytics();
    if (btn.dataset.refresh === 'appeals') refreshAppeals();
  });

  // The master switch is the one control that persists immediately: it is a
  // security switch, and leaving AutoMod disabled (or enabled) because an
  // unrelated field is still dirty would be the wrong default. Everything else
  // batches into the single floating-bar save.
  let masterToggleBusy = false;
  document.addEventListener('change', async (e) => {
    if (e.target.id !== 'am-enabled') return;
    const input = e.target;
    const on = input.checked;
    const pill = document.getElementById('am-status-pill');
    const text = document.getElementById('am-status-text');
    if (pill) {
      pill.classList.toggle('am-pill-on', on);
      pill.classList.toggle('am-pill-off', !on);
    }
    if (text) text.textContent = on ? 'Enabled' : 'Disabled';

    if (masterToggleBusy) return;
    masterToggleBusy = true;
    input.disabled = true;
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/automod`, {
        method: 'PATCH', body: JSON.stringify({ enabled: on }),
      });
      if (data && data.automod) Object.assign(SETTINGS, data.automod);
      // The switch is now persisted, so re-baseline just this control — without
      // it the floating bar would keep claiming there are unsaved changes.
      if (window.saveBar && window.saveBar.syncControl) window.saveBar.syncControl(input);
      window.toast(on ? 'AutoMod enabled' : 'AutoMod disabled', 'success');
    } catch (err) {
      // Roll the switch back so the UI never claims a state the server rejected.
      input.checked = !on;
      if (pill) {
        pill.classList.toggle('am-pill-on', !on);
        pill.classList.toggle('am-pill-off', on);
      }
      if (text) text.textContent = !on ? 'Enabled' : 'Disabled';
      window.toast(err.message || 'Could not save the master switch', 'error');
    } finally {
      input.disabled = false;
      masterToggleBusy = false;
    }
  });

  // ── Save ──────────────────────────────────────────────────────────────────

  function collectSettings() {
    const exemptRoleIds = $$('.am-exempt-role').filter(cb => cb.checked).map(cb => cb.value);
    const exemptChannelIds = $$('.am-exempt-channel').filter(cb => cb.checked).map(cb => cb.value);
    const exemptUserIds = $$('.am-exempt-user').map(el => el.dataset.id).filter(Boolean);
    const dmMessages = {};
    $$('.am-dm-message').forEach(inp => {
      const key = inp.dataset.key;
      const val = (inp.value || '').trim();
      if (key && val) dmMessages[key] = val;
    });
    const warnLadder = $$('.am-ladder-row').map(row => ({
      count: parseInt(($('.am-ladder-count', row) || {}).value, 10) || 1,
      actions: [($('.am-ladder-action', row) || {}).value].filter(Boolean),
    })).filter(step => step.actions.length);
    const rules = collectRules(document.getElementById('am-rules-all') || document);
    const get = (id) => document.getElementById(id);
    return {
      enabled: get('am-enabled') ? get('am-enabled').checked : false,
      logChannelId: (get('am-log-channel') || {}).value || null,
      muteRoleId: (get('am-mute-role') || {}).value || null,
      exemptRoleIds,
      exemptChannelIds,
      exemptUserIds,
      rules,
      warnLadder: warnLadder.length ? warnLadder : [{ count: 3, actions: ['timeout'] }],
      warnThreshold: (warnLadder[0] && warnLadder[0].count) || 3,
      warnActions: (warnLadder[0] && warnLadder[0].actions) || ['timeout'],
      dmEnabled: get('am-dm-enabled') ? get('am-dm-enabled').checked : true,
      dmMessages,
      dmUser: get('am-dm-user') ? get('am-dm-user').checked : true,
      useAppeal: get('am-use-appeal') ? get('am-use-appeal').checked : false,
      appealChannelId: (get('am-appeal-channel') || {}).value || null,
      dryRun: get('am-dry-run') ? get('am-dry-run').checked : false,
      raidLockdown: get('am-raid-lockdown') ? get('am-raid-lockdown').checked : false,
      raidAlertChannelId: (get('am-raid-alert-channel') || {}).value || null,
      incidentRetentionDays: parseInt((get('am-retention') || {}).value, 10) || 0,
    };
  }

  async function saveAutomod() {
    const body = collectSettings();
    const data = await api(`/api/guilds/${GUILD_ID}/automod`, { method: 'PATCH', body: JSON.stringify(body) });
    if (data && data.automod) Object.assign(SETTINGS, data.automod);
  }

  window.saveBar.register(() => saveAutomod());

  // ── Boot ──────────────────────────────────────────────────────────────────

  bindRuleInteractions();
  renderExemptLists();
  syncRuleLists();
  window.saveBar.track(document.querySelector('.am-page') || document.body);

  const initial = new URL(window.location.href).searchParams.get('section');
  showSection(initial || 'overview', { push: false });

  // Overview stats are filled from the analytics endpoint (one request); the
  // heavier tables are fetched only when their section is opened.
  api(`/api/guilds/${GUILD_ID}/automod/analytics?days=30`)
    .then(data => {
      const t = (data.analytics && data.analytics.totals) || {};
      const stats = $$('#am-stats .am-stat-value');
      if (stats[1]) stats[1].textContent = String(t.blocked || 0);
      if (stats[2]) stats[2].textContent = String((t.warn || 0) + (t.timeout || 0) + (t.kick || 0) + (t.ban || 0));
      if (stats[3]) stats[3].textContent = String(t.total || 0);
    })
    .catch(() => { /* stats stay as "—" — the page still works */ });
})();