/* Automod page — rules, escalation, warnings ledger, appeals.
 * Mirrors the old SPA automod tab bindings.
 */

const GUILD_ID = window.guildData?.guildId;

const AUTOMOD_RULES = (window.__AUTOMOD_RULES || []);
const AUTOMOD_ACTIONS = (window.__AUTOMOD_ACTIONS || []);
const AUTOMOD_WARN_ACTIONS = AUTOMOD_ACTIONS.filter(a => ['warn', 'timeout', 'kick', 'ban'].includes(a.key));
const AUTOMOD_DM_KEYS = ['delete', 'warn', 'timeout', 'kick', 'ban', 'escalation'];

function automodRuleRowHTML(rule = {}) {
  const meta = AUTOMOD_RULES.find(r => r.key === rule.type) || AUTOMOD_RULES[0];
  const selected = Array.isArray(rule.actions) && rule.actions.length
    ? rule.actions
    : (rule.action ? [rule.action] : ['delete']);
  const actionChecks = AUTOMOD_ACTIONS.map(a =>
    `<label class="switch mini am-action-label"><input type="checkbox" class="am-action" value="${a.key}" ${selected.includes(a.key) ? 'checked' : ''}/><span class="switch-text">${window.svgIcon(a.iconName)} ${esc(a.label)}</span></label>`
  ).join('');
  let extra = '';
  if (meta.params.includes('words')) {
    extra = `<input type="text" class="am-words" value="${esc((rule.words || []).join(', '))}" placeholder="extra domains/terms (comma-separated)" />`;
  }
  if (meta.params.includes('threshold')) {
    extra += `<input type="number" class="am-threshold" value="${rule.threshold ?? ''}" placeholder="threshold" min="1" style="width:96px" />`;
  }
  if (meta.params.includes('seconds')) {
    extra += `<input type="number" class="am-seconds" value="${rule.seconds ?? ''}" placeholder="seconds" min="1" max="3600" style="width:96px" />`;
  }
  return `
    <div class="reaction-row am-rule-row" data-type="${esc(meta.key)}">
      <label class="switch mini"><input type="checkbox" class="am-enabled" ${rule.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
      <span class="am-rule-label">${window.svgIcon(meta.iconName)} ${esc(meta.label)}</span>
      <div class="am-actions-group">${actionChecks}</div>
      ${extra}
      <button class="reaction-remove am-remove" type="button">${window.svgIcon('x')}</button>
    </div>`;
}

// Render the exempt role/channel checkbox lists from the inlined guild data.
function renderAmExemptLists() {
  const s = window.__AUTOMOD_SETTINGS || {};
  const roleSet = new Set(s.exemptRoleIds || []);
  const chanSet = new Set(s.exemptChannelIds || []);
  const roles = (window.guildData.roles || []).map(r =>
    `<label class="switch mini"><input type="checkbox" class="am-exempt-role" value="${esc(r.id)}" ${roleSet.has(r.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(r.name)}</span></label>`
  ).join('') || '<div class="field-hint">No roles loaded.</div>';
  const channels = (window.guildData.channels || []).map(c =>
    `<label class="switch mini"><input type="checkbox" class="am-exempt-channel" value="${esc(c.id)}" ${chanSet.has(c.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(c.name)}</span></label>`
  ).join('') || '<div class="field-hint">No channels loaded.</div>';
  const rolesEl = document.getElementById('am-exempt-roles');
  const chanEl = document.getElementById('am-exempt-channels');
  if (rolesEl) rolesEl.innerHTML = roles;
  if (chanEl) chanEl.innerHTML = channels;
}

function collectAmRules() {
  const out = [];
  document.querySelectorAll('#am-rules-list .am-rule-row').forEach(row => {
    const type = row.dataset.type;
    if (!type) return;
    const actions = [];
    row.querySelectorAll('.am-action').forEach(cb => { if (cb.checked) actions.push(cb.value); });
    const rule = {
      type,
      enabled: row.querySelector('.am-enabled')?.checked !== false,
      actions: actions.length ? actions : ['delete'],
    };
    const words = row.querySelector('.am-words')?.value.trim();
    if (words) rule.words = words.split(',').map(w => w.trim().toLowerCase()).filter(Boolean);
    const threshold = parseInt(row.querySelector('.am-threshold')?.value, 10);
    if (Number.isFinite(threshold)) rule.threshold = threshold;
    const seconds = parseInt(row.querySelector('.am-seconds')?.value, 10);
    if (Number.isFinite(seconds)) rule.seconds = seconds;
    out.push(rule);
  });
  return out;
}

async function refreshAmWarnings() {
  const el = document.getElementById('am-warnings-list');
  if (!el) return;
  el.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/automod/warnings`);
    const warnings = data.warnings || [];
    if (warnings.length === 0) {
      el.innerHTML = '<div class="field-hint">No warnings recorded. ✨</div>';
      return;
    }
    el.innerHTML = warnings.slice(0, 50).map(w => {
      const when = new Date(w.createdAt).toLocaleString();
      const who = w.userId ? `<@${esc(w.userId)}>` : 'unknown';
      const by = w.moderatorId ? (w.moderatorId === 'automod' ? 'Automod' : `<@${esc(w.moderatorId)}>`) : 'Automod';
      return `<div class="rr-menu-card"><div class="card-title"><span>${esc(w.ruleType || 'manual')} · ${esc(w.reason || '')}</span></div><div class="rr-meta"><span><strong>User:</strong> ${who}</span><span><strong>By:</strong> ${by}</span><span><strong>When:</strong> ${esc(when)}</span></div></div>`;
    }).join('');
  } catch (err) {
    el.innerHTML = '<div class="field-hint">Failed to load warnings.</div>';
  }
}

async function refreshAmAppeals() {
  const el = document.getElementById('am-appeals-list');
  if (!el) return;
  el.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/automod/appeals`);
    const appeals = data.appeals || [];
    if (appeals.length === 0) {
      el.innerHTML = '<div class="field-hint">No appeals filed.</div>';
      return;
    }
    el.innerHTML = appeals.map(a => {
      const when = a.createdAt ? new Date(a.createdAt).toLocaleString() : '—';
      const who = a.userId ? `<@${esc(a.userId)}>` : 'unknown';
      const statusBadge = a.status === 'approved' ? '<span class="tag on">Approved</span>'
        : a.status === 'denied' ? '<span class="tag off">Denied</span>'
        : '<span class="tag prefix">Pending</span>';
      const decide = a.status === 'pending'
        ? `<div class="field-row" style="gap:8px;margin-top:8px">
             <input type="text" class="am-appeal-note" data-id="${a.id}" placeholder="note (optional)" style="flex:1;min-width:160px"/>
             <button class="btn btn-primary am-appeal-approve" data-id="${a.id}">Approve</button>
             <button class="btn btn-secondary am-appeal-deny" data-id="${a.id}">Deny</button>
           </div>`
        : `<div class="field-hint">Decided by ${esc(a.decidedBy || 'moderator')}${a.decisionNote ? ': ' + esc(a.decisionNote) : ''}${a.reversed ? ' · action reversed' : ''}</div>`;
      return `<div class="rr-menu-card"><div class="card-title"><span>${esc(a.action)} · ${esc(a.reason || '')}</span></div><div class="rr-meta"><span><strong>User:</strong> ${who}</span><span><strong>Status:</strong> ${statusBadge}</span><span><strong>When:</strong> ${esc(when)}</span></div>${decide}</div>`;
    }).join('');
    el.querySelectorAll('.am-appeal-approve').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const note = el.querySelector(`.am-appeal-note[data-id="${id}"]`)?.value || '';
        btn.disabled = true;
        await api(`/api/guilds/${GUILD_ID}/automod/appeals/${id}`, { method: 'PATCH', body: JSON.stringify({ approved: true, note }) });
        await refreshAmAppeals();
      });
    });
    el.querySelectorAll('.am-appeal-deny').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const note = el.querySelector(`.am-appeal-note[data-id="${id}"]`)?.value || '';
        btn.disabled = true;
        await api(`/api/guilds/${GUILD_ID}/automod/appeals/${id}`, { method: 'PATCH', body: JSON.stringify({ approved: false, note }) });
        await refreshAmAppeals();
      });
    });
  } catch (err) {
    el.innerHTML = '<div class="field-hint">Failed to load appeals.</div>';
  }
}

renderAmExemptLists();
bindReactionRemovals();

document.getElementById('am-add-rule')?.addEventListener('click', () => {
  const type = document.getElementById('am-add-type')?.value || 'invites';
  const list = document.getElementById('am-rules-list');
  if (!list) return;
  list.insertAdjacentHTML('beforeend', automodRuleRowHTML({ type, enabled: true, actions: ['delete'] }));
  bindReactionRemovals();
});

document.getElementById('am-refresh-warnings')?.addEventListener('click', (e) => { e.preventDefault(); refreshAmWarnings(); });
document.getElementById('am-refresh-appeals')?.addEventListener('click', (e) => { e.preventDefault(); refreshAmAppeals(); });

// Adding a rule is an edit — surface the floating save bar.
document.getElementById('am-add-rule')?.addEventListener('click', () => saveBar.markDirty());

async function saveSettings(kind) {
  if (kind !== 'automod') return;
  const exemptRoleIds = [];
  document.querySelectorAll('.am-exempt-role').forEach(cb => { if (cb.checked) exemptRoleIds.push(cb.value); });
  const exemptChannelIds = [];
  document.querySelectorAll('.am-exempt-channel').forEach(cb => { if (cb.checked) exemptChannelIds.push(cb.value); });
  const warnActions = [];
  document.querySelectorAll('.am-warn-action').forEach(cb => { if (cb.checked) warnActions.push(cb.value); });
  const dmMessages = {};
  document.querySelectorAll('.am-dm-message').forEach(inp => {
    const key = inp.dataset.key;
    const val = inp.value.trim();
    if (key && val) dmMessages[key] = val;
  });
  const body = {
    enabled: document.getElementById('am-enabled').checked,
    logChannelId: document.getElementById('am-log-channel').value || null,
    muteRoleId: document.getElementById('am-mute-role').value || null,
    exemptRoleIds,
    exemptChannelIds,
    rules: collectAmRules(),
    warnThreshold: parseInt(document.getElementById('am-warn-threshold').value, 10) || 3,
    warnActions: warnActions.length ? warnActions : ['timeout'],
    dmEnabled: document.getElementById('am-dm-enabled').checked,
    dmMessages,
    appealChannelId: document.getElementById('am-appeal-channel').value || null,
  };
  await api(`/api/guilds/${GUILD_ID}/automod`, { method: 'PATCH', body: JSON.stringify(body) });
}

saveBar.register(() => saveSettings('automod'));
saveBar.track(document.body);
refreshAmWarnings();
refreshAmAppeals();
