/**
 * Automod dashboard page — premium moderation control panel.
 *
 * The page is a single server-rendered page with an in-page section navigation
 * (Overview / Rules / Content Protection / Raid Protection / Warnings /
 * Punishments / Exemptions / Incidents / Analytics / Settings). That matches
 * how the rest of the PrimeBot dashboard works (one page per feature, sections
 * inside it) rather than inventing a new multi-page architecture.
 *
 * Design contract:
 *   • Every control is real markup in the initial HTML, so the page is usable
 *     (and readable) before any JS runs.
 *   • The client script (public/js/automod.js) only adds interactivity: section
 *     switching, the rule builder, the live rule tester, charts and saves.
 *   • Icons are SVG (svgIcon) — never emoji — so the UI stays crisp.
 *   • All values are escaped; no user content is interpolated unescaped.
 */

const { esc, channelOptions, roleOptions, svgIcon, jsonForScript } = require('./layout');
const constants = require('../constants');

const {
    AUTOMOD_RULES, AUTOMOD_ACTIONS, AUTOMOD_SEVERITIES, AUTOMOD_SECTIONS,
    AUTOMOD_PRESETS, AUTOMOD_RETENTION_OPTIONS,
} = constants;
const { ruleParamDefs, ruleParamValue, RULE_PARAMS } = require('../../utils/automodRules');

const SECTION_ORDER = [
    { key: 'overview',    label: 'Overview',           icon: 'activity' },
    { key: 'rules',       label: 'Rules',              icon: 'list' },
    { key: 'spam',        label: 'Anti-Spam',          icon: 'zap' },
    { key: 'content',     label: 'Content Protection', icon: 'shieldAlert' },
    { key: 'raid',        label: 'Raid Protection',    icon: 'users' },
    { key: 'warnings',    label: 'Warnings',           icon: 'alertTriangle' },
    { key: 'punishments', label: 'Punishments',        icon: 'ban' },
    { key: 'exemptions',  label: 'Exemptions',         icon: 'userCheck' },
    { key: 'incidents',   label: 'Incidents',          icon: 'inbox' },
    { key: 'analytics',   label: 'Analytics',          icon: 'chart' },
    { key: 'settings',    label: 'Settings',           icon: 'settings' },
];

const RULE_CATEGORY_TO_SECTION = {
    'Anti-Spam': 'spam',
    'Content Protection': 'content',
    'Raid Protection': 'raid',
};

const SEVERITY_BY_KEY = Object.fromEntries(AUTOMOD_SEVERITIES.map(s => [s.key, s]));

function severityBadge(sev) {
    const meta = SEVERITY_BY_KEY[sev] || SEVERITY_BY_KEY.medium;
    return `<span class="am-sev am-sev-${esc(meta.key)}">${svgIcon(meta.iconName)} ${esc(meta.label)}</span>`;
}

/**
 * The parameter inputs a rule type needs, built from the shared RULE_PARAMS
 * catalog (utils/automodRules.js) so this renderer and the client renderer stay
 * in lockstep. `cssClass` is what public/js/automod.js reads the value back from.
 */
function ruleParamInputs(rule, meta) {
    const defs = ruleParamDefs(meta.key);
    return defs.map(def => {
        if (def.type === 'switch') {
            const on = ruleParamValue(rule, def) === true;
            return `
          <label class="switch mini am-inline-switch">
            <input type="checkbox" class="${esc(def.cssClass)}" ${on ? 'checked' : ''}/>
            <span class="switch-text">${esc(def.label)}</span>
          </label>`;
        }
        if (def.type === 'number') {
            return `
          <label class="am-field am-field-num">
            <span class="am-field-label">${esc(def.label)}</span>
            <input type="number" class="${esc(def.cssClass)}" value="${esc(ruleParamValue(rule, def))}"
                   min="${def.min ?? ''}" max="${def.max ?? ''}" placeholder="${esc(def.placeholder || '')}" />
          </label>`;
        }
        return `
          <label class="am-field">
            <span class="am-field-label">${esc(def.label)}</span>
            <input type="text" class="${esc(def.cssClass)}" value="${esc(ruleParamValue(rule, def))}"
                   placeholder="${esc(def.placeholder || '')}" />
          </label>`;
    }).join('');
}

/** One rule card. Used for both the section lists and the Rules master list. */
function ruleCardHTML(rule, { index = 0 } = {}) {
    const meta = AUTOMOD_RULES.find(r => r.key === rule.type) || AUTOMOD_RULES[0];
    const selected = Array.isArray(rule.actions) && rule.actions.length
        ? rule.actions
        : (rule.action ? [rule.action] : ['delete']);
    const actionChecks = AUTOMOD_ACTIONS.map(a => `
        <label class="switch mini am-action-label" title="${esc(a.label)}">
          <input type="checkbox" class="am-action" value="${esc(a.key)}" ${selected.includes(a.key) ? 'checked' : ''}/>
          <span class="switch-text">${svgIcon(a.iconName)} ${esc(a.label)}</span>
        </label>`).join('');
    const sev = rule.severity || meta.severity || 'medium';
    const sevOpts = AUTOMOD_SEVERITIES.map(s =>
        `<option value="${esc(s.key)}" ${sev === s.key ? 'selected' : ''}>${esc(s.label)}</option>`).join('');
    return `
      <div class="am-rule-card" data-type="${esc(meta.key)}" data-category="${esc(meta.category || '')}">
        <div class="am-rule-head">
          <label class="switch am-rule-toggle" title="Enable or disable this rule">
            <input type="checkbox" class="am-enabled" ${rule.enabled !== false ? 'checked' : ''}/>
            <span class="slider"></span>
          </label>
          <span class="am-rule-icon">${svgIcon(meta.iconName)}</span>
          <div class="am-rule-title">
            <div class="am-rule-name">${esc(meta.label)}</div>
            <div class="am-rule-cat">${esc(meta.category || 'General')}</div>
          </div>
          <div class="am-rule-head-actions">
            ${severityBadge(sev)}
            <button type="button" class="am-icon-btn am-rule-test" title="Test this rule">${svgIcon('flask')}</button>
            <button type="button" class="am-icon-btn am-remove" title="Remove this rule">${svgIcon('x')}</button>
          </div>
        </div>
        <p class="am-rule-desc">${esc(meta.description || '')}</p>
        <div class="am-rule-params">
          <label class="am-field am-field-num">
            <span class="am-field-label">Severity</span>
            <select class="am-severity">${sevOpts}</select>
          </label>
          <label class="am-field am-field-num">
            <span class="am-field-label">Cooldown (s)</span>
            <input type="number" class="am-cooldown" value="${rule.cooldown || 0}" min="0" max="3600" title="Skip repeat actions for the same member for this many seconds" />
          </label>
          ${ruleParamInputs(rule, meta)}
        </div>
        <div class="am-rule-actions-label">Then apply</div>
        <div class="am-actions-group">${actionChecks}</div>
        <div class="am-rule-perrule">
          <button type="button" class="am-link-btn am-rule-exempt-toggle">${svgIcon('userCheck')} Per-rule exemptions</button>
          <div class="am-rule-exempt" hidden>
            <label class="am-field">
              <span class="am-field-label">Exempt roles (IDs, comma-separated)</span>
              <input type="text" class="am-exempt-roles" value="${esc((rule.exemptRoleIds || []).join(', '))}" placeholder="role ids" />
            </label>
            <label class="am-field">
              <span class="am-field-label">Exempt channels (IDs, comma-separated)</span>
              <input type="text" class="am-exempt-channels" value="${esc((rule.exemptChannelIds || []).join(', '))}" placeholder="channel ids" />
            </label>
          </div>
        </div>
      </div>`;
}

function ruleListHTML(rules) {
    if (!rules.length) return '';
    return rules.map((r, i) => ruleCardHTML(r, { index: i })).join('');
}

function emptyRulesHTML() {
    return `
      <div class="am-empty">
        <div class="am-empty-icon">${svgIcon('shield')}</div>
        <div class="am-empty-title">No rules yet</div>
        <div class="am-empty-text">Add a protection rule to start moderating this server automatically.</div>
      </div>`;
}

/** The rule picker (add-rule) grouped by section. */
function addRulePickerHTML() {
    const opts = AUTOMOD_SECTIONS.map(cat => {
        const rules = AUTOMOD_RULES.filter(r => r.category === cat);
        if (!rules.length) return '';
        return `<optgroup label="${esc(cat)}">${rules.map(r =>
            `<option value="${esc(r.key)}">${esc(r.label)}</option>`).join('')}</optgroup>`;
    }).join('');
    return `
      <div class="am-add-row">
        <select id="am-add-type" aria-label="Rule to add">${opts}</select>
        <button class="btn btn-secondary" id="am-add-rule" type="button">${svgIcon('plus')} Add rule</button>
      </div>`;
}

function presetsHTML(currentRules) {
    const have = new Set((currentRules || []).map(r => r.type));
    return AUTOMOD_PRESETS.map(p => `
      <div class="am-preset" data-preset="${esc(p.key)}">
        <div class="am-preset-head">
          <span class="am-preset-icon">${svgIcon(p.iconName)}</span>
          <span class="am-preset-name">${esc(p.label)}</span>
        </div>
        <p class="am-preset-desc">${esc(p.description)}</p>
        <div class="am-preset-meta">${p.rules.filter(r => r.enabled).length} rules · ${p.rules.length - p.rules.filter(r => r.enabled).length} optional</div>
        <button class="btn btn-secondary am-preset-apply" type="button" data-preset="${esc(p.key)}">${svgIcon('zap')} Apply preset</button>
      </div>`).join('');
}

/** Overview stat card. */
function statCard({ label, value, hint, icon, tone = '' }) {
    return `
      <div class="am-stat ${tone ? `am-stat-${tone}` : ''}">
        <div class="am-stat-icon">${svgIcon(icon)}</div>
        <div class="am-stat-body">
          <div class="am-stat-label">${esc(label)}</div>
          <div class="am-stat-value" data-stat="${esc(label)}">${esc(String(value))}</div>
          ${hint ? `<div class="am-stat-hint">${esc(hint)}</div>` : ''}
        </div>
      </div>`;
}

function statusPill(enabled, { on = 'Enabled', off = 'Disabled' } = {}) {
    return `<span class="am-pill ${enabled ? 'am-pill-on' : 'am-pill-off'}">${svgIcon(enabled ? 'check' : 'x')} ${esc(enabled ? on : off)}</span>`;
}

/**
 * Render the Automod page body.
 * @param {{ guild: object, user: object }} ctx
 */
function automodPageHTML({ guild, user }) {
    const s = guild._config.automod || {};
    const rules = Array.isArray(s.rules) ? s.rules : [];
    const enabledRules = rules.filter(r => r.enabled !== false).length;
    const bySection = (sectionKey) => rules.filter(r => RULE_CATEGORY_TO_SECTION[r.category || (AUTOMOD_RULES.find(x => x.key === r.type) || {}).category] === sectionKey);

    const dmKeys = ['delete', 'warn', 'timeout', 'kick', 'ban', 'escalation'];
    const dmMessages = s.dmMessages || {};
    const dmRows = dmKeys.map(k => {
        const a = AUTOMOD_ACTIONS.find(x => x.key === k);
        const label = a ? a.label : (k === 'escalation' ? 'Escalation' : k);
        const def = (constants.AUTOMOD_DEFAULT_DM_MESSAGES || {})[k] || '';
        return `
          <div class="am-dm-row">
            <label class="am-dm-label" for="am-dm-${esc(k)}">${esc(label)}</label>
            <input type="text" id="am-dm-${esc(k)}" class="am-dm-message" data-key="${esc(k)}"
                   value="${esc(dmMessages[k] || '')}" placeholder="${esc(def.slice(0, 90) || '(default)')}" />
          </div>`;
    }).join('');

    const warnActions = AUTOMOD_ACTIONS.filter(a => ['warn', 'timeout', 'kick', 'ban'].includes(a.key));
    const ladder = Array.isArray(s.warnLadder) && s.warnLadder.length
        ? s.warnLadder
        : [{ count: s.warnThreshold ?? 3, actions: s.warnActions || [s.warnAction || 'timeout'] }];
    const ladderRows = ladder.map(step => `
      <div class="am-ladder-row" data-ladder-row>
        <span class="am-ladder-at">At</span>
        <input type="number" class="am-ladder-count" value="${esc(step.count)}" min="1" max="100" aria-label="Warning count" />
        <span class="am-ladder-warn">warnings →</span>
        <select class="am-ladder-action" aria-label="Escalation action">
          ${warnActions.map(a => `<option value="${esc(a.key)}" ${(step.actions || []).includes(a.key) ? 'selected' : ''}>${esc(a.label)}</option>`).join('')}
        </select>
        <button type="button" class="am-icon-btn am-ladder-remove" title="Remove this step">${svgIcon('x')}</button>
      </div>`).join('');

    const retentionOpts = AUTOMOD_RETENTION_OPTIONS.map(o =>
        `<option value="${o.value}" ${Number(s.incidentRetentionDays ?? 30) === o.value ? 'selected' : ''}>${esc(o.label)}</option>`).join('');

    const panelHTML = `
    <div class="am-page">
      <!-- ── Hero / overview ─────────────────────────────────────────── -->
      <section class="am-hero card">
        <div class="am-hero-main">
          <div class="am-hero-icon">${svgIcon('shield')}</div>
          <div>
            <h2 class="am-hero-title">AutoMod</h2>
            <p class="am-hero-sub">Protect your server automatically with advanced, real-time moderation.</p>
            <div class="am-hero-pills">
              <span class="am-pill ${s.enabled ? 'am-pill-on' : 'am-pill-off'}" id="am-status-pill">
                ${svgIcon(s.enabled ? 'check' : 'x')} <span id="am-status-text">${s.enabled ? 'Enabled' : 'Disabled'}</span>
              </span>
              ${s.dryRun ? `<span class="am-pill am-pill-warn">${svgIcon('flask')} Dry run</span>` : ''}
            </div>
          </div>
        </div>
        <div class="am-hero-switch">
          <div class="am-hero-switch-label">
            <div class="sl-title">Master switch</div>
            <div class="sl-desc">When off, no messages are scanned at all.</div>
          </div>
          <label class="switch"><input type="checkbox" id="am-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
        </div>
      </section>

      <div class="am-stats" id="am-stats">
        ${statCard({ label: 'Rules Active', value: `${enabledRules} / ${rules.length}`, icon: 'list', hint: 'enabled protection rules' })}
        ${statCard({ label: 'Threats Blocked', value: '—', icon: 'shieldAlert', hint: 'last 30 days', tone: 'accent' })}
        ${statCard({ label: 'Actions Taken', value: '—', icon: 'zap', hint: 'warnings, timeouts, kicks, bans' })}
        ${statCard({ label: 'Incidents', value: '—', icon: 'inbox', hint: 'recorded violations' })}
      </div>

      <!-- ── Section navigation ──────────────────────────────────────── -->
      <nav class="am-sections" id="am-sections" aria-label="Automod sections">
        ${SECTION_ORDER.map((sec, i) => `
          <button type="button" class="am-section-btn ${i === 0 ? 'active' : ''}" data-section="${esc(sec.key)}">
            ${svgIcon(sec.icon)}<span>${esc(sec.label)}</span>
          </button>`).join('')}
      </nav>

      <!-- ── Overview ────────────────────────────────────────────────── -->
      <section class="am-section" data-section="overview">
        <div class="am-grid-2">
          <div class="card">
            <div class="card-title"><span><span class="icon">${svgIcon('zap')}</span> Quick setup</span></div>
            <p class="card-desc">Start from a professional preset. Applying a preset replaces your rule list — your log channel, exemptions and other settings are kept.</p>
            <div class="am-presets">${presetsHTML(rules)}</div>
          </div>
          <div class="card">
            <div class="card-title"><span><span class="icon">${svgIcon('flask')}</span> Test a rule</span></div>
            <p class="card-desc">Paste a sample message to see exactly which rules would match. Nothing is punished — this is a dry evaluation.</p>
            <label class="am-field">
              <span class="am-field-label">Sample message</span>
              <textarea id="am-test-content" class="am-test-input" rows="3" placeholder="Join my discord.gg/example">Join my discord.gg/example</textarea>
            </label>
            <button class="btn btn-secondary" id="am-run-test" type="button">${svgIcon('playCircle')} Test message</button>
            <div id="am-test-result" class="am-test-result"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> Active protections</span></div>
          <div id="am-overview-rules" class="am-overview-rules">
            ${rules.length ? rules.map(r => {
                const meta = AUTOMOD_RULES.find(x => x.key === r.type) || AUTOMOD_RULES[0];
                return `<div class="am-chip ${r.enabled !== false ? '' : 'am-chip-off'}">${svgIcon(meta.iconName)} ${esc(meta.label)}</div>`;
            }).join('') : '<div class="field-hint">No rules configured yet.</div>'}
          </div>
        </div>
      </section>

      <!-- ── Rules (master list) ─────────────────────────────────────── -->
      <section class="am-section" data-section="rules" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> All rules</span></div>
          <p class="card-desc">Every protection rule in one place. Toggle, tune and reorder them. Priority follows the order below.</p>
          <div class="am-rule-list" id="am-rules-all">
            ${rules.length ? ruleListHTML(rules) : emptyRulesHTML()}
          </div>
          ${addRulePickerHTML()}
        </div>
      </section>

      <!-- ── Anti-Spam ───────────────────────────────────────────────── -->
      <section class="am-section" data-section="spam" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('zap')}</span> Anti-Spam</span></div>
          <p class="card-desc">Catch flooding, repeated messages and mention abuse. These rules use in-memory counters, so they cost nothing in the database.</p>
          <div class="am-rule-list" id="am-rules-spam">
            ${bySection('spam').length ? ruleListHTML(bySection('spam')) : emptyRulesHTML()}
          </div>
        </div>
      </section>

      <!-- ── Content Protection ──────────────────────────────────────── -->
      <section class="am-section" data-section="content" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('shieldAlert')}</span> Content Protection</span></div>
          <p class="card-desc">Filter links, invites, blocked words, NSFW content and unsafe files. Link rules support allow/block domain lists.</p>
          <div class="am-rule-list" id="am-rules-content">
            ${bySection('content').length ? ruleListHTML(bySection('content')) : emptyRulesHTML()}
          </div>
        </div>
      </section>

      <!-- ── Raid Protection ─────────────────────────────────────────── -->
      <section class="am-section" data-section="raid" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('users')}</span> Raid Protection</span></div>
          <p class="card-desc">Detect suspicious join bursts and waves of similar new accounts. Combine several signals before punishing — these rules only act when their thresholds are genuinely met.</p>
          <div class="am-rule-list" id="am-rules-raid">
            ${bySection('raid').length ? ruleListHTML(bySection('raid')) : emptyRulesHTML()}
          </div>

          <div class="am-subhead">${svgIcon('megaphone')} Raid response</div>
          <div class="field">
            <label class="field-label" for="am-raid-alert-channel">Raid alert channel</label>
            <select id="am-raid-alert-channel" data-channel-select>${channelOptions(guild._channels, s.raidAlertChannelId)}</select>
            <div class="field-hint">High-priority alerts are posted here when raid protection trips. Falls back to the automod log channel.</div>
          </div>
          <div class="switch-row">
            <div class="switch-label">
              <div class="sl-title">Automatic lockdown</div>
              <div class="sl-desc">Raise the server verification level when a raid is detected. Conservative by design — the bot never mass-kicks or mass-bans on a weak signal.</div>
            </div>
            <label class="switch"><input type="checkbox" id="am-raid-lockdown" ${s.raidLockdown === true ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
        </div>
      </section>

      <!-- ── Warnings ────────────────────────────────────────────────── -->
      <section class="am-section" data-section="warnings" hidden>
        <div class="card">
          <div class="card-title">
            <span><span class="icon">${svgIcon('alertTriangle')}</span> Warning ladder</span>
            <button class="btn btn-secondary am-refresh" data-refresh="warnings" type="button">${svgIcon('refresh')} Refresh</button>
          </div>
          <p class="card-desc">Escalate automatically as warnings add up. Each step fires when a member's total warnings reach its count; warnings clear after an escalation.</p>
          <div class="am-ladder" id="am-ladder">${ladderRows}</div>
          <button class="btn btn-secondary" id="am-ladder-add" type="button">${svgIcon('plus')} Add escalation step</button>
        </div>

        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('inbox')}</span> Recent warnings</span></div>
          <div id="am-warnings-list" class="am-table-wrap"><div class="am-loading">Loading warnings…</div></div>
        </div>
      </section>

      <!-- ── Punishments ─────────────────────────────────────────────── -->
      <section class="am-section" data-section="punishments" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('ban')}</span> Punishments &amp; notifications</span></div>
          <p class="card-desc">Actions are only performed when the bot actually has the permission and sits above the target in the role hierarchy. Anything it can't do is skipped and logged, never crashing the run.</p>

          <div class="field">
            <label class="field-label" for="am-mute-role">Mute role (optional)</label>
            <select id="am-mute-role" data-role-select data-placeholder="— None (use native timeouts) —">${roleOptions(guild._roles, s.muteRoleId)}</select>
            <div class="field-hint">Used for indefinite mutes when a native timeout isn't suitable.</div>
          </div>

          <div class="switch-row">
            <div class="switch-label">
              <div class="sl-title">DM punished members</div>
              <div class="sl-desc">Send a direct message explaining the action and reason.</div>
            </div>
            <label class="switch"><input type="checkbox" id="am-dm-enabled" ${s.dmEnabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>

          <div class="switch-row">
            <div class="switch-label">
              <div class="sl-title">Rich ban DM</div>
              <div class="sl-desc">Send a detailed ban DM with all available fields.</div>
            </div>
            <label class="switch"><input type="checkbox" id="am-dm-user" ${s.dmUser !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>

          <div class="switch-row">
            <div class="switch-label">
              <div class="sl-title">Ban appeal button</div>
              <div class="sl-desc">Attach an "Appeal ban" button so banned members can file an appeal.</div>
            </div>
            <label class="switch"><input type="checkbox" id="am-use-appeal" ${s.useAppeal === true ? 'checked' : ''}/><span class="slider"></span></label>
          </div>

          <div class="field">
            <label class="field-label" for="am-appeal-channel">Appeal channel (optional)</label>
            <select id="am-appeal-channel" data-channel-select>${channelOptions(guild._channels, s.appealChannelId)}</select>
            <div class="field-hint">Where filed appeals are posted for moderators. Falls back to the automod log channel.</div>
          </div>

          <div class="am-subhead">${svgIcon('envelope')} Custom DM messages</div>
          <div class="field-hint">Override the default text per action. Placeholders: <code>{server}</code>, <code>{reason}</code>, <code>{action}</code>, <code>{threshold}</code>. Leave blank for the default.</div>
          <div class="am-dm-list" id="am-dm-messages">${dmRows}</div>
        </div>
      </section>

      <!-- ── Exemptions ──────────────────────────────────────────────── -->
      <section class="am-section" data-section="exemptions" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('userCheck')}</span> Exemptions &amp; whitelist</span></div>
          <p class="card-desc">Administrators are always exempt. Everything else is up to you — per-rule exemptions are available on each rule card.</p>

          <div class="field">
            <label class="field-label">Exempt roles</label>
            <div class="field-hint">Members with these roles are never actioned by any rule.</div>
            <div class="rr-list" id="am-exempt-roles"></div>
          </div>

          <div class="field">
            <label class="field-label">Exempt channels</label>
            <div class="field-hint">Messages in these channels are never scanned.</div>
            <div class="rr-list" id="am-exempt-channels"></div>
          </div>

          <div class="field">
            <label class="field-label">Exempt members</label>
            <div class="field-hint">Specific users (by ID) who bypass every rule.</div>
            <div class="rr-list" id="am-exempt-users"></div>
          </div>
        </div>
      </section>

      <!-- ── Incidents ───────────────────────────────────────────────── -->
      <section class="am-section" data-section="incidents" hidden>
        <div class="card">
          <div class="card-title">
            <span><span class="icon">${svgIcon('inbox')}</span> Incident center</span>
            <button class="btn btn-secondary am-refresh" data-refresh="incidents" type="button">${svgIcon('refresh')} Refresh</button>
          </div>
          <p class="card-desc">Every enforcement, newest first. Filter, search and page through the history.</p>

          <div class="am-filters">
            <input type="search" id="am-inc-search" class="am-filter-search" placeholder="Search incidents…" aria-label="Search incidents" />
            <select id="am-inc-rule" aria-label="Filter by rule">
              <option value="">All rules</option>
              ${AUTOMOD_RULES.map(r => `<option value="${esc(r.key)}">${esc(r.label)}</option>`).join('')}
            </select>
            <select id="am-inc-severity" aria-label="Filter by severity">
              <option value="">All severities</option>
              ${AUTOMOD_SEVERITIES.map(s2 => `<option value="${esc(s2.key)}">${esc(s2.label)}</option>`).join('')}
            </select>
            <select id="am-inc-action" aria-label="Filter by action">
              <option value="">All actions</option>
              ${AUTOMOD_ACTIONS.map(a => `<option value="${esc(a.key)}">${esc(a.label)}</option>`).join('')}
            </select>
            <select id="am-inc-days" aria-label="Filter by date">
              <option value="">Any time</option>
              <option value="1">Last 24 hours</option>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
          </div>

          <div id="am-incidents-list" class="am-table-wrap"><div class="am-loading">Loading incidents…</div></div>
          <div class="am-pager" id="am-incidents-pager"></div>
        </div>
      </section>

      <!-- ── Analytics ───────────────────────────────────────────────── -->
      <section class="am-section" data-section="analytics" hidden>
        <div class="card">
          <div class="card-title">
            <span><span class="icon">${svgIcon('chart')}</span> Analytics</span>
            <div class="am-title-actions">
              <select id="am-an-days" aria-label="Analytics window">
                <option value="7">Last 7 days</option>
                <option value="30" selected>Last 30 days</option>
                <option value="90">Last 90 days</option>
              </select>
              <button class="btn btn-secondary am-refresh" data-refresh="analytics" type="button">${svgIcon('refresh')} Refresh</button>
            </div>
          </div>
          <div id="am-analytics" class="am-analytics"><div class="am-loading">Loading analytics…</div></div>
        </div>
      </section>

      <!-- ── Settings ────────────────────────────────────────────────── -->
      <section class="am-section" data-section="settings" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('settings')}</span> Automod settings</span></div>

          <div class="field">
            <label class="field-label" for="am-log-channel">Automod log channel</label>
            <select id="am-log-channel" data-channel-select>${channelOptions(guild._channels, s.logChannelId)}</select>
            <div class="field-hint">Where incident embeds are posted as the bot.</div>
          </div>

          <div class="switch-row">
            <div class="switch-label">
              <div class="sl-title">Dry run (detection only)</div>
              <div class="sl-desc">Detect and log violations but take no action. Use this to tune your rules before enforcing them.</div>
            </div>
            <label class="switch"><input type="checkbox" id="am-dry-run" ${s.dryRun === true ? 'checked' : ''}/><span class="slider"></span></label>
          </div>

          <div class="field">
            <label class="field-label" for="am-retention">Incident retention</label>
            <select id="am-retention">${retentionOpts}</select>
            <div class="field-hint">How long incidents are kept before automatic cleanup. Nothing is ever deleted unless you choose a window here.</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span><span class="icon">${svgIcon('envelope')}</span> Appeals</span>
            <button class="btn btn-secondary am-refresh" data-refresh="appeals" type="button">${svgIcon('refresh')} Refresh</button>
          </div>
          <p class="card-desc">Appeals filed by members. Approving one reverses the underlying action automatically.</p>
          <div id="am-appeals-list" class="am-table-wrap"><div class="am-loading">Loading appeals…</div></div>
        </div>
      </section>
    </div>`;

    // Embed catalogs + settings so the client can render rows, run the tester and
    // build charts without extra round-trips.
    const body = `
    ${require('./guild').guildHeaderHTML(guild)}
    ${require('./guild').tabNavHTML(guild.id, 'automod')}
    ${panelHTML}
    ${require('./guild').guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: { _automodSettings: s } })}
    <script>window.__AUTOMOD_RULES=${jsonForScript(AUTOMOD_RULES)};
window.__AUTOMOD_ACTIONS=${jsonForScript(AUTOMOD_ACTIONS)};
window.__AUTOMOD_SEVERITIES=${jsonForScript(AUTOMOD_SEVERITIES)};
window.__AUTOMOD_PRESETS=${jsonForScript(AUTOMOD_PRESETS)};
window.__AUTOMOD_PARAMS=${jsonForScript(RULE_PARAMS)};
window.__AUTOMOD_SETTINGS=${jsonForScript(s)};</script>`;

    return { body, scripts: ['/js/guild-common.js', '/js/automod.js'], title: `PrimeBot · ${guild.name} · Automod` };
}

module.exports = { automodPageHTML, SECTION_ORDER, ruleCardHTML, severityBadge };
