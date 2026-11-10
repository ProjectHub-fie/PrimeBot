/**
 * Anti-Nuke dashboard page — premium security console.
 *
 * Server-rendered, like every other PrimeBot settings page. The page is RELEASED
 * (no `upcoming` overlay): the `upcoming: true` flag was removed from
 * render/guild.js TABS and the write endpoints no longer carry `requireUpcoming`.
 *
 * Two states:
 *   • SETUP NOT COMPLETE → the setup chooser (Automatic / Manual) plus a live
 *     progress panel that resumes an interrupted setup.
 *   • SETUP COMPLETE → the protection console: status, per-module detection
 *     configuration, trusted users/roles, response configuration, alert channel,
 *     lockdown controls, dry-run and the security-activity ledger.
 *
 * All controls are real markup (usable before JS runs); the client script
 * (public/js/antinuke.js) adds interactivity and talks to the API. Icons are
 * SVG, never emoji. Everything the client reads is injected with
 * `jsonForScript` (XSS-safe) or in the `#guild-data` blob.
 */

const { esc, channelOptions, roleOptions, render, svgIcon, jsonForScript } = require('./layout');
const constants = require('../constants');

const {
    ANTINUKE_ACTIONS, ANTINUKE_RESPONSES, ANTINUKE_MODULES,
    ANTINUKE_DANGEROUS_PERMISSIONS, ANTINUKE_AUTO_STEPS, ANTINUKE_MANUAL_SECTIONS,
} = constants;

// ── Small building blocks ───────────────────────────────────────────────────

function severityBadge(sev) {
    const s = String(sev || 'medium');
    return `<span class="an-sev an-sev-${esc(s)}">${esc(s.charAt(0).toUpperCase() + s.slice(1))}</span>`;
}

/** Human label for a setup status (shown beside the progress bar). */
function progressStatusLabel(status) {
    switch (status) {
        case 'completed': return 'Completed';
        case 'in_progress': return 'In progress';
        case 'failed': return 'Failed — needs attention';
        default: return 'Not started';
    }
}

/**
 * The setup progress card — ONE markup for both the automatic chooser and the
 * manual wizard, so a single client function (`renderProgress`) drives both and
 * they can never drift.
 *
 * It is always rendered (even at 0% / not started) so the client always has real
 * elements to update; the earlier version omitted the card until a setup was in
 * progress, which is why the automatic progress bar never appeared.
 */
function progressCardHTML({ title, iconName = 'activity', progress, status = 'not_started', actions = '' }) {
    const p = progress || { percent: 0, completed: 0, total: 0, failed: 0, skipped: 0, steps: [] };
    const pct = Math.max(0, Math.min(100, Number(p.percent) || 0));
    return `
      <section class="card an-progress-card" id="an-progress-card">
        <div class="card-title an-progress-head">
          <span><span class="icon">${svgIcon(iconName)}</span> ${esc(title)}</span>
          <span class="an-progress-status an-progress-status-${esc(status)}" id="an-progress-status">${esc(progressStatusLabel(status))}</span>
        </div>
        <div class="an-progress-bar" id="an-progress-track" role="progressbar"
             aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}">
          <div class="an-progress-fill" id="an-progress-fill" style="width:${pct}%"></div>
        </div>
        <div class="an-progress-meta" id="an-progress-meta"><strong>${pct}%</strong> · ${p.completed || 0} of ${p.total || 0} required steps completed</div>
        <div class="an-progress-flags" id="an-progress-flags">${progressFlagsHTML(p)}</div>
        <ul class="an-step-list" id="an-step-list">${stepListHTML(p.steps)}</ul>
        ${actions}
      </section>`;
}

/** Failed / skipped / remaining chips, rendered only when they are non-zero. */
function progressFlagsHTML(p) {
    const chips = [];
    if (p.failed > 0) chips.push(`<span class="an-flag an-flag-failed">${svgIcon('x')} ${p.failed} failed</span>`);
    if (p.skipped > 0) chips.push(`<span class="an-flag an-flag-skipped">${svgIcon('minus')} ${p.skipped} skipped</span>`);
    if (p.remaining > 0) chips.push(`<span class="an-flag">${svgIcon('clock')} ${p.remaining} remaining</span>`);
    if (p.running > 0) chips.push(`<span class="an-flag an-flag-running"><span class="an-step-spin"></span> running</span>`);
    return chips.join('');
}

/** One watched-action row inside a module card. */
function actionRowHTML(action, watch) {
    return `
      <div class="an-action-row" data-action="${esc(action.key)}">
        <div class="an-action-main">
          <label class="switch">
            <input type="checkbox" class="an-watch-enabled" ${watch.enabled !== false ? 'checked' : ''}/>
            <span class="slider"></span>
          </label>
          <span class="an-action-icon">${svgIcon(action.iconName)}</span>
          <div class="an-action-title">
            <div class="an-action-name">${esc(action.label)}</div>
            <div class="an-action-desc">${esc(action.description)}</div>
          </div>
          ${severityBadge(action.severity)}
        </div>
        <div class="an-action-params">
          <label class="am-field am-field-num">
            <span class="am-field-label">Max actions</span>
            <input type="number" class="an-watch-threshold" value="${esc(watch.threshold)}" min="1" max="100" />
          </label>
          <label class="am-field am-field-num">
            <span class="am-field-label">Within (seconds)</span>
            <input type="number" class="an-watch-seconds" value="${esc(watch.seconds)}" min="1" max="3600" />
          </label>
        </div>
      </div>`;
}

/** One protection-module card with its watched actions. */
function moduleCardHTML(module, watched) {
    const actions = ANTINUKE_ACTIONS.filter(a => a.module === module.key);
    const rows = actions.map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('');
    return `
      <section class="card an-module" data-module="${esc(module.key)}">
        <div class="card-title"><span><span class="icon">${svgIcon(module.iconName)}</span> ${esc(module.label)}</span></div>
        <p class="card-desc">${esc(module.description)}</p>
        <div class="an-action-list">${rows}</div>
      </section>`;
}

// ── Setup chooser ───────────────────────────────────────────────────────────

function setupChooserHTML(setup) {
    const progress = setup.progress || { percent: 0, completed: 0, total: 0, steps: [] };
    const resume = setup.status === 'in_progress' || setup.status === 'failed';
    // Always rendered (even at 0% / not started) so the client always has a real
    // element to update — see progressCardHTML.
    const progressPanel = progressCardHTML({
        title: 'Setup progress',
        progress,
        status: setup.status || 'not_started',
        actions: `
        <div class="an-setup-actions">
          <button class="btn btn-primary" id="an-resume-setup" ${resume ? '' : 'hidden'}>${svgIcon('playCircle')} Resume setup</button>
          <button class="btn" id="an-reset-setup" ${resume ? '' : 'hidden'}>Reset progress</button>
        </div>`,
    });

    return `
    <div class="an-page an-setup-page">
      <section class="card am-hero">
        <div class="am-hero-main">
          <div class="am-hero-icon">${svgIcon('shieldAlert')}</div>
          <div>
            <h2 class="am-hero-title">PrimeBot Anti-Nuke</h2>
            <p class="am-hero-sub">Protect your server against destructive actions, unauthorized changes and attacks.</p>
            <div class="am-hero-pills">
              <span class="am-pill ${setup.enabled ? 'am-pill-on' : 'am-pill-off'}">${svgIcon(setup.enabled ? 'check' : 'x')} ${setup.enabled ? 'Protection active' : 'Not configured'}</span>
              <span class="am-pill am-pill-on">${svgIcon('zap')} Live by default</span>
            </div>
          </div>
        </div>
      </section>

      ${progressPanel}

      <div class="an-setup-grid">
        <section class="card an-setup-card">
          <div class="an-setup-icon">${svgIcon('zap')}</div>
          <div class="card-title">Automatic Setup</div>
          <p class="card-desc">Recommended security configuration, applied for you. The bot inspects the server, checks its permissions and prepares safe detection thresholds. Dry-run stays on.</p>
          <button class="btn btn-primary an-setup-start" data-method="automatic">${svgIcon('zap')} Start Setup</button>
        </section>

        <section class="card an-setup-card">
          <div class="an-setup-icon">${svgIcon('settings')}</div>
          <div class="card-title">Manual Setup</div>
          <p class="card-desc">Configure each protection module yourself. Partial progress is saved, so you can leave and resume at any time.</p>
          <button class="btn an-setup-start" data-method="manual">${svgIcon('sliders')} Configure Manually</button>
        </section>
      </div>
    </div>`;
}

function stepListHTML(steps) {
    return (steps || []).map(step => {
        const icon = stepIcon(step.status);
        const cls = `an-step an-step-${esc(step.status)}`;
        const optional = step.required ? '' : ' <span class="an-step-opt">optional</span>';
        return `<li class="${cls}" data-step="${esc(step.key)}">
            <span class="an-step-icon">${icon}</span>
            <span class="an-step-label">${esc(step.label)}${optional}</span>
            <span class="an-step-status">${esc(step.status)}</span>
          </li>`;
    }).join('');
}

function stepIcon(status) {
    switch (status) {
        case 'completed': return svgIcon('check');
        case 'running': return `<span class="an-step-spin"></span>`;
        case 'failed': return svgIcon('x');
        case 'skipped': return svgIcon('minus');
        default: return svgIcon('clock');
    }
}

// ── Manual setup wizard ─────────────────────────────────────────────────────

function manualWizardHTML(guild, settings) {
    const channels = guild._channels || [];
    const roles = guild._roles || [];
    const trustedUsers = Array.isArray(settings.trustedUserIds) ? settings.trustedUserIds : [];
    const trustedRoles = Array.isArray(settings.trustedRoleIds) ? settings.trustedRoleIds : [];
    const sections = ANTINUKE_MANUAL_SECTIONS.map(sec => `
        <div class="an-wizard-section" data-section="${esc(sec.key)}" hidden>
          <h3 class="an-wizard-title">${esc(sec.label)}</h3>
          <p class="card-desc">${esc(sec.description)}</p>
          ${wizardSectionBody(sec.key, { guild, settings, channels, roles, trustedUsers, trustedRoles })}
        </div>`).join('');

    // Same progress card as the automatic chooser, so ONE client function
    // (renderProgress) drives both and the two views can never drift.
    const initialSteps = ANTINUKE_MANUAL_SECTIONS.map(s => ({ key: s.key, label: s.label, required: s.required, status: 'pending' }));
    const requiredTotal = ANTINUKE_MANUAL_SECTIONS.filter(s => s.required).length;
    const progressCard = progressCardHTML({
        title: 'Manual Security Setup',
        iconName: 'sliders',
        status: 'in_progress',
        progress: { percent: 0, completed: 0, total: requiredTotal, failed: 0, skipped: 0, remaining: requiredTotal, running: 0, steps: initialSteps },
    });

    return `
    <div class="an-page an-wizard-page">
      ${progressCard}

      <section class="card">
        ${sections}
        <div class="an-wizard-nav">
          <button class="btn" id="an-wizard-prev">${svgIcon('arrowLeft')} Previous</button>
          <button class="btn btn-primary" id="an-wizard-next">Continue ${svgIcon('arrowRight')}</button>
          <button class="btn btn-primary" id="an-wizard-save" hidden>${svgIcon('save')} Save configuration</button>
        </div>
      </section>
    </div>`;
}

function wizardSectionBody(key, ctx) {
    const { settings, channels, roles, trustedUsers, trustedRoles } = ctx;
    switch (key) {
        case 'general':
            return `
              <div class="switch-row">
                <div class="switch-label"><div class="sl-title">Enable Anti-Nuke</div><div class="sl-desc">The server owner is never treated as a threat.</div></div>
                <label class="switch"><input type="checkbox" id="an-enabled" ${settings.enabled ? 'checked' : ''}/><span class="slider"></span></label>
              </div>
              <div class="card an-wizard-check">
                <div class="card-title"><span><span class="icon">${svgIcon('shieldCheck')}</span> Bot readiness check</span>
                  <button class="btn btn-mini" id="an-wizard-check-run">${svgIcon('refresh')} Re-check</button></div>
                <div id="an-wizard-check-result" class="an-wizard-check-result"><div class="an-empty">Running check…</div></div>
              </div>`;
        case 'channel':
            return `
              <div class="field">
                <label class="field-label" for="an-alert-channel">Alert channel</label>
                <div class="an-create-row">
                  <select id="an-alert-channel" data-channel-select>${channelOptions(channels, settings.alertChannelId)}</select>
                  <button class="btn btn-mini an-create-auto" data-create="alert_channel">${svgIcon('sparkles')} Make automatically</button>
                </div>
                <div class="field-hint">Where security alerts are posted. PrimeBot needs View Channel + Send Messages there. “Make automatically” creates <strong>#primebot-antinuke-log</strong>.</div>
              </div>`;
        case 'trustedUsers':
            return `
              <div class="field">
                <label class="field-label">Trusted users</label>
                <div class="an-trusted-input"><input type="text" id="an-trusted-user-input" placeholder="User ID (15-22 digits)"/><button class="btn" id="an-add-trusted-user">${svgIcon('userPlus')} Add</button></div>
                <div class="rr-list" id="an-trusted-users"></div>
                <div class="field-hint">Anyone listed here bypasses Anti-Nuke detection. The server owner and PrimeBot always do. Administrators are NOT trusted automatically.</div>
              </div>`;
        case 'trustedRoles':
            return `
              <div class="field">
                <label class="field-label">Trusted roles</label>
                <div class="rr-list an-trusted-roles" id="an-trusted-roles"></div>
                <div class="field-hint">Members holding one of these roles are exempt from Anti-Nuke detection.</div>
              </div>`;
        case 'thresholds':
            return `
              <p class="card-desc">How many actions within a window count as an attack. Edit a value in its protection section; this table is a summary.</p>
              <table class="an-review-table an-threshold-table"><tbody>
                ${ANTINUKE_ACTIONS.map(a => {
                    const w = (settings.watched || {})[a.key] || { threshold: a.threshold, seconds: a.seconds, enabled: true };
                    return `<tr><th>${svgIcon(a.iconName)} ${esc(a.label)}</th><td>${w.enabled !== false ? `${esc(w.threshold)} / ${esc(w.seconds)}s` : 'disabled'}</td></tr>`;
                }).join('')}
              </tbody></table>`;
        case 'responses':
            return `
              <p class="card-desc">What happens when a threshold trips. Every active response is checked by default (except "Log only"). Punishment responses (ban/kick) stay OFF until you enable them for the specific rule they should punish.</p>
              <div class="an-responses">${ANTINUKE_RESPONSES.map(r => `
                <label class="an-response">
                  <input type="checkbox" class="an-response-cb" value="${esc(r.key)}" ${(settings.responses || []).includes(r.key) ? 'checked' : ''}/>
                  <span class="an-response-body">
                    <span class="an-response-name">${svgIcon(r.iconName)} ${esc(r.label)}${r.dangerous ? ' <span class="an-danger-tag">containment</span>' : ''}</span>
                    <span class="an-response-desc">${esc(r.description)}</span>
                  </span>
                </label>`).join('')}</div>
              <details class="an-rule-responses">
                <summary>${svgIcon('sliders')} Per-rule response overrides</summary>
                <p class="field-hint">Give a single rule its own response set. Leave a rule unset to use the global responses above. Enabling <strong>ban</strong>/<strong>kick</strong> here punishes the confirmed attacker for that rule only.</p>
                ${ANTINUKE_ACTIONS.map(a => {
                    const overrides = ((settings.actionResponses || {})[a.key]) || [];
                    return `<div class="an-rule-response">
                      <span class="an-rule-response-name">${svgIcon(a.iconName)} ${esc(a.label)}</span>
                      <span class="an-rule-response-cbs">${ANTINUKE_RESPONSES.map(r => `
                        <label class="an-rule-response-cb"><input type="checkbox" class="an-action-response-cb" data-action="${esc(a.key)}" value="${esc(r.key)}" ${overrides.includes(r.key) ? 'checked' : ''}/> ${esc(r.label)}</label>`).join('')}</span>
                    </div>`;
                }).join('')}
              </details>
              <div class="field">
                <label class="field-label" for="an-quarantine-role">Quarantine role</label>
                <div class="an-create-row">
                  <select id="an-quarantine-role" data-role-select data-placeholder="— None (strip dangerous roles only) —"><option value="">${esc(settings.quarantineRoleId ? settings.quarantineRoleId : '— None (strip dangerous roles only) —')}</option></select>
                  <button class="btn btn-mini an-create-auto" data-create="isolation_role">${svgIcon('sparkles')} Make automatically</button>
                </div>
                <div class="field-hint">Applied to the confirmed attacker by the Quarantine response. Unset falls back to stripping dangerous roles only. “Make automatically” creates <strong>isolated</strong> just below the bot's role.</div>
              </div>
              <div class="field">
                <label class="field-label">Dangerous permissions to strip</label>
                <div class="an-perm-list">${ANTINUKE_DANGEROUS_PERMISSIONS.map(p => `
                  <label class="an-perm"><input type="checkbox" class="an-danger-perm" value="${esc(p.key)}" ${(settings.dangerousPermissions || []).includes(p.key) ? 'checked' : ''}/> ${esc(p.label)}</label>`).join('')}</div>
              </div>`;
        case 'safety':
            return `
              <div class="switch-row">
                <div class="switch-label"><div class="sl-title">Dry run</div><div class="sl-desc">Detect and alert but never contain. Off by default — leave off to let protection enforce.</div></div>
                <label class="switch"><input type="checkbox" id="an-dry-run" ${settings.dryRun !== false ? 'checked' : ''}/><span class="slider"></span></label>
              </div>
              <div class="switch-row">
                <div class="switch-label"><div class="sl-title">Lockdown allowed</div><div class="sl-desc">Permit a lockdown response (raises verification level, pauses invites).</div></div>
                <label class="switch"><input type="checkbox" id="an-lockdown-enabled" ${settings.lockdown && settings.lockdown.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
              </div>
              <div class="field">
                <label class="field-label" for="an-response-cooldown">Response cooldown (seconds)</label>
                <input type="number" id="an-response-cooldown" min="0" max="3600" value="${esc(settings.responseCooldownSeconds != null ? settings.responseCooldownSeconds : 30)}"/>
                <div class="field-hint">Minimum gap between responses for the same guild + action, so a sustained attack does not flood alerts.</div>
              </div>`;
        case 'review':
            return `<div class="an-review" id="an-review"></div>`;
        default: {
            // Module sections. The catalog key `channels` (Channel Protection)
            // maps to the `channel` protection module.
            const modKey = key === 'channels' ? 'channel' : key;
            const mod = ANTINUKE_MODULES.find(m => m.key === modKey);
            if (!mod) return '';
            const watched = settings.watched || {};
            return `<div class="an-action-list">${ANTINUKE_ACTIONS.filter(a => a.module === modKey)
                .map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('')}</div>`;
        }
    }
}

// ── Premium section-based protection console ────────────────────────────────
//
// Anti-Nuke now matches the AutoMod dashboard's premium design language: one
// hero, one sticky horizontal section rail, and one <section class="an-section">
// per area. The client (public/js/antinuke.js) switches sections without a page
// reload, keeps the section in the URL (?section=), and lazy-loads data.

const SECTION_ORDER = [
    { key: 'overview',    label: 'Overview',        icon: 'activity' },
    { key: 'protection',  label: 'Protection',      icon: 'shield' },
    { key: 'antiraid',    label: 'Anti-Raid',       icon: 'users' },
    { key: 'permission',  label: 'Permission Guard', icon: 'key' },
    { key: 'channel',     label: 'Channel Guard',   icon: 'hash' },
    { key: 'role',        label: 'Role Guard',      icon: 'userCheck' },
    { key: 'webhook',     label: 'Webhook Guard',   icon: 'link' },
    { key: 'bot',         label: 'Bot Guard',       icon: 'bot' },
    { key: 'responses',   label: 'Responses',       icon: 'megaphone' },
    { key: 'backups',     label: 'Backups',         icon: 'archive' },
    { key: 'lockdown',    label: 'Lockdown',        icon: 'lock' },
    { key: 'access',      label: 'Access Control',  icon: 'shieldCheck' },
    { key: 'incidents',   label: 'Incidents',       icon: 'inbox' },
    { key: 'health',      label: 'Health',          icon: 'heart' },
    { key: 'settings',    label: 'Settings',        icon: 'settings' },
];

// Modules that get their own dedicated section (everything except the two
// special-case modules `raid` and `permission`, which have bespoke sections).
const GUARD_SECTIONS = {
    channel: 'channel',
    role: 'role',
    webhook: 'webhook',
    bot: 'bot',
};

function statCard({ label, value, icon, hint = '', tone = '' }) {
    return `
      <div class="am-stat ${tone ? 'am-stat-' + esc(tone) : ''}">
        <div class="am-stat-icon">${svgIcon(icon)}</div>
        <div class="am-stat-body">
          <div class="am-stat-label">${esc(label)}</div>
          <div class="am-stat-value">${esc(value)}</div>
          ${hint ? `<div class="am-stat-hint">${esc(hint)}</div>` : ''}
        </div>
      </div>`;
}

/** One guard section (channel / role / webhook / bot) = the module's actions. */
function guardSectionHTML(moduleKey, watched, settings) {
    const mod = ANTINUKE_MODULES.find(m => m.key === moduleKey);
    if (!mod) return '';
    const actions = ANTINUKE_ACTIONS.filter(a => a.module === moduleKey);
    const rows = actions.map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('');
    return `
      <section class="an-section" data-section="${esc(GUARD_SECTIONS[moduleKey])}" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon(mod.iconName)}</span> ${esc(mod.label)}</span></div>
          <p class="card-desc">${esc(mod.description)}</p>
          <div class="an-action-list">${rows}</div>
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('sliders')}</span> Responses for this guard</span></div>
          <p class="card-desc">Leave unset to use the global Responses. Enabling ban/kick here punishes a confirmed attacker for this guard's actions only.</p>
          <details class="an-rule-responses">
            <summary>${svgIcon('sliders')} Per-action response overrides</summary>
            ${actions.map(a => {
                const overrides = ((settings.actionResponses || {})[a.key]) || [];
                return `<div class="an-rule-response">
                  <span class="an-rule-response-name">${svgIcon(a.iconName)} ${esc(a.label)}</span>
                  <span class="an-rule-response-cbs">${ANTINUKE_RESPONSES.map(r => `
                    <label class="an-rule-response-cb"><input type="checkbox" class="an-action-response-cb" data-action="${esc(a.key)}" value="${esc(r.key)}" ${overrides.includes(r.key) ? 'checked' : ''}/> ${esc(r.label)}</label>`).join('')}</span>
                </div>`;
            }).join('')}
          </details>
        </div>
      </section>`;
}

function overviewSectionHTML({ settings, lockdown, summary }) {
    const watched = settings.watched || {};
    const activeModules = ANTINUKE_MODULES.filter(m => ANTINUKE_ACTIONS.some(a => a.module === m.key && (watched[a.key] || {}).enabled !== false)).length;
    const totalActions = ANTINUKE_ACTIONS.filter(a => (watched[a.key] || {}).enabled !== false).length;
    const s = summary || { total: 0, byAction: [] };
    return `
      <section class="an-section" data-section="overview">
        <div class="am-stats" id="an-overview-stats">
          ${statCard({ label: 'Protection', value: settings.enabled ? 'Enabled' : 'Disabled', icon: 'shield', tone: settings.enabled ? 'accent' : '' })}
          ${statCard({ label: 'Active modules', value: String(activeModules) + ' / ' + ANTINUKE_MODULES.length, icon: 'layers', hint: totalActions + ' actions watched' })}
          ${statCard({ label: 'Incidents', value: String(s.total || 0), icon: 'inbox', hint: 'last ' + (s.days || 30) + ' days' })}
          ${statCard({ label: 'Lockdown', value: lockdown && lockdown.active ? 'Active' : 'Off', icon: 'lock', tone: lockdown && lockdown.active ? 'accent' : '' })}
        </div>

        <div class="card">
          <div class="card-title">
            <span><span class="icon">${svgIcon('activity')}</span> Security overview</span>
            <span class="an-range">
              <select id="an-overview-range" class="an-range-select">
                <option value="1">24 hours</option>
                <option value="7">7 days</option>
                <option value="30" selected>30 days</option>
                <option value="0">All time</option>
              </select>
            </span>
          </div>
          <div class="am-stats" id="an-overview-live"></div>
          <div id="an-overview-modules" class="an-overview-modules"></div>
          <div id="an-overview-top" class="an-overview-top"></div>
        </div>

        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('zap')}</span> Quick actions</span></div>
          <div class="an-setup-actions">
            <button class="btn btn-mini" id="an-qa-lockdown">${svgIcon('lock')} Engage lockdown</button>
            <button class="btn btn-mini" id="an-qa-backup">${svgIcon('archive')} Create backup</button>
            <button class="btn btn-mini" id="an-qa-health">${svgIcon('heart')} Run health scan</button>
          </div>
        </div>
      </section>`;
}

function antiRaidSectionHTML({ settings }) {
    const raid = settings.raid || {};
    const watched = settings.watched || {};
    const raidMod = ANTINUKE_MODULES.find(m => m.key === 'raid');
    const raidRows = ANTINUKE_ACTIONS.filter(a => a.module === 'raid')
        .map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('');
    const risk = [
        { key: 'low', label: 'Low' }, { key: 'medium', label: 'Medium' },
        { key: 'high', label: 'High' }, { key: 'critical', label: 'Critical' },
    ];
    return `
      <section class="an-section" data-section="antiraid" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('users')}</span> Anti-Raid</span></div>
          <p class="card-desc">Detects join floods, coordinated join waves and suspicious new-account activity. Detection uses several signals together — an account is never actioned for being new alone.</p>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Enable Anti-Raid</div><div class="sl-desc">Joins are monitored and fed to the raid detector.</div></div>
            <label class="switch"><input type="checkbox" id="an-raid-enabled" ${raid.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Automatic lockdown on a confirmed raid</div><div class="sl-desc">Engage the configured lockdown profile when the detector confirms a raid.</div></div>
            <label class="switch"><input type="checkbox" id="an-raid-autolockdown" ${raid.automaticLockdown === true ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="an-watch-grid">
            <label class="am-field am-field-num"><span class="am-field-label">Join velocity (joins / window)</span><input type="number" id="an-raid-velocity" min="1" max="200" value="${esc(raid.joinThreshold != null ? raid.joinThreshold : 10)}"/></label>
            <label class="am-field am-field-num"><span class="am-field-label">Window (seconds)</span><input type="number" id="an-raid-window" min="1" max="3600" value="${esc(raid.joinWindowSeconds != null ? raid.joinWindowSeconds : 30)}"/></label>
            <label class="am-field am-field-num"><span class="am-field-label">Min account age (days)</span><input type="number" id="an-raid-account-age" min="0" max="365" value="${esc(raid.accountAgeMinDays != null ? raid.accountAgeMinDays : 7)}"/></label>
            <label class="am-field am-field-num"><span class="am-field-label">Verification escalation</span>
              <select id="an-raid-verification">
                ${['none', 'low', 'medium', 'high', 'very_high'].map(v => `<option value="${esc(v)}" ${String(raid.verificationLevel || 'high') === v ? 'selected' : ''}>${esc(v)}</option>`).join('')}
              </select>
            </label>
          </div>
          <div class="field">
            <label class="field-label">Risk thresholds</label>
            <div class="an-raid-risk">${risk.map(r => `
              <span class="an-risk an-risk-${esc(r.key)}">${svgIcon('alertTriangle')} ${esc(r.label)}</span>`).join('')}</div>
            <div class="field-hint">Risk is computed from join velocity, new-account ratio and coordination. Only a confirmed (high/critical) raid escalates to containment.</div>
          </div>
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('users')}</span> Raid detection signals</span></div>
          <p class="card-desc">${esc((raidMod && raidMod.description) || 'Join velocity, new-account waves and coordinated join patterns.')}</p>
          <div class="an-action-list">${raidRows}</div>
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('inbox')}</span> Raid incidents</span></div>
          <div id="an-raid-incidents" class="an-activity-wrap">
            <table class="an-activity-table"><thead><tr><th>Detected</th><th>Risk</th><th>Joins</th><th>New accounts</th><th>Response</th></tr></thead>
            <tbody id="an-raid-incidents-body"><tr><td colspan="5" class="an-empty">Loading…</td></tr></tbody></table>
          </div>
          <div class="an-setup-actions">
            <button class="btn btn-mini" id="an-raid-refresh">${svgIcon('refresh')} Refresh</button>
          </div>
        </div>
      </section>`;
}

function permissionGuardSectionHTML({ settings }) {
    const watched = settings.watched || {};
    const actions = ANTINUKE_ACTIONS.filter(a => a.module === 'permission');
    const rows = actions.map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('');
    return `
      <section class="an-section" data-section="permission" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('key')}</span> Permission Guard</span></div>
          <p class="card-desc">Watches for dangerous permission grants — Administrator, Manage Server/Roles/Channels/Webhooks and mass ban/kick. Enforcement only ever runs on a verified audit-log executor; uncertain attribution alerts but never contains.</p>
          <div class="an-action-list">${rows}</div>
        </div>
      </section>`;
}

function responsesSectionHTML({ settings }) {
    return `
      <section class="an-section" data-section="responses" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('megaphone')}</span> Response configuration</span></div>
          <p class="card-desc">What happens when a threshold trips. Every response is checked by default (except "Log only"). Punishment responses (ban/kick) always require explicit opt-in per action — a confirmed attacker is never permanently punished automatically.</p>
          <div class="an-responses">${ANTINUKE_RESPONSES.map(r => `
            <label class="an-response">
              <input type="checkbox" class="an-response-cb" value="${esc(r.key)}" ${(settings.responses || []).includes(r.key) ? 'checked' : ''}/>
              <span class="an-response-body">
                <span class="an-response-name">${svgIcon(r.iconName)} ${esc(r.label)}${r.dangerous ? ' <span class="an-danger-tag">containment</span>' : ''}</span>
                <span class="an-response-desc">${esc(r.description)}</span>
              </span>
            </label>`).join('')}</div>
          <div class="field">
            <label class="field-label" for="an-quarantine-role">Quarantine role</label>
            <select id="an-quarantine-role" data-role-select data-placeholder="— None (strip dangerous roles only) —"><option value="">${esc(settings.quarantineRoleId ? settings.quarantineRoleId : '— None (strip dangerous roles only) —')}</option></select>
            <div class="field-hint">Applied to the confirmed attacker by the Quarantine response. Unset falls back to stripping dangerous roles only.</div>
          </div>
          <div class="field">
            <label class="field-label">Dangerous permissions to strip</label>
            <div class="an-perm-list">${ANTINUKE_DANGEROUS_PERMISSIONS.map(p => `
              <label class="an-perm"><input type="checkbox" class="an-danger-perm" value="${esc(p.key)}" ${(settings.dangerousPermissions || []).includes(p.key) ? 'checked' : ''}/> ${esc(p.label)}</label>`).join('')}</div>
          </div>
          <div class="field">
            <label class="field-label" for="an-response-cooldown">Response cooldown (seconds)</label>
            <input type="number" id="an-response-cooldown" min="0" max="3600" value="${esc(settings.responseCooldownSeconds != null ? settings.responseCooldownSeconds : 30)}"/>
            <div class="field-hint">Minimum gap between responses for the same guild + action, so a sustained attack does not flood alerts.</div>
          </div>
        </div>
      </section>`;
}

function backupsSectionHTML() {
    return `
      <section class="an-section" data-section="backups" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('archive')}</span> Server structure backups</span></div>
          <p class="card-desc">Snapshots capture roles (with permission bitfields), channel/category structure, positions and permission overwrites, plus the guild security settings a bot can read. Restoration recreates structure — <strong>recreated roles and channels receive new IDs</strong>, and deleted messages cannot be restored through Discord's API.</p>
          <div class="an-setup-actions">
            <input type="text" id="an-backup-name" placeholder="Backup name (optional)" class="an-backup-name"/>
            <button class="btn btn-primary btn-mini" id="an-backup-create">${svgIcon('archive')} Create snapshot</button>
            <button class="btn btn-mini" id="an-backup-refresh">${svgIcon('refresh')} Refresh</button>
          </div>
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> Snapshots</span></div>
          <div id="an-backup-list" class="an-backup-list"><div class="an-empty">Loading…</div></div>
        </div>
      </section>`;
}

function lockdownSectionHTML({ lockdown }) {
    const profiles = [
        { key: 'join',      label: 'Join Lockdown',      desc: 'Raise verification and pause invites to stop account floods.' },
        { key: 'message',   label: 'Message Lockdown',   desc: 'Restrict @everyone from sending messages in public channels.' },
        { key: 'channel',   label: 'Channel Lockdown',   desc: 'Hide public channels from @everyone.' },
        { key: 'permission', label: 'Permission Lockdown', desc: 'Strip dangerous permissions from managed roles.' },
        { key: 'full',      label: 'Full Emergency Lockdown', desc: 'Apply every supported lockdown operation at once.' },
    ];
    return `
      <section class="an-section" data-section="lockdown" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('lock')}</span> Lockdown</span></div>
          <p class="card-desc">Emergency lockdown saves exactly what it changes so it can be reversed, and never overwrites an administrator's later changes. Choose a profile to preview its exact operations before activating.</p>
          <div class="an-lockdown-status" id="an-lockdown-status">
            ${lockdown && lockdown.active
              ? `<span class="am-pill am-pill-off">${svgIcon('lock')} Active${lockdown.startedAt ? ` since ${esc(String(lockdown.startedAt).slice(0, 19))}` : ''}</span>`
              : `<span class="am-pill am-pill-on">${svgIcon('unlock')} Not active</span>`}
          </div>
        </div>
        <div class="an-lockdown-profiles">
          ${profiles.map(p => `
            <div class="card an-lockdown-profile" data-profile="${esc(p.key)}">
              <div class="card-title"><span><span class="icon">${svgIcon('lock')}</span> ${esc(p.label)}</span></div>
              <p class="card-desc">${esc(p.desc)}</p>
              <ul class="an-profile-ops" id="an-profile-ops-${esc(p.key)}"></ul>
              <div class="an-setup-actions">
                <button class="btn btn-mini an-lockdown-preview" data-profile="${esc(p.key)}">${svgIcon('eye')} Preview</button>
                <button class="btn btn-danger btn-mini an-lockdown-engage-profile" data-profile="${esc(p.key)}">${svgIcon('lock')} Engage</button>
              </div>
            </div>`).join('')}
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('unlock')}</span> Recovery</span></div>
          <p class="card-desc">Restores only the settings changed by the active lockdown. Settings changed by an administrator afterwards are left untouched.</p>
          <div class="an-setup-actions">
            <button class="btn" id="an-lockdown-lift" ${lockdown && lockdown.active ? '' : 'disabled'}>${svgIcon('unlock')} Restore lockdown</button>
          </div>
        </div>
      </section>`;
}

function incidentsSectionHTML() {
    return `
      <section class="an-section" data-section="incidents" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('inbox')}</span> Incident center</span></div>
          <p class="card-desc">Every detected incident with its attribution result, response plan and outcome. Only real outcomes are stored.</p>
          <div class="an-incident-filters">
            <input type="search" id="an-inc-search" placeholder="Search executor, action, details…"/>
            <select id="an-inc-severity"><option value="">All severities</option>${['low', 'medium', 'high', 'critical'].map(s => `<option value="${s}">${s}</option>`).join('')}</select>
            <select id="an-inc-action"><option value="">All categories</option>${ANTINUKE_ACTIONS.map(a => `<option value="${esc(a.key)}">${esc(a.label)}</option>`).join('')}</select>
            <input type="text" id="an-inc-executor" placeholder="Executor ID"/>
            <select id="an-inc-range"><option value="">All time</option><option value="1">24 hours</option><option value="7">7 days</option><option value="30">30 days</option></select>
            <button class="btn btn-mini" id="an-inc-export">${svgIcon('download')} Export CSV</button>
          </div>
          <div class="an-activity-summary" id="an-activity-summary"></div>
          <div class="an-activity-wrap">
            <table class="an-activity-table" id="an-activity-table">
              <thead><tr><th>Detected</th><th>Executor</th><th>Category</th><th>Severity</th><th>Threshold</th><th>Response</th><th>Result</th><th></th></tr></thead>
              <tbody id="an-activity-body"><tr><td colspan="8" class="an-empty">Loading…</td></tr></tbody>
            </table>
            <div class="an-activity-pager">
              <button class="btn btn-mini" id="an-activity-prev">‹ Prev</button>
              <span id="an-activity-page">Page 1</span>
              <button class="btn btn-mini" id="an-activity-next">Next ›</button>
            </div>
          </div>
        </div>
      </section>`;
}

function healthSectionHTML() {
    return `
      <section class="an-section" data-section="health" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('heart')}</span> Protection health</span></div>
          <p class="card-desc">Checks intents, event handlers, database connectivity, detection modules, audit-log attribution, enforcement handlers, response mappings, dry-run state, permissions, role hierarchy, quarantine role, alert channel and backup availability. A module is never reported ready when a required component is missing.</p>
          <div class="an-setup-actions"><button class="btn btn-primary btn-mini" id="an-health-run">${svgIcon('refresh')} Run health scan</button></div>
          <div id="an-health-result" class="an-health-result"><div class="an-empty">Run a scan to see readiness.</div></div>
        </div>
      </section>`;
}

function settingsSectionHTML({ settings, channels, permissionReport }) {
    const permWarning = permissionReport && !permissionReport.ok ? `
      <div class="card an-warn-card">
        <div class="card-title"><span><span class="icon">${svgIcon('alertTriangle')}</span> Missing permissions</span></div>
        <p class="card-desc">Anti-Nuke cannot fully protect this server until PrimeBot has these permissions:</p>
        <ul class="an-perm-checks">${permissionReport.checks.map(c => `
          <li class="an-perm-check ${c.available ? 'ok' : 'bad'}"><span>${svgIcon(c.available ? 'check' : 'x')}</span> <strong>${esc(c.label)}</strong> <span class="an-perm-for">${esc(c.neededFor)}</span></li>`).join('')}</ul>
      </div>` : '';
    return `
      <section class="an-section" data-section="settings" hidden>
        ${permWarning}
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('settings')}</span> General</span></div>
          <div class="field">
            <label class="field-label" for="an-alert-channel">Alert channel</label>
            <select id="an-alert-channel" data-channel-select>${channelOptions(channels, settings.alertChannelId)}</select>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Dry run</div><div class="sl-desc">Detect and alert but never contain. Off by default — leave off to let protection enforce.</div></div>
            <label class="switch"><input type="checkbox" id="an-dry-run" ${settings.dryRun !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Lockdown allowed</div><div class="sl-desc">Permit a lockdown response (raises verification level, pauses invites).</div></div>
            <label class="switch"><input type="checkbox" id="an-lockdown-enabled" ${settings.lockdown && settings.lockdown.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
        </div>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('userCheck')}</span> Trusted users &amp; roles</span></div>
          <p class="card-desc">Anyone listed here bypasses Anti-Nuke entirely. The server owner and PrimeBot always do. Administrators are NOT trusted automatically.</p>
          <div class="field">
            <label class="field-label">Trusted users</label>
            <div class="an-trusted-input"><input type="text" id="an-trusted-user-input" placeholder="User ID (15-22 digits)"/><button class="btn" id="an-add-trusted-user">${svgIcon('userPlus')} Add</button></div>
            <div class="rr-list" id="an-trusted-users"></div>
          </div>
          <div class="field">
            <label class="field-label">Trusted roles</label>
            <div class="rr-list" id="an-trusted-roles"></div>
          </div>
        </div>
      </section>`;
}

function consoleHTML({ guild, settings, lockdown, permissionReport, summary }) {
    const watched = settings.watched || {};
    const channels = guild._channels || [];

    return `
    <div class="an-page an-console-page">
      <section class="card am-hero">
        <div class="am-hero-main">
          <div class="am-hero-icon">${svgIcon('shieldAlert')}</div>
          <div>
            <h2 class="am-hero-title">Anti-Nuke</h2>
            <p class="am-hero-sub">Detect and contain destructive administrative actions — mass channel/role deletion, mass bans, webhook and bot additions, permission escalation and raids.</p>
            <div class="am-hero-pills">
              <span class="am-pill ${settings.enabled ? 'am-pill-on' : 'am-pill-off'}">${svgIcon(settings.enabled ? 'check' : 'x')} ${settings.enabled ? 'Protection active' : 'Disabled'}</span>
              ${settings.dryRun !== false ? `<span class="am-pill am-pill-warn">${svgIcon('flask')} Dry run</span>` : `<span class="am-pill am-pill-live">${svgIcon('zap')} Live containment</span>`}
              ${lockdown && lockdown.active ? `<span class="am-pill am-pill-off">${svgIcon('lock')} Lockdown active</span>` : ''}
              <button class="btn btn-mini" id="an-rerun-setup">Re-run setup</button>
            </div>
          </div>
        </div>
        <div class="am-hero-switch">
          <div class="am-hero-switch-label">
            <div class="sl-title">Enable Anti-Nuke</div>
            <div class="sl-desc">Saves immediately.</div>
          </div>
          <label class="switch"><input type="checkbox" id="an-enabled" ${settings.enabled ? 'checked' : ''}/><span class="slider"></span></label>
        </div>
      </section>

      <nav class="am-sections an-sections" id="an-sections" aria-label="Anti-Nuke sections">
        ${SECTION_ORDER.map((sec, i) => `
          <button type="button" class="am-section-btn ${i === 0 ? 'active' : ''}" data-section="${esc(sec.key)}" aria-current="${i === 0 ? 'true' : 'false'}">
            ${svgIcon(sec.icon)}<span>${esc(sec.label)}</span>
          </button>`).join('')}
      </nav>

      ${overviewSectionHTML({ settings, lockdown, summary })}
      <section class="an-section" data-section="protection" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> Threat detection</span></div>
          <p class="card-desc">Pick which dangerous actions are monitored and how many within a window count as an attack. Thresholds are per-executor sliding windows.</p>
          <div class="an-modules">${ANTINUKE_MODULES.filter(m => !GUARD_SECTIONS[m.key] && m.key !== 'permission' && m.key !== 'raid').map(m => moduleCardHTML(m, watched)).join('')}</div>
        </div>
      </section>
      ${antiRaidSectionHTML({ settings })}
      ${permissionGuardSectionHTML({ settings })}
      ${guardSectionHTML('channel', watched, settings)}
      ${guardSectionHTML('role', watched, settings)}
      ${guardSectionHTML('webhook', watched, settings)}
      ${guardSectionHTML('bot', watched, settings)}
      ${responsesSectionHTML({ settings })}
      ${backupsSectionHTML()}
      ${lockdownSectionHTML({ lockdown })}
      <section class="an-section" data-section="access" hidden>
        <div class="card">
          <div class="card-title"><span><span class="icon">${svgIcon('shieldCheck')}</span> Access control</span></div>
          <p class="card-desc">Anti-Nuke management is restricted to the server owner and to Co-Owners / Trusted Admins explicitly appointed by the owner with the permissions below.</p>
          <div id="an-access-root" class="an-access-root">
            <div class="an-access-loading">Loading access control…</div>
          </div>
        </div>
      </section>
      ${incidentsSectionHTML()}
      ${healthSectionHTML()}
      ${settingsSectionHTML({ settings, channels, permissionReport })}
    </div>`;
}
// ── Page ────────────────────────────────────────────────────────────────────

/**
 * Decide how much of the Anti-Nuke panel a viewer may see, based on the
 * owner-controlled access hierarchy (utils/antiNukeAccess) that
 * `requireGuildAdminPage` attached as `guild._antiNukeAccess`. Anti-Nuke is
 * NOT released to the public: Discord Administrator/Manage Guild grants nothing
 * by itself — only the ACTUAL guild owner and explicitly assigned Co-Owners /
 * Trusted Admins get in.
 *
 * Returns { mode: 'denied'|'locked'|'granted', reason }
 *   - denied:  not a member / access could not be resolved (no access page)
 *   - locked:  member with no Anti-Nuke access — explanatory "no access" panel
 *   - granted: owner or an assigned user (page renders fully)
 */
function accessModeFor(guild) {
    const ctx = guild && guild._antiNukeAccess;
    if (!ctx || !ctx.ok) return { mode: 'denied', reason: ctx && ctx.reason ? ctx.reason : 'unresolved' };
    if (ctx.role === 'none' && !ctx.isOwner) return { mode: 'locked', reason: 'no_access' };
    return { mode: 'granted', reason: null };
}

/**
 * Render the "no access" panel for a logged-in guild admin who is not part of
 * the Anti-Nuke hierarchy. This is deliberate: an ordinary Discord
 * Administrator/Moderator has no Anti-Nuke management access by default, and
 * only the owner (or an assigned manager) can grant it.
 */
function noAccessPanelHTML(guild, ctx) {
    const ctxSafe = ctx && typeof ctx === 'object' ? ctx : {};
    const accessState = {
        role: ctxSafe.role || 'none',
        level: ctxSafe.level != null ? ctxSafe.level : 4,
        isOwner: !!ctxSafe.isOwner,
    };
    return `
    <div class="card an-no-access">
        <div class="an-no-access-icon">${svgIcon('shieldAlert')}</div>
        <h3>No Anti-Nuke access</h3>
        <p>Anti-Nuke configuration is restricted. You are signed in as a server
        administrator, but this server's owner has not granted you any
        Anti-Nuke management permission.</p>
        <p class="an-no-access-hint">Ask the server owner to open
        <strong>Server features → 🛡️ Anti-Nuke → Access Control</strong> and
        assign you a role (Co-Owner or Trusted Admin) with the permissions you
        need.</p>
        <script>window.__ANTINUKE_ACCESS_CONTEXT=${jsonForScript(accessState)};</script>
    </div>`;
}

function antiNukePageHTML({ guild, user, view }) {
    const settings = (guild._config || {}).antiNuke || {};
    const lockdown = (guild._config || {}).antiNukeLockdown || { active: false };
    const permissionReport = (guild._config || {}).antiNukePermissions || null;
    const summary = (guild._config || {}).antiNukeSummary || { total: 0, byAction: [] };
    const setup = (guild._config || {}).antiNukeSetup || { status: 'not_started', progress: { percent: 0, completed: 0, total: 0, steps: [] } };
    const accessCtx = (guild && guild._antiNukeAccess) || { role: 'none', level: 4, isOwner: false };
    const { mode, reason } = accessModeFor(guild);

    let inner;
    if (mode !== 'granted') {
        inner = noAccessPanelHTML(guild, accessCtx);
    } else if (view === 'wizard') {
        inner = manualWizardHTML(guild, settings);
    } else if (view === 'console' || (setup.status === 'completed' && view !== 'setup')) {
        inner = consoleHTML({ guild, settings, lockdown, permissionReport, summary });
    } else {
        inner = setupChooserHTML({ ...setup, enabled: settings.enabled });
    }

    const body = `
    ${require('./guild').guildHeaderHTML(guild)}
    ${require('./guild').tabNavHTML(guild.id, 'antinuke')}
    ${inner}
    ${require('./guild').guildDataScript({
        guildId: guild.id,
        channels: guild._channels,
        roles: guild._roles,
        extra: { _antiNukeSettings: settings, _antiNukeLockdown: lockdown, _antiNukeSummary: summary },
    })}
    <script>
window.__ANTINUKE_ACCESS=${jsonForScript({
    role: accessCtx.role || 'none',
    level: accessCtx.level != null ? accessCtx.level : 4,
    isOwner: !!accessCtx.isOwner,
    permissions: accessCtx.permissions || [],
    canManageAccess: !!accessCtx.canManageAccess,
    canAppointCoOwners: !!accessCtx.canAppointCoOwners,
    canRevoke: !!accessCtx.canRevoke,
})};
window.__ANTINUKE_ACTIONS=${jsonForScript(ANTINUKE_ACTIONS)};
window.__ANTINUKE_RESPONSES=${jsonForScript(ANTINUKE_RESPONSES)};
window.__ANTINUKE_MODULES=${jsonForScript(ANTINUKE_MODULES)};
window.__ANTINUKE_DANGEROUS_PERMISSIONS=${jsonForScript(ANTINUKE_DANGEROUS_PERMISSIONS)};
window.__ANTINUKE_SETTINGS=${jsonForScript(settings)};
window.__ANTINUKE_SETUP=${jsonForScript(setup)};
window.__ANTINUKE_VIEW=${jsonForScript(view || (setup.status === 'completed' ? 'console' : 'setup'))};
window.__ANTINUKE_PERMISSION_CATALOG=${jsonForScript(require('../constants').ANTINUKE_PERMISSION_CATALOG || {})};
</script>`;

    return { body, scripts: ['/js/guild-common.js', '/js/antinuke.js'], title: `PrimeBot · ${guild.name} · Anti-Nuke` };
}

module.exports = { antiNukePageHTML, moduleCardHTML, actionRowHTML, setupChooserHTML, manualWizardHTML, consoleHTML, stepListHTML, accessModeFor, SECTION_ORDER, statCard };
