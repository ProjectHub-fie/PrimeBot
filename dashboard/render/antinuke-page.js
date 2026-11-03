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
    const progressPanel = resume ? `
      <section class="card an-progress-card" id="an-progress-card">
        <div class="card-title"><span><span class="icon">${svgIcon('activity')}</span> Setup in progress</span></div>
        <div class="an-progress-bar"><div class="an-progress-fill" style="width:${progress.percent}%"></div></div>
        <div class="an-progress-meta"><strong>${progress.percent}%</strong> · ${progress.completed} of ${progress.total} required steps completed</div>
        <ul class="an-step-list">${stepListHTML(progress.steps)}</ul>
        <div class="an-setup-actions">
          <button class="btn btn-primary" id="an-resume-setup">${svgIcon('playCircle')} Resume setup</button>
          <button class="btn" id="an-reset-setup">Reset progress</button>
        </div>
      </section>` : '';

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
              <span class="am-pill am-pill-warn">${svgIcon('flask')} Dry run by default</span>
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

    return `
    <div class="an-page an-wizard-page">
      <section class="card an-progress-card">
        <div class="card-title"><span><span class="icon">${svgIcon('sliders')}</span> Manual Security Setup</span></div>
        <div class="an-progress-bar"><div class="an-progress-fill" id="an-wizard-fill" style="width:0%"></div></div>
        <div class="an-progress-meta"><strong id="an-wizard-percent">0%</strong> · <span id="an-wizard-count">0 of ${ANTINUKE_MANUAL_SECTIONS.length} sections completed</span></div>
        <ul class="an-step-list" id="an-wizard-steps">${stepListHTML(ANTINUKE_MANUAL_SECTIONS.map(s => ({ key: s.key, label: s.label, required: s.required, status: 'pending' })))}</ul>
      </section>

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
              <div class="switch-row">
                <div class="switch-label"><div class="sl-title">Dry run</div><div class="sl-desc">Detect and alert but never contain. Turn off only once you trust the thresholds.</div></div>
                <label class="switch"><input type="checkbox" id="an-dry-run" ${settings.dryRun !== false ? 'checked' : ''}/><span class="slider"></span></label>
              </div>
              <div class="field">
                <label class="field-label" for="an-alert-channel">Alert channel</label>
                <select id="an-alert-channel" data-channel-select>${channelOptions(channels, settings.alertChannelId)}</select>
                <div class="field-hint">Where security alerts are posted.</div>
              </div>`;
        case 'trust':
            return `
              <div class="field">
                <label class="field-label">Trusted users</label>
                <div class="an-trusted-input"><input type="text" id="an-trusted-user-input" placeholder="User ID (15-22 digits)"/><button class="btn" id="an-add-trusted-user">${svgIcon('userPlus')} Add</button></div>
                <div class="rr-list" id="an-trusted-users"></div>
                <div class="field-hint">Anyone listed here bypasses Anti-Nuke. The server owner and PrimeBot always do.</div>
              </div>
              <div class="field">
                <label class="field-label">Trusted roles</label>
                <div class="rr-list" id="an-trusted-roles"></div>
              </div>`;
        case 'response':
            return `
              <div class="an-responses">${ANTINUKE_RESPONSES.map(r => `
                <label class="an-response">
                  <input type="checkbox" class="an-response-cb" value="${esc(r.key)}" ${(settings.responses || []).includes(r.key) ? 'checked' : ''}/>
                  <span class="an-response-body">
                    <span class="an-response-name">${svgIcon(r.iconName)} ${esc(r.label)}${r.dangerous ? ' <span class="an-danger-tag">containment</span>' : ''}</span>
                    <span class="an-response-desc">${esc(r.description)}</span>
                  </span>
                </label>`).join('')}</div>
              <div class="field">
                <label class="field-label">Dangerous permissions to strip</label>
                <div class="an-perm-list">${ANTINUKE_DANGEROUS_PERMISSIONS.map(p => `
                  <label class="an-perm"><input type="checkbox" class="an-danger-perm" value="${esc(p.key)}" ${(settings.dangerousPermissions || []).includes(p.key) ? 'checked' : ''}/> ${esc(p.label)}</label>`).join('')}</div>
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
            // Module sections (channel/role/member/webhook/bot/server) — the
            // same watched-action rows as the console, scoped to one module.
            const mod = ANTINUKE_MODULES.find(m => m.key === key);
            if (!mod) return '';
            const watched = settings.watched || {};
            return `<div class="an-action-list">${ANTINUKE_ACTIONS.filter(a => a.module === key)
                .map(a => actionRowHTML(a, watched[a.key] || { enabled: true, threshold: a.threshold, seconds: a.seconds })).join('')}</div>`;
        }
    }
}

// ── Protection console ──────────────────────────────────────────────────────

function consoleHTML({ guild, settings, lockdown, permissionReport, summary }) {
    const watched = settings.watched || {};
    const channels = guild._channels || [];
    const trustedRoles = Array.isArray(settings.trustedRoleIds) ? settings.trustedRoleIds : [];
    const trustedUsers = Array.isArray(settings.trustedUserIds) ? settings.trustedUserIds : [];

    const permWarning = permissionReport && !permissionReport.ok ? `
      <section class="card an-warn-card">
        <div class="card-title"><span><span class="icon">${svgIcon('alertTriangle')}</span> Missing permissions</span></div>
        <p class="card-desc">Anti-Nuke cannot fully protect this server until PrimeBot has these permissions:</p>
        <ul class="an-perm-checks">${permissionReport.checks.map(c => `
          <li class="an-perm-check ${c.available ? 'ok' : 'bad'}"><span>${svgIcon(c.available ? 'check' : 'x')}</span> <strong>${esc(c.label)}</strong> <span class="an-perm-for">${esc(c.neededFor)}</span></li>`).join('')}</ul>
      </section>` : '';

    return `
    <div class="an-page an-console-page">
      <section class="card am-hero">
        <div class="am-hero-main">
          <div class="am-hero-icon">${svgIcon('shieldAlert')}</div>
          <div>
            <h2 class="am-hero-title">Anti-Nuke</h2>
            <p class="am-hero-sub">Detect and contain destructive administrative actions — mass channel/role deletion, mass bans, webhook and bot additions.</p>
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

      ${permWarning}

      ${settings.dryRun !== false ? `
      <section class="card an-dryrun-card">
        <div class="card-title"><span><span class="icon">${svgIcon('flask')}</span> DRY RUN ACTIVE</span></div>
        <p class="card-desc">Protection is monitoring threats. Automatic containment is disabled — incidents are detected, attributed and alerted, but nobody is contained and the server is not locked down.</p>
      </section>` : ''}

      <section class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> Threat detection</span></div>
        <p class="card-desc">Pick which dangerous actions are monitored and how many within a window count as an attack. Thresholds are per-executor sliding windows.</p>
        <div class="an-modules">${ANTINUKE_MODULES.map(m => moduleCardHTML(m, watched)).join('')}</div>
      </section>

      <section class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('megaphone')}</span> Response configuration</span></div>
        <p class="card-desc">What happens when a threshold trips. All responses alert and contain — none of them punish a member automatically.</p>
        <div class="an-responses">${ANTINUKE_RESPONSES.map(r => `
          <label class="an-response">
            <input type="checkbox" class="an-response-cb" value="${esc(r.key)}" ${(settings.responses || []).includes(r.key) ? 'checked' : ''}/>
            <span class="an-response-body">
              <span class="an-response-name">${svgIcon(r.iconName)} ${esc(r.label)}${r.dangerous ? ' <span class="an-danger-tag">containment</span>' : ''}</span>
              <span class="an-response-desc">${esc(r.description)}</span>
            </span>
          </label>`).join('')}</div>
        <div class="field">
          <label class="field-label" for="an-alert-channel">Alert channel</label>
          <select id="an-alert-channel" data-channel-select>${channelOptions(channels, settings.alertChannelId)}</select>
        </div>
        <div class="switch-row">
          <div class="switch-label"><div class="sl-title">Dry run</div><div class="sl-desc">Detect and alert but never contain.</div></div>
          <label class="switch"><input type="checkbox" id="an-dry-run" ${settings.dryRun !== false ? 'checked' : ''}/><span class="slider"></span></label>
        </div>
      </section>

      <section class="card">
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
      </section>

      <section class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('lock')}</span> Lockdown</span></div>
        <p class="card-desc">Emergency lockdown raises the verification level and pauses new invites, saving what it changes so it can be reversed. It never overwrites an administrator's later changes.</p>
        <div class="an-lockdown-status" id="an-lockdown-status">
          ${lockdown && lockdown.active
            ? `<span class="am-pill am-pill-off">${svgIcon('lock')} Active${lockdown.startedAt ? ` since ${esc(String(lockdown.startedAt).slice(0, 19))}` : ''}</span>`
            : `<span class="am-pill am-pill-on">${svgIcon('unlock')} Not active</span>`}
        </div>
        <div class="an-setup-actions">
          <button class="btn btn-danger" id="an-lockdown-engage" ${lockdown && lockdown.active ? 'disabled' : ''}>${svgIcon('lock')} Engage lockdown</button>
          <button class="btn" id="an-lockdown-lift" ${lockdown && lockdown.active ? '' : 'disabled'}>${svgIcon('unlock')} Restore lockdown</button>
        </div>
      </section>

      <section class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('activity')}</span> Security activity</span></div>
        <p class="card-desc">Detected incidents and the response taken. Only relevant security incidents are stored — never ordinary Discord events.</p>
        <div class="an-activity-summary" id="an-activity-summary"></div>
        <div class="an-activity-wrap">
          <table class="an-activity-table" id="an-activity-table">
            <thead><tr><th>Detected</th><th>Executor</th><th>Severity</th><th>Threshold</th><th>Response</th><th>Result</th><th>Mode</th></tr></thead>
            <tbody id="an-activity-body"><tr><td colspan="7" class="an-empty">Loading…</td></tr></tbody>
          </table>
          <div class="an-activity-pager">
            <button class="btn btn-mini" id="an-activity-prev">‹ Prev</button>
            <span id="an-activity-page">Page 1</span>
            <button class="btn btn-mini" id="an-activity-next">Next ›</button>
          </div>
        </div>
      </section>
    </div>`;
}

// ── Page ────────────────────────────────────────────────────────────────────

function antiNukePageHTML({ guild, user, view }) {
    const settings = (guild._config || {}).antiNuke || {};
    const lockdown = (guild._config || {}).antiNukeLockdown || { active: false };
    const permissionReport = (guild._config || {}).antiNukePermissions || null;
    const summary = (guild._config || {}).antiNukeSummary || { total: 0, byAction: [] };
    const setup = (guild._config || {}).antiNukeSetup || { status: 'not_started', progress: { percent: 0, completed: 0, total: 0, steps: [] } };

    // The console renders once setup has been completed (or was never needed);
    // otherwise the chooser + progress panel. `?view=console|wizard|setup`
    // overrides it so the client can switch without a round trip.
    let inner;
    if (view === 'wizard') {
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
window.__ANTINUKE_ACTIONS=${jsonForScript(ANTINUKE_ACTIONS)};
window.__ANTINUKE_RESPONSES=${jsonForScript(ANTINUKE_RESPONSES)};
window.__ANTINUKE_MODULES=${jsonForScript(ANTINUKE_MODULES)};
window.__ANTINUKE_DANGEROUS_PERMISSIONS=${jsonForScript(ANTINUKE_DANGEROUS_PERMISSIONS)};
window.__ANTINUKE_SETTINGS=${jsonForScript(settings)};
window.__ANTINUKE_SETUP=${jsonForScript(setup)};
window.__ANTINUKE_VIEW=${jsonForScript(view || (setup.status === 'completed' ? 'console' : 'setup'))};
</script>`;

    return { body, scripts: ['/js/guild-common.js', '/js/antinuke.js'], title: `PrimeBot · ${guild.name} · Anti-Nuke` };
}

module.exports = { antiNukePageHTML, moduleCardHTML, actionRowHTML, setupChooserHTML, manualWizardHTML, consoleHTML, stepListHTML };
