/**
 * Anti-Nuke dashboard page (upcoming feature).
 *
 * Anti-Nuke watches the destructive administrative actions a compromised or
 * malicious moderator can take (mass channel/role deletion, mass bans/kicks,
 * webhook and bot additions, permission rewrites) and alerts the server owner.
 *
 * The tab is flagged `upcoming: true` in render/guild.js, so this page renders
 * the standard "Coming Soon……" overlay for ordinary users — the editor markup
 * below is kept behind the blur, blurred and inert, so releasing the feature is
 * just a matter of removing the flag. Developer/owner bot roles bypass the gate
 * (guild._bypassUpcoming, set by requireGuildAdminPage) and get the real editor
 * so the feature can be exercised, exactly like eventsPage. Nothing here
 * moderates anyone: the detection executor is deliberately not attached to
 * Discord audit-log events while the feature is unreleased.
 *
 * All controls are real markup (usable before JS runs); the client script
 * (public/js/antinuke.js) only adds interactivity. Icons are SVG, never emoji.
 */

const { esc, channelOptions, roleOptions, render, svgIcon, jsonForScript } = require('./layout');
const constants = require('../constants');

const { ANTINUKE_ACTIONS, ANTINUKE_RESPONSES } = constants;

/** One watched-action card. */
function watchCardHTML(action, watch) {
    return `
      <div class="an-watch-card" data-action="${esc(action.key)}">
        <div class="an-watch-head">
          <label class="switch">
            <input type="checkbox" class="an-watch-enabled" ${watch.enabled !== false ? 'checked' : ''}/>
            <span class="slider"></span>
          </label>
          <span class="an-watch-icon">${svgIcon(action.iconName)}</span>
          <div class="an-watch-title">
            <div class="an-watch-name">${esc(action.label)}</div>
            <div class="an-watch-desc">${esc(action.description)}</div>
          </div>
          <span class="am-sev am-sev-${esc(action.severity)}">${esc(action.severity.charAt(0).toUpperCase() + action.severity.slice(1))}</span>
        </div>
        <div class="an-watch-params">
          <label class="am-field am-field-num">
            <span class="am-field-label">Threshold</span>
            <input type="number" class="an-watch-threshold" value="${esc(watch.threshold)}" min="1" max="100" />
          </label>
          <label class="am-field am-field-num">
            <span class="am-field-label">Within (seconds)</span>
            <input type="number" class="an-watch-seconds" value="${esc(watch.seconds)}" min="1" max="3600" />
          </label>
        </div>
      </div>`;
}

function antiNukePageHTML({ guild, user }) {
    const s = (guild._config || {}).antiNuke || {};
    const watched = s.watched || {};
    const responses = Array.isArray(s.responses) ? s.responses : [];
    const trustedRoles = Array.isArray(s.trustedRoleIds) ? s.trustedRoleIds : [];

    const responseChecks = ANTINUKE_RESPONSES.map(r => `
      <label class="an-response">
        <input type="checkbox" class="an-response-cb" value="${esc(r.key)}" ${responses.includes(r.key) ? 'checked' : ''}/>
        <span class="an-response-body">
          <span class="an-response-name">${svgIcon(r.iconName)} ${esc(r.label)}</span>
          <span class="an-response-desc">${esc(r.description)}</span>
        </span>
      </label>`).join('');

    const innerPanelHTML = `
    <div class="an-page">
      <section class="card am-hero">
        <div class="am-hero-main">
          <div class="am-hero-icon">${svgIcon('shieldAlert')}</div>
          <div>
            <h2 class="am-hero-title">Anti-Nuke</h2>
            <p class="am-hero-sub">Detect and contain destructive administrative actions — mass channel/role deletion, mass bans, webhook and bot additions.</p>
            <div class="am-hero-pills">
              <span class="am-pill ${s.enabled ? 'am-pill-on' : 'am-pill-off'}">
                ${svgIcon(s.enabled ? 'check' : 'x')} ${s.enabled ? 'Enabled' : 'Disabled'}
              </span>
              <span class="am-pill am-pill-warn">${svgIcon('flask')} Dry run by default</span>
            </div>
          </div>
        </div>
        <div class="am-hero-switch">
          <div class="am-hero-switch-label">
            <div class="sl-title">Enable Anti-Nuke</div>
            <div class="sl-desc">The server owner is never treated as a threat.</div>
          </div>
          <label class="switch"><input type="checkbox" id="an-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
        </div>
      </section>

      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('list')}</span> Watched actions</span></div>
        <p class="card-desc">Pick which dangerous actions are monitored and how many within a window count as an attack.</p>
        <div class="an-watch-grid">
          ${ANTINUKE_ACTIONS.map(a => watchCardHTML(a, watched[a.key] || { enabled: a.severity === 'critical', threshold: a.threshold, seconds: a.seconds })).join('')}
        </div>
      </div>

      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('megaphone')}</span> Response</span></div>
        <p class="card-desc">What should happen when a threshold trips. All responses alert and contain — none of them punish a member automatically.</p>
        <div class="an-responses">${responseChecks}</div>

        <div class="field">
          <label class="field-label" for="an-alert-channel">Alert channel</label>
          <select id="an-alert-channel" data-channel-select>${channelOptions(guild._channels, s.alertChannelId)}</select>
          <div class="field-hint">Where Anti-Nuke alerts are posted. The owner is DM'd when "Alert the server owner" is enabled.</div>
        </div>

        <div class="switch-row">
          <div class="switch-label">
            <div class="sl-title">Dry run</div>
            <div class="sl-desc">Detect and alert but never contain. Turn this off only once you trust the thresholds.</div>
          </div>
          <label class="switch"><input type="checkbox" id="an-dry-run" ${s.dryRun !== false ? 'checked' : ''}/><span class="slider"></span></label>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('userCheck')}</span> Trusted staff</span></div>
        <p class="card-desc">Anyone listed here bypasses Anti-Nuke entirely. The server owner always does.</p>
        <div class="field">
          <label class="field-label">Trusted roles</label>
          <div class="rr-list" id="an-trusted-roles"></div>
        </div>
      </div>
    </div>`;

    // Developer/owner-role viewers bypass the upcoming gate (guild._bypassUpcoming,
    // set by requireGuildAdminPage): render the real editor so the feature can be
    // exercised, mirroring eventsPage.
    const panelHTML = guild._bypassUpcoming
        ? innerPanelHTML
        : upcomingOverlayWrap(innerPanelHTML);

    const body = `
    ${require('./guild').guildHeaderHTML(guild)}
    ${require('./guild').tabNavHTML(guild.id, 'antinuke')}
    ${panelHTML}
    ${require('./guild').guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: { _antiNukeSettings: s } })}
    <script>window.__ANTINUKE_ACTIONS=${jsonForScript(ANTINUKE_ACTIONS)};
window.__ANTINUKE_RESPONSES=${jsonForScript(ANTINUKE_RESPONSES)};
window.__ANTINUKE_SETTINGS=${jsonForScript(s)};</script>`;

    return { body, scripts: ['/js/guild-common.js', '/js/antinuke.js'], title: `PrimeBot · ${guild.name} · Anti-Nuke` };
}

// Re-use the shared overlay helper so Anti-Nuke matches the Events tab exactly.
const { upcomingOverlayWrap } = require('./guild-pages');

module.exports = { antiNukePageHTML, watchCardHTML };