/**
 * Invite Tracking page (/guild/:guildId/invites).
 *
 * Server-rendered: the overview arrives with the HTML, so the page is useful
 * before any JS runs. The client script only refreshes, paginates and saves
 * configuration. Uses the same visual language as the AutoMod console
 * (hero + stat cards + section cards), no decorative side bars.
 */

const { esc, svgIcon, channelOptions } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');

const SUPPORT_URL = 'https://discord.gg/gd7UNSfX86';

function fmtWhen(iso) {
    if (!iso) return '—';
    const ms = new Date(iso).getTime();
    if (!Number.isFinite(ms)) return '—';
    return `<t:${Math.floor(ms / 1000)}:R>`;
}

function statusPill(enabled) {
    return `<span class="iv-pill ${enabled ? 'iv-pill-on' : 'iv-pill-off'}">${svgIcon(enabled ? 'check' : 'ban')} ${enabled ? 'Tracking enabled' : 'Tracking disabled'}</span>`;
}

function attributionBadge(join) {
    if (join.attribution === 'exact') return '<span class="iv-badge iv-badge-good">Attributed</span>';
    if (join.attribution === 'ambiguous') return '<span class="iv-badge iv-badge-warn">Ambiguous</span>';
    if (join.source === 'vanity') return '<span class="iv-badge iv-badge-info">Vanity (probable)</span>';
    if (join.source === 'bot') return '<span class="iv-badge">Bot</span>';
    return '<span class="iv-badge iv-badge-muted">Unknown</span>';
}

function inviterCell(join) {
    if (join.inviterId) return `<a href="#" class="iv-member" data-invite-member="${esc(join.inviterId)}">&lt;@${esc(join.inviterId)}&gt;</a>`;
    return '<span class="iv-muted">Unknown</span>';
}

function leaderboardRows(rows) {
    if (!rows || !rows.length) {
        return `<tr><td colspan="6" class="iv-empty">${svgIcon('users')} No invites tracked yet. Invite someone and their join appears here.</td></tr>`;
    }
    const max = Math.max(...rows.map(r => Math.max(r.net, 0)), 1);
    return rows.map((r, i) => {
        const pct = Math.max(2, Math.round((Math.max(r.net, 0) / max) * 100));
        return `
        <tr>
          <td class="iv-rank">${i + 1}</td>
          <td><a href="#" class="iv-member" data-invite-member="${esc(r.userId)}">&lt;@${esc(r.userId)}&gt;</a></td>
          <td class="iv-num">${r.joins}</td>
          <td class="iv-num">${r.leaves}</td>
          <td class="iv-num iv-net">${r.net}<div class="iv-bar"><div class="iv-bar-fill" style="width:${pct}%"></div></div></td>
          <td class="iv-num">${r.activeInvites || 0}</td>
        </tr>`;
    }).join('');
}

function joinRows(joins) {
    if (!joins || !joins.length) {
        return `<tr><td colspan="4" class="iv-empty">${svgIcon('userPlus')} No joins recorded yet.</td></tr>`;
    }
    return joins.map(j => `
        <tr>
          <td><span class="iv-member-static">&lt;@${esc(j.userId)}&gt;</span></td>
          <td>${inviterCell(j)}</td>
          <td>${attributionBadge(j)}${j.inviteCode ? ` <code class="iv-code">${esc(j.inviteCode)}</code>` : ''}</td>
          <td class="iv-when">${fmtWhen(j.joinedAt)}</td>
        </tr>`).join('');
}

function activityRows(activity) {
    if (!activity || !activity.length) {
        return `<li class="iv-activity-empty">${svgIcon('activity')} No activity yet.</li>`;
    }
    const iconFor = (type) => type === 'join' ? 'userPlus' : type === 'leave' ? 'userX' : type === 'reset' ? 'trash' : type === 'config' ? 'settings' : 'link';
    return activity.slice(0, 20).map(a => `
        <li class="iv-activity-row">
          <span class="iv-activity-ico iv-activity-${esc(a.type)}">${svgIcon(iconFor(a.type))}</span>
          <span class="iv-activity-body">
            <span class="iv-activity-title">${esc(String(a.type || '').replace(/_/g, ' '))}</span>
            <span class="iv-activity-detail">${a.userId ? `&lt;@${esc(a.userId)}&gt;` : ''}${a.detail ? ` · ${esc(a.detail)}` : ''}</span>
          </span>
          <span class="iv-activity-when">${fmtWhen(a.createdAt)}</span>
        </li>`).join('');
}

function diagnosticsHTML(diag) {
    if (!diag) {
        return `<p class="iv-muted">Diagnostics unavailable — the dashboard could not query the bot's permissions.</p>`;
    }
    if (diag.ok) {
        return `<p class="iv-diag iv-diag-ok">${svgIcon('check')} The bot can read invites (Manage Server) — attribution is active.</p>`;
    }
    return `<p class="iv-diag iv-diag-warn">${svgIcon('ban')} The bot is missing <strong>Manage Server</strong>, so it cannot read invite usage. Joins are recorded with an <strong>Unknown</strong> inviter until this is granted.</p>`;
}

function invitesPage({ guild, user }) {
    const cfg = guild._config || {};
    const data = cfg.invites || {};
    const settings = data.settings || {};
    const totals = data.totals || {};
    const rows = data.leaderboard || [];
    const total = data.total || 0;
    const joins = data.recentJoins || [];
    const activity = data.activity || [];
    const diag = data.diagnostics || null;

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'invites')}
    <div class="iv-page" id="iv-page" data-guild-id="${esc(guild.id)}">
      <section class="iv-hero">
        <div class="iv-hero-main">
          <div class="iv-hero-icon">${svgIcon('userPlus')}</div>
          <div>
            <h2 class="iv-hero-title">Invite Tracking</h2>
            <p class="iv-hero-sub">See who is bringing members to your server — joins, leaves, net invites and a live leaderboard.</p>
            <div class="iv-hero-pills">
              <span class="iv-pill iv-pill-premium">${svgIcon('rocket')} Free for every server</span>
              <span class="iv-pill">${svgIcon('shieldCheck')} Unknown is never guessed</span>
            </div>
          </div>
        </div>
        <div class="iv-hero-actions">
          <button class="btn btn-secondary" id="iv-refresh" type="button">${svgIcon('refresh')} Refresh</button>
          <a class="btn btn-primary" href="#iv-config">${svgIcon('settings')} Configure</a>
        </div>
      </section>

      <section class="iv-stats" id="iv-stats">
        <div class="iv-stat"><div class="iv-stat-num" data-iv="totalJoins">${totals.totalJoins || 0}</div><div class="iv-stat-label">${svgIcon('userPlus')} Tracked joins</div></div>
        <div class="iv-stat"><div class="iv-stat-num" data-iv="totalLeaves">${totals.totalLeaves || 0}</div><div class="iv-stat-label">${svgIcon('userX')} Departed</div></div>
        <div class="iv-stat"><div class="iv-stat-num" data-iv="net">${totals.net || 0}</div><div class="iv-stat-label">${svgIcon('activity')} Net invites</div></div>
        <div class="iv-stat"><div class="iv-stat-num" data-iv="joins24h">${totals.joins24h || 0}</div><div class="iv-stat-label">${svgIcon('clock')} Joins (24h)</div></div>
        <div class="iv-stat"><div class="iv-stat-num" data-iv="uniqueInviters">${totals.uniqueInviters || 0}</div><div class="iv-stat-label">${svgIcon('users')} Inviters</div></div>
        <div class="iv-stat"><div class="iv-stat-num" data-iv="unknownJoins">${totals.unknownJoins || 0}</div><div class="iv-stat-label">${svgIcon('info')} Unknown</div></div>
      </section>

      <div class="iv-grid">
        <section class="iv-card iv-card-wide">
          <div class="iv-card-head">
            <h3>${svgIcon('trophy')} Top inviters</h3>
            <span class="iv-muted" id="iv-total">${total} tracked</span>
          </div>
          <div class="iv-table-wrap">
            <table class="iv-table" id="iv-leaderboard">
              <thead><tr><th>#</th><th>Member</th><th>Joins</th><th>Left</th><th>Net</th><th>Active</th></tr></thead>
              <tbody>${leaderboardRows(rows)}</tbody>
            </table>
          </div>
          <div class="iv-pager">
            <button class="btn btn-secondary" id="iv-prev" type="button" disabled>${svgIcon('arrowLeft')} Prev</button>
            <span class="iv-muted" id="iv-page-label">Page 1 / ${Math.max(1, Math.ceil(total / 10))}</span>
            <button class="btn btn-secondary" id="iv-next" type="button" ${total > 10 ? '' : 'disabled'}>Next ${svgIcon('arrowRight')}</button>
          </div>
        </section>

        <section class="iv-card">
          <div class="iv-card-head"><h3>${svgIcon('shieldCheck')} Tracking status</h3></div>
          <div class="iv-status" id="iv-status">
            ${statusPill(settings.enabled !== false)}
            <ul class="iv-status-list">
              <li><span>Log channel</span><strong>${settings.logChannelId ? `<#${esc(settings.logChannelId)}>` : 'Not set'}</strong></li>
              <li><span>Join notifications</span><strong>${settings.joinNotifications ? 'On' : 'Off'}</strong></li>
              <li><span>Leave notifications</span><strong>${settings.leaveNotifications ? 'On' : 'Off'}</strong></li>
              <li><span>Vanity detection</span><strong>${settings.vanityTracking !== false ? 'On' : 'Off'}</strong></li>
              <li><span>Exclude bots</span><strong>${settings.excludeBots !== false ? 'Yes' : 'No'}</strong></li>
              <li><span>Excluded members</span><strong>${(settings.excludedUserIds || []).length}</strong></li>
            </ul>
          </div>
          <div class="iv-diag-wrap" id="iv-diagnostics">${diagnosticsHTML(diag)}</div>
        </section>
      </div>

      <div class="iv-grid">
        <section class="iv-card iv-card-wide">
          <div class="iv-card-head"><h3>${svgIcon('clock')} Recent joins</h3></div>
          <div class="iv-table-wrap">
            <table class="iv-table" id="iv-joins">
              <thead><tr><th>Member</th><th>Invited by</th><th>Attribution</th><th>When</th></tr></thead>
              <tbody>${joinRows(joins)}</tbody>
            </table>
          </div>
        </section>

        <section class="iv-card">
          <div class="iv-card-head"><h3>${svgIcon('activity')} Activity</h3></div>
          <ul class="iv-activity" id="iv-activity">${activityRows(activity)}</ul>
        </section>
      </div>

      <section class="iv-card" id="iv-config">
        <div class="iv-card-head"><h3>${svgIcon('settings')} Configuration</h3></div>
        <p class="iv-muted">Changes save through the floating Save bar and take effect in the bot within seconds.</p>
        <div class="iv-form-grid">
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Enable invite tracking</div><div class="sl-desc">When off, no joins or leaves are recorded.</div></div>
            <label class="switch"><input type="checkbox" id="iv-enabled" ${settings.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Join notifications</div><div class="sl-desc">Post a card in the log channel when a member joins.</div></div>
            <label class="switch"><input type="checkbox" id="iv-join-notify" ${settings.joinNotifications ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Leave notifications</div><div class="sl-desc">Post a card when an invited member leaves.</div></div>
            <label class="switch"><input type="checkbox" id="iv-leave-notify" ${settings.leaveNotifications ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Vanity URL detection</div><div class="sl-desc">Mark a join as a possible vanity join when no invite counter changed.</div></div>
            <label class="switch"><input type="checkbox" id="iv-vanity" ${settings.vanityTracking !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Exclude bots</div><div class="sl-desc">Bot joins are recorded separately and never counted in statistics.</div></div>
            <label class="switch"><input type="checkbox" id="iv-exclude-bots" ${settings.excludeBots !== false ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
          <div class="field">
            <label class="field-label" for="iv-log-channel">Log channel</label>
            <select id="iv-log-channel" data-channel-select>${channelOptions(guild._channels, settings.logChannelId)}</select>
            <div class="field-hint">Where join/leave notifications are posted.</div>
          </div>
          <div class="field iv-field-wide">
            <label class="field-label" for="iv-excluded">Excluded member IDs</label>
            <input type="text" id="iv-excluded" value="${esc((settings.excludedUserIds || []).join(', '))}" placeholder="123456789012345678, 987654321098765432" />
            <div class="field-hint">Comma-separated user IDs whose joins/leaves are not counted.</div>
          </div>
        </div>
      </section>

      <section class="iv-card iv-danger">
        <div class="iv-card-head"><h3>${svgIcon('trash')} Reset statistics</h3></div>
        <p class="iv-muted">Permanently clears every recorded join and inviter counter for this server. Live invite snapshots are preserved, so attribution keeps working immediately.</p>
        <div class="iv-danger-actions">
          <input type="text" id="iv-reset-confirm" placeholder="Type RESET to confirm" />
          <button class="btn btn-danger" id="iv-reset" type="button" disabled>${svgIcon('trash')} Reset statistics</button>
        </div>
      </section>

      <p class="iv-foot">Need help? <a href="${SUPPORT_URL}" target="_blank" rel="noopener">Join the support server</a>.</p>
    </div>
    ${guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles })}`;

    return {
        body,
        scripts: ['/js/guild-common.js', '/js/invites.js'],
        title: `PrimeBot · ${guild.name} · Invite Tracking`,
    };
}

module.exports = { invitesPage };
