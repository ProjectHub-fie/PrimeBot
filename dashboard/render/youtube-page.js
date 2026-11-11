/**
 * YouTube Notifications (Creator Hub) dashboard page.
 *
 * Server-rendered, sectioned page (same design language as the AutoMod/AntiNuke
 * consoles): Overview / Creators / Announcement / History / Health. Every
 * control is real markup in the initial HTML so the page is usable before JS
 * runs; dashboard/public/js/youtube.js only adds interactivity (add/remove,
 * enable/pause, the embed-template editor, test, history refresh).
 *
 * This feature is DASHBOARD-ONLY: the bot never writes subscriptions and the
 * `/youtube` command just points users here (mirrors the Tickets pattern).
 *
 * Data comes from `guild._config.youtubeSubscriptions` /
 * `youtubeAnnouncements` / `youtubeStats` (assembled by dashboard/db.js
 * getGuildConfig), so the page renders without an extra round-trip.
 */

const { esc, channelOptions, roleOptions, svgIcon, jsonForScript } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');
const { DEFAULT_TEMPLATE, normalizeTemplate } = require('../../shared/youtubeConstants');

const SECTIONS = [
    { key: 'overview', label: 'Overview',     icon: 'activity' },
    { key: 'creators', label: 'Creators',     icon: 'users' },
    { key: 'template', label: 'Announcement', icon: 'message' },
    { key: 'history',  label: 'History',      icon: 'history' },
    { key: 'health',   label: 'Health',       icon: 'heart' },
];

function fmtDate(value) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function statusPill(sub) {
    if (!sub.enabled) return `<span class="yt-pill yt-pill-off">Disabled</span>`;
    if (sub.paused) return `<span class="yt-pill yt-pill-pause">${svgIcon('pauseCircle')} Paused</span>`;
    if (sub.lastError) return `<span class="yt-pill yt-pill-err">${svgIcon('alertTriangle')} Error</span>`;
    if (!sub.baselineDone) return `<span class="yt-pill yt-pill-base">${svgIcon('clock')} Baselining</span>`;
    return `<span class="yt-pill yt-pill-on">${svgIcon('check')} Active</span>`;
}

function sectionNav(active) {
    return `<div class="yt-sections" id="yt-sections">${SECTIONS.map((s) =>
        `<button type="button" class="yt-section-btn${s.key === active ? ' active' : ''}" data-section="${s.key}">${svgIcon(s.icon)}<span>${esc(s.label)}</span></button>`
    ).join('')}</div>`;
}

function statCard(icon, label, value, id) {
    return `<div class="yt-stat"><div class="yt-stat-ico">${svgIcon(icon)}</div>
      <div class="yt-stat-body"><div class="yt-stat-value" id="${esc(id)}">${esc(String(value))}</div>
      <div class="yt-stat-label">${esc(label)}</div></div></div>`;
}

function overviewSection(stats) {
    return `<section class="yt-section" data-section="overview">
      <div class="yt-stats-grid">
        ${statCard('youtube', 'Subscribed creators', stats.totalSubscriptions, 'yt-stat-total')}
        ${statCard('bell', 'Active monitors', stats.activeSubscriptions, 'yt-stat-active')}
        ${statCard('rss', 'Announcements sent', stats.announcementsSent, 'yt-stat-sent')}
        ${statCard('alertTriangle', 'Failed announcements', stats.announcementsFailed, 'yt-stat-failed')}
      </div>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('activity')}</span> Monitoring status</span></div>
        <p class="card-desc">PrimeBot polls each creator's public YouTube RSS feed (no API key required) and announces new uploads in the channel you choose. Only one shard node polls at a time, and every announcement is de-duplicated in the database — so a video is never posted twice, even across restarts.</p>
        <div class="yt-kv">
          <div><span class="yt-kv-label">Last successful check</span><span class="yt-kv-value" id="yt-stat-lastcheck">${esc(fmtDate(stats.lastSuccessAt))}</span></div>
          <div><span class="yt-kv-label">Paused creators</span><span class="yt-kv-value" id="yt-stat-paused">${esc(String(stats.pausedSubscriptions))}</span></div>
          <div><span class="yt-kv-label">Creators with errors</span><span class="yt-kv-value" id="yt-stat-errored">${esc(String(stats.erroredSubscriptions))}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('plus')}</span> Add a YouTube creator</span></div>
        <p class="card-desc">Paste a channel URL (<code>youtube.com/channel/…</code> or <code>youtube.com/@handle</code>), a channel ID (<code>UC…</code>), or an <code>@handle</code>. PrimeBot resolves it to the stable channel ID and starts monitoring new uploads — existing videos are never announced.</p>
        <div class="yt-add-row">
          <input type="text" id="yt-add-input" placeholder="https://www.youtube.com/@handle  ·  @handle  ·  UCX6OQ3DkcsbYNE6H8uQQuVA" autocomplete="off" />
          <select id="yt-add-channel" data-channel-select>${channelOptions([], null)}</select>
          <input type="text" id="yt-add-group" placeholder="Group (optional)" autocomplete="off" />
          <button class="btn btn-primary" id="yt-add-btn" type="button">${svgIcon('plus')} Add creator</button>
        </div>
        <div class="field-hint" id="yt-add-hint">Choose the Discord channel where announcements for this creator are posted. You can change it per creator afterwards.</div>
      </div>
    </section>`;
}

function creatorCardHTML(sub) {
    const tpl = normalizeTemplate(sub.template || {});
    const avatar = sub.avatarUrl
        ? `<img class="yt-avatar" src="${esc(sub.avatarUrl)}" alt="" onerror="this.style.display='none'"/>`
        : `<span class="yt-avatar yt-avatar-fallback">${esc((sub.channelName || '?')[0].toUpperCase())}</span>`;
    return `<div class="yt-creator card" data-id="${esc(String(sub.id))}">
      <div class="yt-creator-head">
        ${avatar}
        <div class="yt-creator-info">
          <div class="yt-creator-name">${esc(sub.channelName || sub.youtubeChannelId)}</div>
          <div class="yt-creator-meta">
            <a href="${esc(sub.channelUrl || `https://www.youtube.com/channel/${sub.youtubeChannelId}`)}" target="_blank" rel="noopener">${esc(sub.youtubeChannelId)}</a>
            ${sub.groupName ? ` · <span class="yt-group">${esc(sub.groupName)}</span>` : ''}
          </div>
          <div class="yt-creator-status">${statusPill(sub)}
            <span class="yt-creator-chan">${sub.discordChannelId ? `#${esc(sub.discordChannelId)}` : 'no channel set'}</span>
          </div>
        </div>
        <div class="yt-creator-actions">
          <button class="btn btn-sm" data-act="test" title="Send a test announcement">${svgIcon('bell')} Test</button>
          <button class="btn btn-sm" data-act="edit" title="Edit announcement">${svgIcon('pencil')} Edit</button>
          <button class="btn btn-sm" data-act="pause" title="${sub.paused ? 'Resume' : 'Pause'} monitoring">${svgIcon(sub.paused ? 'playCircle' : 'pauseCircle')} ${sub.paused ? 'Resume' : 'Pause'}</button>
          <button class="btn btn-sm" data-act="toggle" title="${sub.enabled ? 'Disable' : 'Enable'}">${svgIcon(sub.enabled ? 'eyeOff' : 'eye')} ${sub.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-danger" data-act="remove" title="Remove">${svgIcon('trash')} Remove</button>
        </div>
      </div>
      <div class="yt-creator-sub">
        <span>Last check: <b>${esc(fmtDate(sub.lastCheckedAt))}</b></span>
        <span>Last success: <b>${esc(fmtDate(sub.lastSuccessAt))}</b></span>
        <span>Last video: <b>${esc(sub.lastVideoId || '—')}</b></span>
        ${sub.lastError ? `<span class="yt-err">Last error: ${esc(sub.lastError)}</span>` : ''}
      </div>
      <script type="application/json" class="yt-sub-data">${jsonForScript(sub)}</script>
      <script type="application/json" class="yt-tpl-data">${jsonForScript(tpl)}</script>
    </div>`;
}

function creatorsSection(subs) {
    const list = subs.length
        ? subs.map(creatorCardHTML).join('')
        : `<div class="yt-empty" id="yt-empty">${svgIcon('youtube')}<p>No creators subscribed yet. Use <b>Add a YouTube creator</b> on the Overview section to get started.</p></div>`;
    return `<section class="yt-section" data-section="creators" hidden>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('users')}</span> Subscribed creators</span>
          <span class="card-title-actions"><input type="text" id="yt-search" placeholder="Filter creators…" /><button class="btn btn-sm" id="yt-refresh" type="button">${svgIcon('refresh')} Refresh</button></span>
        </div>
        <div id="yt-creators">${list}</div>
      </div>
    </section>`;
}

// The announcement editor is rendered once and re-used for whichever creator is
// being edited (its values are populated client-side from the card's data blob).
function templateSection() {
    const t = DEFAULT_TEMPLATE;
    const field = (id, label, value, hint, tag = 'input') => `
      <div class="field">
        <label class="field-label" for="${id}">${esc(label)}</label>
        ${tag === 'textarea'
            ? `<textarea id="${id}" rows="3" placeholder="${esc(hint)}">${esc(value)}</textarea>`
            : `<input type="text" id="${id}" value="${esc(value)}" placeholder="${esc(hint)}" />`}
        <div class="field-hint">${esc(hint)}</div>
      </div>`;
    return `<section class="yt-section" data-section="template" hidden>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('message')}</span> Announcement customization</span></div>
        <p class="card-desc">Customize the announcement embed for each creator. Placeholders: <code>{creator}</code>, <code>{videoTitle}</code>, <code>{videoUrl}</code>, <code>{channel}</code>, <code>{server}</code>. Leave a field blank to use the built-in professional default.</p>
        <div id="yt-template-editor" class="yt-template-editor">
          <div class="yt-template-empty" id="yt-template-empty">${svgIcon('pencil')}<p>Select a creator's <b>Edit</b> button to customize its announcement, or pick one below.</p>
            <select id="yt-template-picker"><option value="">— Choose a creator —</option></select></div>
          <div id="yt-template-form" hidden>
            <div class="yt-template-target">Editing: <b id="yt-template-name">—</b></div>
            ${field('yt-tpl-title', 'Announcement title', t.title, 'Shown as the embed title')}
            ${field('yt-tpl-description', 'Embed description', t.description, 'Main body text of the embed', 'textarea')}
            ${field('yt-tpl-message', 'Custom message', t.message, 'Optional plain-text line above the embed')}
            ${field('yt-tpl-footer', 'Footer text', t.footer, 'Small text at the bottom of the embed')}
            <div class="field">
              <label class="field-label" for="yt-tpl-color">Embed color</label>
              <div class="color-field"><input type="color" id="yt-tpl-color" value="${esc(t.color)}" /><input type="text" id="yt-tpl-color-text" value="${esc(t.color)}" /></div>
            </div>
            <div class="field">
              <label class="field-label" for="yt-tpl-role">Mention role (optional)</label>
              <select id="yt-tpl-role" data-role-select data-placeholder="— No role mention —">${roleOptions([], t.mentionRoleId)}</select>
              <div class="field-hint">When set, this role is pinged on each announcement. @everyone/@here are never enabled unless you opt in below.</div>
            </div>
            <div class="yt-switches">
              <label class="switch mini"><input type="checkbox" id="yt-tpl-showcreator" ${t.showCreator ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">Show creator (author line + avatar)</span></label>
              <label class="switch mini"><input type="checkbox" id="yt-tpl-showthumb" ${t.showThumbnail ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">Show video thumbnail</span></label>
              <label class="switch mini"><input type="checkbox" id="yt-tpl-showtime" ${t.showTimestamp ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">Show upload timestamp</span></label>
              <label class="switch mini"><input type="checkbox" id="yt-tpl-showurl" ${t.showVideoUrl ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">Show “Watch now” link field</span></label>
              <label class="switch mini"><input type="checkbox" id="yt-tpl-mentioneveryone" ${t.contentMentions ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">Allow @everyone mention (advanced)</span></label>
            </div>
            <div class="yt-template-actions">
              <button class="btn btn-sm" id="yt-tpl-reset" type="button">${svgIcon('refresh')} Reset to default</button>
              <button class="btn btn-primary" id="yt-tpl-save" type="button">${svgIcon('save')} Save announcement</button>
            </div>
          </div>
        </div>
      </div>
    </section>`;
}

function historySection(announcements) {
    const rows = announcements.length ? announcements.map((a) => `
      <tr>
        <td><a href="${esc(a.videoUrl || '#')}" target="_blank" rel="noopener">${esc((a.videoTitle || a.videoId).slice(0, 60))}</a></td>
        <td>${esc(a.youtubeChannelId)}</td>
        <td><span class="yt-pill yt-pill-${a.status === 'sent' ? 'on' : (a.status === 'failed' ? 'err' : 'pause')}">${esc(a.status)}</span></td>
        <td>${esc(fmtDate(a.createdAt))}</td>
      </tr>`).join('') : `<tr><td colspan="4" class="yt-empty-cell">No announcements yet.</td></tr>`;
    return `<section class="yt-section" data-section="history" hidden>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('history')}</span> Recent announcements</span>
          <span class="card-title-actions"><button class="btn btn-sm" id="yt-history-refresh" type="button">${svgIcon('refresh')} Refresh</button></span></div>
        <div class="yt-table-wrap"><table class="yt-table">
          <thead><tr><th>Video</th><th>YouTube channel</th><th>Status</th><th>When</th></tr></thead>
          <tbody id="yt-history-body">${rows}</tbody>
        </table></div>
      </div>
    </section>`;
}

function healthSection(subs) {
    const rows = subs.length ? subs.map((s) => `
      <tr>
        <td>${esc(s.channelName || s.youtubeChannelId)}</td>
        <td>${statusPill(s)}</td>
        <td>${esc(fmtDate(s.lastCheckedAt))}</td>
        <td>${esc(fmtDate(s.lastSuccessAt))}</td>
        <td>${s.errorCount ? `<span class="yt-err">${esc(String(s.errorCount))}×</span>` : '0'}</td>
        <td>${s.lastError ? `<span class="yt-err" title="${esc(s.lastError)}">${esc(s.lastError.slice(0, 60))}</span>` : '—'}</td>
      </tr>`).join('') : `<tr><td colspan="6" class="yt-empty-cell">No creators subscribed.</td></tr>`;
    return `<section class="yt-section" data-section="health" hidden>
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('heart')}</span> Monitoring health</span></div>
        <p class="card-desc">Per-creator check status. Failures back off exponentially and retry automatically; one broken creator never stops the others.</p>
        <div class="yt-table-wrap"><table class="yt-table">
          <thead><tr><th>Creator</th><th>Status</th><th>Last check</th><th>Last success</th><th>Errors</th><th>Last error</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </div>
    </section>`;
}

function youtubePageHTML({ guild, user }) {
    const cfg = guild._config || {};
    const subs = Array.isArray(cfg.youtubeSubscriptions) ? cfg.youtubeSubscriptions : [];
    const announcements = Array.isArray(cfg.youtubeAnnouncements) ? cfg.youtubeAnnouncements : [];
    const stats = cfg.youtubeStats || {
        totalSubscriptions: subs.length, activeSubscriptions: subs.filter(s => s.enabled && !s.paused).length,
        pausedSubscriptions: subs.filter(s => s.paused).length, erroredSubscriptions: subs.filter(s => s.lastError).length,
        announcementsSent: announcements.filter(a => a.status === 'sent').length,
        announcementsFailed: announcements.filter(a => a.status === 'failed').length, lastSuccessAt: null,
    };

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'youtube')}
    <div class="card yt-hero">
      <div class="card-title"><span><span class="icon">${svgIcon('youtube')}</span> YouTube Notifications</span>
        <span class="embed-builder-badge">${svgIcon('sparkles')} Free feature</span></div>
      <p class="card-desc">Announce new YouTube uploads automatically. Subscribe to any public creator — no API key, no login. Configure everything here; the bot does the posting.</p>
    </div>
    ${sectionNav('overview')}
    ${overviewSection(stats)}
    ${creatorsSection(subs)}
    ${templateSection()}
    ${historySection(announcements)}
    ${healthSection(subs)}
    <div id="yt-modal" class="modal-overlay hidden"></div>
    ${guildDataScript({ guildId: guild.id, channels: guild._channels || [], roles: guild._roles || [] })}`;

    return {
        body,
        scripts: ['/js/guild-common.js', '/js/youtube.js'],
        title: `PrimeBot · ${guild.name} · YouTube`,
    };
}

module.exports = { youtubePageHTML, SECTIONS };
