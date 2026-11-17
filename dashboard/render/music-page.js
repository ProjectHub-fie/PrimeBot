/**
 * Music dashboard page.
 *
 * Server-rendered, sectioned page (same design language as the AutoMod /
 * YouTube / Radio consoles): Overview / Playlists / History / 24/7.
 *
 * The bot's MusicManager owns the live player; this page reads the persisted
 * music settings, playlists and history and lets administrators enable the
 * persistent 24/7 connection, pick the voice channel, set the DJ role and the
 * default volume. Data comes from `guild._config.musicSettings` /
 * `musicPlaylists` / `musicHistory` so the page renders without an extra fetch.
 * dashboard/public/js/music.js only adds interactivity.
 */

const { esc, svgIcon } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');

const SECTIONS = [
    { key: 'overview', label: 'Overview', icon: 'activity' },
    { key: 'playlists', label: 'Playlists', icon: 'list' },
    { key: 'history', label: 'History', icon: 'clock' },
    { key: '247', label: '24/7', icon: 'radio' },
];

function sectionNav(active, extra = []) {
    const all = SECTIONS.concat(extra);
    return `<div class="rd-sections" id="mu-sections">${all.map(s =>
        `<button type="button" class="rd-section-btn${s.key === active ? ' active' : ''}" data-section="${s.key}">${svgIcon(s.icon)}<span>${esc(s.label)}</span></button>`
    ).join('')}</div>`;
}

function statCard(icon, label, value, id) {
    return `<div class="rd-stat"><div class="rd-stat-ico">${svgIcon(icon)}</div>
      <div class="rd-stat-body"><div class="rd-stat-value" id="${esc(id)}">${esc(String(value))}</div>
      <div class="rd-stat-label">${esc(label)}</div></div></div>`;
}

function channelOptions(channels, selected) {
    const list = (channels || []).filter(c => c.type === 2 || c.type === 13 || c.voice || c.isVoice);
    if (!list.length) return '<option value="">No voice channels found</option>';
    return list.map(c => `<option value="${esc(c.id)}"${String(c.id) === String(selected) ? ' selected' : ''}>${esc(c.name)}</option>`).join('');
}

function roleOptions(roles, selected) {
    const list = (roles || []).filter(r => !r.managed);
    const opts = ['<option value="">— None —</option>'].concat(
        list.map(r => `<option value="${esc(r.id)}"${String(r.id) === String(selected) ? ' selected' : ''}>${esc(r.name)}</option>`),
    );
    return opts.join('');
}

function overviewSection(settings, history) {
    const st = settings || {};
    // Which playback engine this deployment uses (env-derived; the dashboard
    // holds no live player). Labelled honestly so an operator can see at a
    // glance whether Lavalink is active.
    let engineLabel = 'Direct (local ffmpeg)';
    try {
        const { resolveEngineName } = require('../../utils/music/engines');
        engineLabel = resolveEngineName() === 'lavalink' ? 'Lavalink' : 'Direct (local ffmpeg)';
    } catch (_) { /* keep the default label */ }
    const last = history && history[0];
    const lastLine = last ? `${esc(last.title || 'Unknown')}${last.artist ? ` — ${esc(last.artist)}` : ''}` : '—';
    return `<section class="rd-section" data-section="overview">
      <div class="rd-stats-grid">
        ${statCard('radio', '24/7 mode', st.twentyFourSevenEnabled ? 'Enabled' : 'Disabled', 'mu-stat-247')}
        ${statCard('volume', 'Default volume', (st.defaultVolume != null ? st.defaultVolume : 100) + '%', 'mu-stat-volume')}
        ${statCard('list', 'Playlists', (st.playlistCount != null ? st.playlistCount : 0), 'mu-stat-playlists')}
        ${statCard('clock', 'Tracks played', history ? history.length : 0, 'mu-stat-history')}
      </div>
      <div class="rd-hero" id="mu-hero">
        <div class="rd-hero-head">
          <span class="rd-hero-ico">${svgIcon('music')}</span>
          <div>
            <div class="rd-hero-title">Last played</div>
            <div class="rd-hero-track" id="mu-last-track">${lastLine}</div>
          </div>
          <span id="mu-state-pill" class="rd-pill ${st.twentyFourSevenEnabled ? 'rd-pill-play' : 'rd-pill-off'}">${st.twentyFourSevenEnabled ? '24/7' : 'On demand'}</span>
        </div>
        <div class="rd-hero-meta">
          <span>Channel: <strong id="mu-channel-label">${st.twentyFourSevenChannelId ? `<#${st.twentyFourSevenChannelId}>` : '—'}</strong></span>
          <span>DJ role: <strong id="mu-dj-label">${st.djRoleId ? `<@&${st.djRoleId}>` : '—'}</strong></span>
          <span>Node: <strong id="mu-node-label">${esc(st.ownerNode || '—')}</strong></span>
          <span>Engine: <strong id="mu-engine-label">${esc(engineLabel)}</strong></span>
        </div>
      </div>
      <p class="card-desc">PrimeBot plays on demand from YouTube, SoundCloud, Spotify (matched to a streamable source) and direct audio URLs. With 24/7 enabled it stays connected to the voice channel with an empty queue and nobody listening — playback state is independent of the connection, so pausing, stopping or an empty queue never disconnects. Requesters control their own tracks; DJ role holders and admins manage the whole queue.</p>
    </section>`;
}

function playlistsSection(playlists) {
    const rows = (playlists || []).map(p => `
      <div class="rd-station-card" data-id="${esc(p.id)}">
        <div class="rd-station-head">
          <span class="rd-station-name">${esc(p.name)}</span>
          <span class="rd-pill ${p.isPublic ? 'rd-pill-play' : 'rd-pill-off'}">${p.isPublic ? 'Public' : 'Personal'}</span>
          <span class="rd-chip">${p.trackCount != null ? p.trackCount : 0} tracks</span>
        </div>
        <div class="rd-station-desc">${esc(p.description || '')}</div>
        <div class="rd-station-meta">
          ${p.ownerId ? `<span class="rd-chip">Owner <@${esc(p.ownerId)}></span>` : ''}
        </div>
        <div class="rd-station-actions">
          <button type="button" class="btn btn-secondary btn-sm mu-playlist-view" data-id="${esc(p.id)}">View</button>
          <button type="button" class="btn btn-danger btn-sm mu-playlist-delete" data-id="${esc(p.id)}">Delete</button>
        </div>
      </div>`).join('') || '<p class="card-desc">No playlists yet. Create one in Discord with <code>/playlist create</code> or <code>$music playlist create &lt;name&gt;</code>.</p>';

    return `<section class="rd-section" data-section="playlists">
      <div class="card">
        <div class="card-title"><span>${svgIcon('list')} Playlists</span></div>
        <p class="card-desc">Public playlists are shared with everyone; personal playlists are owner-only. Playlists are created and edited from Discord (the bot owns the resolver).</p>
        <div class="rd-stations" id="mu-playlists">${rows}</div>
      </div>
      <div id="mu-playlist-modal" class="modal-overlay hidden"></div>
      <template id="mu-playlist-template">
        <div class="modal floating-window">
          <div class="modal-head"><h3 id="mu-pl-title">Playlist</h3><button type="button" class="modal-close" data-close>&times;</button></div>
          <div class="modal-body"><div id="mu-pl-body" class="card-desc">Loading…</div></div>
        </div>
      </template>
    </section>`;
}

function historySection(history) {
    const rows = (history || []).map(h => `
      <tr>
        <td>${esc(h.title || 'Unknown')}</td>
        <td>${esc(h.artist || '—')}</td>
        <td>${esc(h.provider || '—')}</td>
        <td>${h.requesterId ? `<@${esc(h.requesterId)}>` : '—'}</td>
        <td>${h.playedAt ? esc(new Date(h.playedAt).toISOString().replace('T', ' ').slice(0, 16)) : '—'}</td>
      </tr>`).join('') || '<tr><td colspan="5">No tracks played yet.</td></tr>';
    return `<section class="rd-section" data-section="history">
      <div class="card">
        <div class="card-title"><span>${svgIcon('clock')} Recently played</span></div>
        <table class="mu-table">
          <thead><tr><th>Title</th><th>Artist</th><th>Source</th><th>Requester</th><th>Played</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>`;
}

function twentyFourSevenSection(settings, channels, roles) {
    const st = settings || {};
    return `<section class="rd-section" data-section="247">
      <div class="card">
        <div class="card-title"><span>${svgIcon('radio')} Persistent 24/7 connection</span></div>
        <p class="card-desc">When enabled, PrimeBot reconnects to the configured voice channel automatically after a restart and stays connected with an empty queue and nobody listening. Disabling disconnects intentionally and prevents automatic reconnection.</p>
        <label class="switch-row">
          <span>24/7 mode</span>
          <input type="checkbox" id="mu-247-enabled" ${st.twentyFourSevenEnabled ? 'checked' : ''} />
        </label>
        <label class="field"><span>Permanent voice channel</span>
          <select id="mu-247-channel">${channelOptions(channels, st.twentyFourSevenChannelId)}</select></label>
        <label class="field"><span>DJ role (can manage the whole queue)</span>
          <select id="mu-dj-role">${roleOptions(roles, st.djRoleId)}</select></label>
        <label class="field"><span>Default volume (1-100)</span>
          <input type="range" id="mu-default-volume" min="1" max="100" value="${st.defaultVolume != null ? st.defaultVolume : 100}" />
          <output id="mu-default-volume-out">${st.defaultVolume != null ? st.defaultVolume : 100}</output></label>
        <label class="field"><span>Maximum queue size</span>
          <input type="number" id="mu-max-queue" min="10" max="2000" value="${st.maxQueue != null ? st.maxQueue : 500}" /></label>
      </div>
      <div class="card">
        <div class="card-title"><span>${svgIcon('info')} How it behaves</span></div>
        <p class="card-desc">Playback pauses automatically when the channel is empty and resumes when a listener returns — but PrimeBot never disconnects because the channel emptied, the queue ran out or a track ended. A manual pause is honoured and is not overridden by a listener joining. Per-track controls are run from Discord with <code>/music</code> or <code>$music</code>.</p>
      </div>
    </section>`;
}

function musicPageHTML({ guild, user }) {
    const cfg = guild._config || {};
    const settings = cfg.musicSettings || null;
    const playlists = Array.isArray(cfg.musicPlaylists) ? cfg.musicPlaylists : [];
    const history = Array.isArray(cfg.musicHistory) ? cfg.musicHistory : [];
    const settingsWithCount = { ...(settings || {}), playlistCount: playlists.length };

    // Radio lives INSIDE the Music tab: reuse the radio page's section builders
    // (same rd-* ids/classes) so dashboard/public/js/radio.js drives it as-is.
    const radioSession = cfg.radioSession || null;
    const radioStations = Array.isArray(cfg.radioStations) ? cfg.radioStations : [];
    const radio = require('./radio-page').radioSectionsHTML({
        session: radioSession, stations: radioStations, channels: guild._channels || [],
    });

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'music')}
    <div class="card rd-hero-card">
      <div class="card-title"><span><span class="icon">${svgIcon('music')}</span> Music</span>
        <span class="embed-builder-badge">${svgIcon('sparkles')} Free feature</span></div>
      <p class="card-desc">On-demand music with an administrator-controlled 24/7 voice connection. Plays from YouTube, SoundCloud, Spotify (matched to a playable source) and direct audio URLs. PrimeBot stays connected with an empty queue and nobody listening, and never disconnects just because the channel emptied. The 24/7 SoundCloud <strong>radio</strong> is configured in the Radio sections below.</p>
    </div>
    ${sectionNav('overview', radio.nav)}
    ${overviewSection(settingsWithCount, history)}
    ${playlistsSection(playlists)}
    ${historySection(history)}
    ${twentyFourSevenSection(settings, guild._channels || [], guild._roles || [])}
    ${radio.html}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels || [], roles: guild._roles || [], extra: { musicSettings: settings, musicPlaylists: playlists, radioSession, radioStations } })}`;

    return {
        body,
        scripts: ['/js/guild-common.js', '/js/music.js', '/js/radio.js'],
        title: `PrimeBot · ${guild.name} · Music`,
    };
}

module.exports = { musicPageHTML, SECTIONS };
