/**
 * 24/7 Radio dashboard page.
 *
 * Server-rendered, sectioned page (same design language as the AutoMod/YouTube
 * consoles): Overview / Stations / Session. The bot's RadioManager owns the
 * live voice session; this page reads the persisted session + station catalog
 * and lets administrators toggle the persistent session, pick the voice
 * channel, and add/edit stations.
 *
 * Data comes from `guild._config.radioSession` / `radioStations` (assembled by
 * dashboard/db.js getGuildConfig), so the page renders without an extra fetch.
 * dashboard/public/js/radio.js only adds interactivity.
 */

const { esc, svgIcon } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');
const { RADIO_STATES, RADIO_STATE_LABELS, VALID_SOURCES, SOURCE_LABELS } = require('../../shared/radioConstants');

const SECTIONS = [
    { key: 'overview', label: 'Overview', icon: 'activity' },
    { key: 'stations', label: 'Stations', icon: 'music' },
    { key: 'session', label: 'Session', icon: 'radio' },
];

function sectionNav(active) {
    return `<div class="rd-sections" id="rd-sections">${SECTIONS.map(s =>
        `<button type="button" class="rd-section-btn${s.key === active ? ' active' : ''}" data-section="${s.key}">${svgIcon(s.icon)}<span>${esc(s.label)}</span></button>`
    ).join('')}</div>`;
}

function statCard(icon, label, value, id) {
    return `<div class="rd-stat"><div class="rd-stat-ico">${svgIcon(icon)}</div>
      <div class="rd-stat-body"><div class="rd-stat-value" id="${esc(id)}">${esc(String(value))}</div>
      <div class="rd-stat-label">${esc(label)}</div></div></div>`;
}

function statePill(state) {
    const label = RADIO_STATE_LABELS[state] || state || 'Stopped';
    const cls = state === RADIO_STATES.PLAYING ? 'rd-pill-play'
        : (state === RADIO_STATES.PAUSED_EMPTY || state === RADIO_STATES.PAUSED_MANUAL) ? 'rd-pill-pause'
        : state === RADIO_STATES.CONNECTING ? 'rd-pill-conn' : 'rd-pill-off';
    return `<span class="rd-pill ${cls}">${esc(label)}</span>`;
}

function channelOptions(channels, selected) {
    const list = (channels || []).filter(c => c.type === 2 || c.type === 13 || c.voice || c.isVoice);
    if (!list.length) return '<option value="">No voice channels found</option>';
    return list.map(c => `<option value="${esc(c.id)}"${String(c.id) === String(selected) ? ' selected' : ''}>${esc(c.name)}</option>`).join('');
}

function overviewSection(session, stations) {
    const st = session || {};
    const track = st.currentTrack;
    const trackLine = track
        ? `${esc(track.title || 'Unknown')}${track.artist && track.artist.username ? ` — ${esc(track.artist.username)}` : ''}`
        : '—';
    const stationName = st.stationId
        ? (stations.find(s => s.id === st.stationId) || {}).name || st.stationId
        : '—';
    return `<section class="rd-section" data-section="overview">
      <div class="rd-stats-grid">
        ${statCard('radio', 'Playback state', RADIO_STATE_LABELS[st.state] || 'Stopped', 'rd-stat-state')}
        ${statCard('volume', 'Listeners', st.listeners != null ? st.listeners : 0, 'rd-stat-listeners')}
        ${statCard('music', 'Station', stationName, 'rd-stat-station')}
        ${statCard('play', 'Queue', st.queueLength || 0, 'rd-stat-queue')}
      </div>
      <div class="rd-hero" id="rd-hero">
        <div class="rd-hero-head">
          <span class="rd-hero-ico">${svgIcon('radio')}</span>
          <div>
            <div class="rd-hero-title">Now playing</div>
            <div class="rd-hero-track" id="rd-now-track">${trackLine}</div>
          </div>
          <span id="rd-state-pill">${statePill(st.state)}</span>
        </div>
        <div class="rd-hero-meta">
          <span>Channel: <strong id="rd-channel-label">${st.channelId ? `<#${st.channelId}>` : '—'}</strong></span>
          <span>Volume: <strong id="rd-volume-label">${st.volume != null ? st.volume : 100}</strong></span>
          <span>Connection: <strong id="rd-conn-label">${st.connected ? 'Connected' : 'Disconnected'}</strong></span>
        </div>
      </div>
      <p class="card-desc">The radio stays connected to its voice channel 24/7. Playback pauses automatically when the channel is empty and resumes the moment a listener returns — the connection is never dropped just because the channel emptied.</p>
    </section>`;
}

function stationsSection(stations) {
    const rows = stations.map(s => `
      <div class="rd-station-card" data-id="${esc(s.id)}">
        <div class="rd-station-head">
          <span class="rd-station-name">${esc(s.name)}</span>
          ${s.guildId ? '' : '<span class="rd-pill rd-pill-global">Global</span>'}
          <span class="rd-pill ${s.enabled ? 'rd-pill-play' : 'rd-pill-off'}">${s.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <div class="rd-station-desc">${esc(s.description || '')}</div>
        <div class="rd-station-meta">
          <span class="rd-chip">${esc(SOURCE_LABELS[s.source] || s.source)}</span>
          ${s.genre ? `<span class="rd-chip">${esc(s.genre)}</span>` : ''}
          <code class="rd-station-ref">${esc(s.reference)}</code>
        </div>
        ${s.guildId ? `<div class="rd-station-actions">
          <button type="button" class="btn btn-secondary btn-sm rd-station-toggle" data-id="${esc(s.id)}" data-enabled="${s.enabled}">${s.enabled ? 'Disable' : 'Enable'}</button>
          <button type="button" class="btn btn-danger btn-sm rd-station-delete" data-id="${esc(s.id)}">Delete</button>
        </div>` : ''}
      </div>`).join('') || '<p class="card-desc">No stations configured.</p>';

    const sourceOpts = VALID_SOURCES.map(s => `<option value="${esc(s)}">${esc(SOURCE_LABELS[s] || s)}</option>`).join('');
    return `<section class="rd-section" data-section="stations">
      <div class="card">
        <div class="card-title"><span>${svgIcon('music')} Stations</span>
          <button type="button" class="btn btn-primary btn-sm" id="rd-add-station">${svgIcon('plus')} Add station</button></div>
        <p class="card-desc">A station is a SoundCloud source the radio loops continuously — a playlist URL, a single track URL, or a genre search.</p>
        <div class="rd-stations" id="rd-stations">${rows}</div>
      </div>
      <div id="rd-station-modal" class="modal-overlay hidden"></div>
      <template id="rd-station-form-template">
        <div class="modal floating-window">
          <div class="modal-head"><h3>Add station</h3><button type="button" class="modal-close" data-close>&times;</button></div>
          <div class="modal-body">
            <label class="field"><span>Station id (slug)</span><input type="text" id="rd-station-id" placeholder="house-radio" /></label>
            <label class="field"><span>Name</span><input type="text" id="rd-station-name" placeholder="House Radio" /></label>
            <label class="field"><span>Description</span><input type="text" id="rd-station-desc" placeholder="Continuous house music" /></label>
            <label class="field"><span>Source</span><select id="rd-station-source">${sourceOpts}</select></label>
            <label class="field"><span>Reference (URL, or genre search term)</span><input type="text" id="rd-station-ref" placeholder="https://soundcloud.com/… or deep house" /></label>
            <p class="rd-modal-error hidden" id="rd-station-error"></p>
          </div>
          <div class="modal-foot">
            <button type="button" class="btn btn-secondary" data-close>Cancel</button>
            <button type="button" class="btn btn-primary" id="rd-station-save">Add station</button>
          </div>
        </div>
      </template>
    </section>`;
}

function sessionSection(session, channels) {
    const st = session || {};
    return `<section class="rd-section" data-section="session">
      <div class="card">
        <div class="card-title"><span>${svgIcon('radio')} Persistent session</span></div>
        <p class="card-desc">When enabled, the radio reconnects to the configured voice channel automatically after a bot restart and keeps broadcasting until stopped.</p>
        <label class="switch-row">
          <span>Radio enabled</span>
          <input type="checkbox" id="rd-enabled" ${st.enabled ? 'checked' : ''} />
        </label>
        <label class="field"><span>Permanent voice channel</span>
          <select id="rd-channel-select">${channelOptions(channels, st.channelId)}</select></label>
        <label class="field"><span>Station</span>
          <select id="rd-station-select"></select></label>
        <label class="field"><span>Volume (0-100)</span>
          <input type="range" id="rd-volume" min="0" max="100" value="${st.volume != null ? st.volume : 100}" />
          <output id="rd-volume-out">${st.volume != null ? st.volume : 100}</output></label>
      </div>
      <div class="card">
        <div class="card-title"><span>${svgIcon('activity')} Live controls</span></div>
        <div class="rd-controls">
          <button type="button" class="btn btn-primary" id="rd-btn-start">${svgIcon('play')} Start</button>
          <button type="button" class="btn btn-danger" id="rd-btn-stop">Stop &amp; disconnect</button>
        </div>
        <p class="card-desc">Manual pause is honoured: a listener joining will not override an administrator's intentional pause. Per-track controls (pause / resume / skip / volume) are run from Discord with <code>/radio</code> — the bot owns the live player.</p>
      </div>
    </section>`;
}

function radioPageHTML({ guild, user }) {
    const cfg = guild._config || {};
    const session = cfg.radioSession || null;
    const stations = Array.isArray(cfg.radioStations) ? cfg.radioStations : [];

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'radio')}
    <div class="card rd-hero-card">
      <div class="card-title"><span><span class="icon">${svgIcon('radio')}</span> 24/7 Radio</span>
        <span class="embed-builder-badge">${svgIcon('sparkles')} Free feature</span></div>
      <p class="card-desc">Continuous SoundCloud radio. PrimeBot stays in the voice channel and pauses automatically when nobody is listening — no disconnect, no restart, no duplicate streams.</p>
    </div>
    ${sectionNav('overview')}
    ${overviewSection(session, stations)}
    ${stationsSection(stations)}
    ${sessionSection(session, guild._channels || [])}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels || [], roles: guild._roles || [], extra: { radioSession: session, radioStations: stations } })}`;

    return {
        body,
        scripts: ['/js/guild-common.js', '/js/radio.js'],
        title: `PrimeBot · ${guild.name} · Radio`,
    };
}

module.exports = {
    radioPageHTML,
    SECTIONS,
    sectionNav,
    overviewSection,
    stationsSection,
    sessionSection,
    radioSectionsHTML,
};

/**
 * The radio sections (Stations + Session) plus their nav buttons, for embedding
 * inside the Music dashboard page (radio now lives inside the Music tab). The
 * returned markup reuses the same `rd-*` classes and ids, so
 * dashboard/public/js/radio.js drives it unchanged.
 */
function radioSectionsHTML({ session, stations, channels }) {
    return {
        nav: [
            { key: 'stations', label: 'Radio stations', icon: 'music' },
            { key: 'radio', label: 'Radio session', icon: 'radio' },
        ],
        html: `${stationsSection(stations)}\n${sessionSection(session, channels)}`,
    };
}
