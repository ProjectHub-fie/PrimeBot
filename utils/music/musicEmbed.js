/**
 * Music UI — embeds, buttons and select menus.
 *
 * Presentation is recreated from the Linix music system (artwork-first Now
 * Playing, an author line, a progress bar, requester/source/duration fields,
 * filter + autoplay status, a numbered paginated queue, a search select menu)
 * but rendered with PrimeBot's own embed theme and discord.js 14 components —
 * Linix's Lavalink/musicard image cards are NOT used (no new dependencies).
 *
 * All Discord component limits are respected: ≤5 buttons per row, ≤5 rows per
 * message, ≤25 options per select menu. Callers pass a prefix ('/' or the guild
 * prefix) so the same embed renders correctly for slash and sash commands.
 */

const {
    EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle,
    StringSelectMenuBuilder, StringSelectMenuOptionBuilder,
} = require('discord.js');
const config = require('../../config');
const { formatDuration, progressBar, PLAYBACK_STATES, REPEAT_MODES, PROVIDER_LABELS } = require('../../shared/musicConstants');
const musicFilters = require('./musicFilters');

const BRAND = config.colors.primary;
const MAX_SELECT_OPTIONS = 25;
const QUEUE_PER_PAGE = 10;

/**
 * Apply a track's artwork to the large embed image, tolerating a non-URL value.
 *
 * `EmbedBuilder.setImage()`/`setThumbnail()` validate their argument and THROW
 * on anything that is not a valid URL (a bare identifier, a relative path, an
 * empty string). A provider that returns such a value would otherwise blow up
 * the whole embed build — and because `nowPlaying()` is rebuilt on every control
 * button press, one bad track would make every button fail. Only apply a value
 * that looks like an http(s) URL.
 */
function isImageUrl(url) {
    return typeof url === 'string' && /^https?:\/\/\S+$/i.test(url.trim());
}

function applyArtwork(embed, url) {
    if (!isImageUrl(url)) return embed;
    try { embed.setImage(url.trim()); } catch (_) { /* never let artwork break an embed */ }
    return embed;
}

function stateLabel(state) {
    switch (state) {
        case PLAYBACK_STATES.PLAYING: return '▶️ Playing';
        case PLAYBACK_STATES.PAUSED: return '⏸️ Paused';
        case PLAYBACK_STATES.STOPPED: return '⏹️ Stopped';
        case PLAYBACK_STATES.BUFFERING: return '⏳ Buffering…';
        case PLAYBACK_STATES.RECONNECTING: return '🔄 Reconnecting…';
        default: return '💤 Idle';
    }
}

function repeatLabel(mode) {
    return mode === REPEAT_MODES.TRACK ? '🔂 Track' : mode === REPEAT_MODES.QUEUE ? '🔁 Queue' : '➡️ Off';
}

function trackLine(track) {
    if (!track) return 'Nothing is playing.';
    const artist = track.artist ? ` — ${track.artist}` : '';
    return `**${track.title}**${artist}`;
}

/** A clickable `[title](url)` line (falls back to bold text without a URL). */
function trackLink(track) {
    if (!track) return 'Unknown track';
    const artist = track.artist ? ` — ${track.artist}` : '';
    const title = String(track.title || 'Unknown title');
    return track.url ? `**[${title}](${track.url})**${artist}` : `**${title}**${artist}`;
}

function sourceLabel(track) {
    if (!track) return null;
    const src = track.source || PROVIDER_LABELS[track.provider] || track.provider;
    if (track.matchedFrom && track.matchedFrom !== track.provider) {
        return `${src} (matched from ${PROVIDER_LABELS[track.matchedFrom] || track.matchedFrom})`;
    }
    return src;
}

function requesterLabel(track) {
    if (!track) return null;
    if (track.requesterId) return `<@${track.requesterId}>`;
    return null;
}

/** The Linix-style playback progress line: bar + `current / total`. */
function progressLine(snapshot) {
    const s = snapshot || {};
    const t = s.current;
    if (!t) return null;
    const bar = progressBar(s.positionMs || 0, t.durationMs);
    const cur = formatDuration(s.positionMs || 0);
    const total = t.durationMs ? formatDuration(t.durationMs) : '🔴 LIVE';
    return `${bar}\n\`${cur} / ${total}\``;
}

/** The Now Playing embed + the interactive control row. */
function nowPlaying(snapshot, { prefix = '/' } = {}) {
    const s = snapshot || {};
    const t = s.current;
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: '🎶 Now Playing' })
        .setDescription(
            (t ? trackLink(t) : 'Nothing is playing right now.') +
            (t ? `\n\n${progressLine(s)}` : ''),
        )
        .addFields(
            { name: 'Duration', value: t && t.durationMs ? formatDuration(t.durationMs) : '—', inline: true },
            { name: 'Requester', value: (t && requesterLabel(t)) || '—', inline: true },
            { name: 'Source', value: sourceLabel(t) || '—', inline: true },
            { name: 'Volume', value: `${s.volume != null ? s.volume : 100}%`, inline: true },
            { name: 'Repeat', value: repeatLabel(s.repeat), inline: true },
            { name: 'Autoplay', value: s.autoplay ? '♾️ On' : 'Off', inline: true },
            { name: 'Filter', value: s.filter ? musicFilters.filterLabel(s.filter) : 'None', inline: true },
            { name: 'Queue', value: `${s.queueLength != null ? s.queueLength : 0} track(s)`, inline: true },
            { name: 'State', value: stateLabel(s.state), inline: true },
        )
        .setFooter({ text: `${s.twentyFourSeven ? '🕐 24/7' : '🎧 On demand'} • ${s.listeners != null ? s.listeners : 0} listener(s) • ${prefix}music help` })
        .setTimestamp();
    if (t) applyArtwork(embed, t.artworkUrl);
    return { embed, components: [controlRow(s)] };
}

/**
 * The full "now playing" message payload — the Now Playing embed plus BOTH
 * control rows. Use this for every reply that announces playback (play, resume,
 * next/previous, 24/7 enable, search-select). `nowPlaying()` alone only returns
 * the first row, so a bare `components: [components[0]]` silently drops the
 * repeat/autoplay/queue/lyrics/24-7 controls.
 *
 * `opts.title` overrides the embed headline (e.g. "▶️ Playing" / "➕ Queued")
 * while keeping the SAME embed — artwork, progress bar, fields and controls all
 * survive. Do NOT swap in a bare success embed for a play announcement: that
 * drops the artwork the user expects to see.
 *
 * `opts.track` renders THAT track as the embed subject while the control rows
 * still reflect the live session — use it for a "queued" announcement, where
 * the just-queued track is not the one currently playing.
 */
function nowPlayingPayload(snapshot, opts = {}) {
    const subject = opts.track ? { ...(snapshot || {}), current: opts.track } : snapshot;
    const { embed } = nowPlaying(subject, opts);
    if (opts.title) embed.setTitle(opts.title);
    if (opts.description != null) embed.setDescription(opts.description);
    const s = snapshot || {};
    return { embeds: [embed], components: [controlRow(s), secondControlRow(s)] };
}

/** Pause/Resume, Skip, Previous, Stop, Shuffle (≤5 per row). */
function controlRow(snapshot = {}) {
    const paused = snapshot.state === PLAYBACK_STATES.PAUSED || snapshot.manualPause;
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('music_prev').setEmoji('⏮️').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_pauseresume').setEmoji(paused ? '▶️' : '⏸️').setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId('music_skip').setEmoji('⏭️').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_stop').setEmoji('⏹️').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('music_shuffle').setEmoji('🔀').setStyle(ButtonStyle.Secondary),
    );
}

function secondControlRow(snapshot = {}) {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('music_repeat').setEmoji('🔁').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_autoplay').setEmoji('♾️').setStyle(snapshot.autoplay ? ButtonStyle.Success : ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_queue').setEmoji('📜').setLabel('Queue').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_lyrics').setEmoji('📝').setLabel('Lyrics').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_247status').setEmoji('🕐').setLabel('24/7').setStyle(ButtonStyle.Secondary),
    );
}

/** The audio-filter select menu (Linix filter list, real ffmpeg presets). */
function filterRow(currentFilter = null) {
    const options = [
        new StringSelectMenuOptionBuilder().setLabel('Reset Filters').setValue('clear').setEmoji('🚫'),
    ].concat(musicFilters.FILTER_LIST.map(f =>
        new StringSelectMenuOptionBuilder()
            .setLabel(f.label)
            .setDescription(f.description)
            .setValue(f.id)
            .setEmoji(f.emoji)
            .setDefault(f.id === currentFilter),
    ));
    const menu = new StringSelectMenuBuilder()
        .setCustomId('music_filter')
        .setPlaceholder(currentFilter ? `Filter: ${musicFilters.filterLabel(currentFilter)}` : '🎛️ Select an audio filter')
        .addOptions(options.slice(0, MAX_SELECT_OPTIONS));
    return new ActionRowBuilder().addComponents(menu);
}

/** A standalone filter-picker embed (the `/music filter` command). */
function filterEmbed(currentFilter = null) {
    const lines = musicFilters.FILTER_LIST.map(f => `${f.emoji} **${f.label}** — ${f.description}`);
    return {
        embed: new EmbedBuilder()
            .setColor(BRAND)
            .setTitle('🎛️ Audio Filters')
            .setDescription(lines.join('\n'))
            .setFooter({ text: currentFilter ? `Active: ${musicFilters.filterLabel(currentFilter)}` : 'No filter active' }),
        components: [filterRow(currentFilter)],
    };
}

/** Queue embed with pagination (10 per page) and prev/next buttons. */
function queueEmbed(snapshot, page = 0, { prefix = '/' } = {}) {
    const s = snapshot || {};
    const all = s.queue || [];
    const perPage = QUEUE_PER_PAGE;
    const pages = Math.max(1, Math.ceil(all.length / perPage));
    const p = Math.min(Math.max(0, page), pages - 1);
    const slice = all.slice(p * perPage, p * perPage + perPage);
    const lines = slice.map((t, i) => {
        const num = p * perPage + i + 1;
        const req = t.requesterId ? ` • <@${t.requesterId}>` : '';
        return `\`${String(num).padStart(2, '0')}.\` ${trackLink(t)} \`${formatDuration(t.durationMs)}\`${req}`;
    });
    const totalMs = all.reduce((n, t) => n + (t.durationMs || 0), 0);
    const nowBlock = s.current
        ? `**▶️ Now playing**\n${trackLink(s.current)} \`${formatDuration(s.current.durationMs)}\`\n\n`
        : '';
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: '📜 Queue For Current Player' })
        .setDescription(
            nowBlock +
            (lines.length ? lines.join('\n') : 'The queue is empty — add songs with `/music play`.'),
        )
        .setFooter({ text: `Page ${p + 1}/${pages} • ${all.length} track(s) • ${formatDuration(totalMs)} total • ${prefix}music help` });
    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`music_qpage:${p - 1}`).setEmoji('◀️').setStyle(ButtonStyle.Secondary).setDisabled(p <= 0),
        new ButtonBuilder().setCustomId('music_qclose').setEmoji('✖️').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(`music_qpage:${p + 1}`).setEmoji('▶️').setStyle(ButtonStyle.Secondary).setDisabled(p >= pages - 1),
    );
    return { embed, components: [row] };
}

/** Search results select menu (≤25 options). */
function searchSelect(tracks, token) {
    const options = tracks.slice(0, MAX_SELECT_OPTIONS).map((t, i) =>
        new StringSelectMenuOptionBuilder()
            .setLabel(`${i + 1}. ${t.title}`.slice(0, 95))
            .setDescription(`${t.artist ? t.artist + ' • ' : ''}${formatDuration(t.durationMs)} • ${t.source || PROVIDER_LABELS[t.provider] || t.provider}`.slice(0, 95))
            .setValue(String(i)),
    );
    const menu = new StringSelectMenuBuilder()
        .setCustomId(`music_search:${token}`)
        .setPlaceholder('❯ Select a song to play')
        .addOptions(options);
    return new ActionRowBuilder().addComponents(menu);
}

function searchEmbed(query, tracks) {
    const lines = (tracks || []).slice(0, 10).map((t, i) =>
        `\`${String(i + 1).padStart(2, '0')}.\` **${t.title}**${t.artist ? ` — ${t.artist}` : ''} \`${formatDuration(t.durationMs)}\` • ${t.source || PROVIDER_LABELS[t.provider] || t.provider}`,
    );
    return new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: `🔎 Search: ${String(query).slice(0, 200)}` })
        .setDescription(lines.length ? lines.join('\n') : 'No results found.')
        .setFooter({ text: `${tracks.length} result(s) • pick one below` });
}

/** A detailed single-track card (the `/music track` information command). */
function trackInfoEmbed(track) {
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: '🎵 Track Information' })
        .setTitle(String(track.title || 'Unknown title').slice(0, 256))
        .addFields(
            { name: 'Artist', value: track.artist || '—', inline: true },
            { name: 'Duration', value: track.durationMs ? formatDuration(track.durationMs) : '—', inline: true },
            { name: 'Source', value: sourceLabel(track) || '—', inline: true },
            { name: 'Provider ID', value: track.id ? String(track.id).slice(0, 100) : '—', inline: true },
            { name: 'Requester', value: requesterLabel(track) || '—', inline: true },
            { name: 'URL', value: track.url ? String(track.url).slice(0, 200) : '—', inline: false },
        )
        .setTimestamp();
    applyArtwork(embed, track.artworkUrl);
    return embed;
}

function playlistListEmbed(playlists) {
    const lines = (playlists || []).map(p => `**#${p.id}** ${p.name} ${p.isPublic ? '🌐' : '🔒'}${p.ownerId ? ` — <@${p.ownerId}>` : ''}`);
    return new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: '🗂️ Playlists' })
        .setDescription(lines.length ? lines.join('\n') : 'No playlists yet. Create one with `/playlist create`.')
        .setFooter({ text: `${(playlists || []).length} playlist(s)` });
}

function playlistEmbed(playlist, tracks) {
    const totalMs = (tracks || []).reduce((n, t) => n + (t.durationMs || 0), 0);
    const lines = (tracks || []).slice(0, 25).map((t, i) =>
        `\`${String(i + 1).padStart(2, '0')}.\` **${t.title}**${t.artist ? ` — ${t.artist}` : ''} \`${formatDuration(t.durationMs)}\``,
    );
    return new EmbedBuilder()
        .setColor(BRAND)
        .setAuthor({ name: `🗂️ ${playlist.name} ${playlist.isPublic ? '🌐 Public' : '🔒 Personal'}` })
        .setDescription((playlist.description ? `${playlist.description}\n\n` : '') + (lines.length ? lines.join('\n') : 'This playlist is empty.'))
        .setFooter({ text: `${(tracks || []).length} track(s) • ${formatDuration(totalMs)} total${(tracks || []).length > 25 ? ' (showing first 25)' : ''}` });
}

function status247Embed(snapshot) {
    const s = snapshot || {};
    return new EmbedBuilder()
        .setColor(s.twentyFourSeven ? config.colors.success : BRAND)
        .setTitle('🕐 24/7 Mode')
        .addFields(
            { name: 'Enabled', value: s.twentyFourSeven ? '✅ Yes' : '❌ No', inline: true },
            { name: 'Voice channel', value: s.channelId ? `<#${s.channelId}>` : '—', inline: true },
            { name: 'Connection', value: s.connected ? '🟢 Connected' : '🔴 Disconnected', inline: true },
            { name: 'Playback', value: stateLabel(s.state), inline: true },
            { name: 'Queue', value: `${s.queueLength != null ? s.queueLength : 0} track(s)`, inline: true },
            { name: 'Node', value: s.ownerNode || '—', inline: true },
        )
        .setFooter({ text: '24/7 stays connected with an empty queue and nobody listening.' });
}

function successEmbed(title, description) {
    return new EmbedBuilder().setColor(config.colors.success).setTitle(title).setDescription(description || null).setTimestamp();
}

/** A consistent "working on it" state (searching / connecting / loading). */
function loadingEmbed(title = '⏳ Loading…', description = null) {
    return new EmbedBuilder().setColor(BRAND).setTitle(title).setDescription(description || null).setTimestamp();
}

function errorEmbed(description) {
    return new EmbedBuilder().setColor(config.colors.error).setTitle('❌ Music').setDescription(description || 'Something went wrong.').setTimestamp();
}

/** A compact text list of commands for /musichelp and $music help. */
function helpEmbed({ prefix = '/', slash = false } = {}) {
    const p = slash ? '/' : prefix;
    const cmd = (name, args, desc) => ({ name: `${p}${name}${args ? ' ' + args : ''}`, value: desc, inline: true });
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🎵 Music Commands')
        .setDescription('On-demand music with an admin-controlled 24/7 voice connection. Every feature is free.')
        .addFields(
            cmd('play', '<query|url>', 'Play a song, or queue it if something is playing'),
            cmd('search', '<query>', 'Search and pick a result to play'),
            cmd('pause', '', 'Pause playback'),
            cmd('resume', '', 'Resume playback'),
            cmd('skip', '[count]', 'Skip the current track'),
            cmd('previous', '', 'Play the previous track'),
            cmd('stop', '', 'Stop playback (stays connected)'),
            cmd('seek', '<timestamp>', 'Jump to a position in the track'),
            cmd('rewind', '[seconds]', 'Rewind a few seconds'),
            cmd('skipto', '<position>', 'Skip directly to a queue position'),
            cmd('queue', '', 'Show the queue'),
            cmd('remove', '<position>', 'Remove a track from the queue'),
            cmd('clear', '', 'Clear the queue'),
            cmd('shuffle', '', 'Shuffle the queue'),
            cmd('loop', '<off|track|queue>', 'Set the repeat mode'),
            cmd('autoplay', '', 'Toggle autoplay (keeps music going)'),
            cmd('filter', '[preset]', 'Apply an audio filter'),
            cmd('nowplaying', '', 'Show what is playing'),
            cmd('track', '', 'Show details for the current track'),
            cmd('lyrics', '[song]', 'Show the lyrics of the current song'),
            cmd('grab', '', 'DM yourself the current track'),
            cmd('volume', '<1-100>', 'Set the volume'),
            cmd('musicstatus', '', 'Music + connection status'),
            cmd('247 enable', '', 'Enable the persistent connection (Admin)'),
            cmd('247 disable', '', 'Disable it and disconnect (Admin)'),
            cmd('247 status', '', 'Show 24/7 status'),
            cmd('join', '', 'Join your voice channel'),
            cmd('leave', '', 'Leave the voice channel'),
            cmd('playlist', '<list|create|add|play|delete>', 'Manage playlists'),
        )
        .setFooter({ text: `PrimeBot • Version ${config.version}` });
}

module.exports = {
    nowPlaying, nowPlayingPayload, controlRow, secondControlRow, filterRow, filterEmbed, queueEmbed, searchSelect, searchEmbed,
    trackInfoEmbed, playlistListEmbed, playlistEmbed, status247Embed, successEmbed, loadingEmbed, errorEmbed, helpEmbed,
    stateLabel, repeatLabel, sourceLabel, trackLine, trackLink, requesterLabel, progressLine, QUEUE_PER_PAGE,
};
