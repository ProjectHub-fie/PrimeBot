/**
 * Music UI — embeds, buttons and select menus.
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
const { formatDuration, PLAYBACK_STATES, REPEAT_MODES, PROVIDER_LABELS } = require('../../shared/musicConstants');

const BRAND = config.colors.primary;
const MAX_SELECT_OPTIONS = 25;

function stateLabel(state) {
    switch (state) {
        case PLAYBACK_STATES.PLAYING: return '▶️ Playing';
        case PLAYBACK_STATES.PAUSED: return '⏸️ Paused';
        case PLAYBACK_STATES.STOPPED: return '⏹️ Stopped';
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

function sourceLabel(track) {
    if (!track) return null;
    const src = track.source || PROVIDER_LABELS[track.provider] || track.provider;
    if (track.matchedFrom && track.matchedFrom !== track.provider) {
        return `${src} (matched from ${PROVIDER_LABELS[track.matchedFrom] || track.matchedFrom})`;
    }
    return src;
}

/** The Now Playing embed + the interactive control row. */
function nowPlaying(snapshot, { prefix = '/' } = {}) {
    const s = snapshot || {};
    const t = s.current;
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🎶 Now Playing')
        .setDescription(t ? trackLine(t) : 'Nothing is playing right now.')
        .addFields(
            { name: 'State', value: stateLabel(s.state), inline: true },
            { name: 'Volume', value: `${s.volume != null ? s.volume : 100}%`, inline: true },
            { name: 'Repeat', value: repeatLabel(s.repeat), inline: true },
            { name: 'Shuffle', value: s.shuffle ? '🔀 On' : 'Off', inline: true },
            { name: 'Queue', value: `${s.queueLength != null ? s.queueLength : 0} track(s)`, inline: true },
            { name: 'Listeners', value: `${s.listeners != null ? s.listeners : 0}`, inline: true },
        )
        .setFooter({ text: `Source: ${sourceLabel(t) || '—'} • ${s.twentyFourSeven ? '24/7' : 'On demand'} • ${prefix}musichelp` })
        .setTimestamp();
    if (t && t.durationMs) embed.addFields({ name: 'Duration', value: formatDuration(t.durationMs), inline: true });
    if (t && t.requesterId) embed.addFields({ name: 'Requested by', value: `<@${t.requesterId}>`, inline: true });
    if (t && t.artworkUrl) embed.setThumbnail(t.artworkUrl);
    return { embed, components: [controlRow()] };
}

/** Pause/Resume, Skip, Previous, Stop, Shuffle, Repeat (≤5 per row). */
function controlRow() {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('music_prev').setEmoji('⏮️').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_pauseresume').setEmoji('⏯️').setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId('music_skip').setEmoji('⏭️').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_stop').setEmoji('⏹️').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('music_shuffle').setEmoji('🔀').setStyle(ButtonStyle.Secondary),
    );
}

function secondControlRow() {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('music_repeat').setEmoji('🔁').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_queue').setEmoji('📜').setLabel('Queue').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('music_247status').setEmoji('🕐').setLabel('24/7').setStyle(ButtonStyle.Secondary),
    );
}

/** Queue embed with pagination (10 per page) and prev/next buttons. */
function queueEmbed(snapshot, page = 0, { prefix = '/' } = {}) {
    const s = snapshot || {};
    const all = s.queue || [];
    const perPage = 10;
    const pages = Math.max(1, Math.ceil(all.length / perPage));
    const p = Math.min(Math.max(0, page), pages - 1);
    const slice = all.slice(p * perPage, p * perPage + perPage);
    const lines = slice.map((t, i) => `**${p * perPage + i + 1}.** ${trackLine(t)} \`${formatDuration(t.durationMs)}\``);
    const totalMs = all.reduce((n, t) => n + (t.durationMs || 0), 0);
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('📜 Queue')
        .setDescription(
            (s.current ? `**Now:** ${trackLine(s.current)}\n\n` : '') +
            (lines.length ? lines.join('\n') : 'The queue is empty.'),
        )
        .setFooter({ text: `Page ${p + 1}/${pages} • ${all.length} track(s) • ${formatDuration(totalMs)} total • ${prefix}musichelp` });
    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`music_qpage:${p - 1}`).setEmoji('◀️').setStyle(ButtonStyle.Secondary).setDisabled(p <= 0),
        new ButtonBuilder().setCustomId(`music_qpage:${p + 1}`).setEmoji('▶️').setStyle(ButtonStyle.Secondary).setDisabled(p >= pages - 1),
    );
    return { embed, components: [row] };
}

/** Search results select menu (≤25 options). */
function searchSelect(tracks, token) {
    const options = tracks.slice(0, MAX_SELECT_OPTIONS).map((t, i) =>
        new StringSelectMenuOptionBuilder()
            .setLabel(`${t.title}`.slice(0, 95))
            .setDescription(`${t.artist ? t.artist + ' • ' : ''}${formatDuration(t.durationMs)} • ${t.source || PROVIDER_LABELS[t.provider] || t.provider}`.slice(0, 95))
            .setValue(String(i)),
    );
    const menu = new StringSelectMenuBuilder()
        .setCustomId(`music_search:${token}`)
        .setPlaceholder('Choose a track to play')
        .addOptions(options);
    return new ActionRowBuilder().addComponents(menu);
}

function searchEmbed(query, tracks) {
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle(`🔎 Search: ${String(query).slice(0, 200)}`)
        .setDescription(tracks.length
            ? 'Pick a result below to play it.'
            : 'No results found.')
        .setFooter({ text: `${tracks.length} result(s)` });
}

function playlistListEmbed(playlists) {
    const lines = playlists.map(p => `**#${p.id}** ${p.name} ${p.isPublic ? '🌐' : '🔒'}${p.ownerId ? ` — <@${p.ownerId}>` : ''}`);
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🗂️ Playlists')
        .setDescription(lines.length ? lines.join('\n') : 'No playlists yet. Create one with `/playlist create`.');
}

function playlistEmbed(playlist, tracks) {
    const lines = tracks.slice(0, 25).map((t, i) => `**${i + 1}.** ${t.title}${t.artist ? ` — ${t.artist}` : ''} \`${formatDuration(t.durationMs)}\``);
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle(`🗂️ ${playlist.name} ${playlist.isPublic ? '🌐 Public' : '🔒 Personal'}`)
        .setDescription((playlist.description ? `${playlist.description}\n\n` : '') + (lines.length ? lines.join('\n') : 'This playlist is empty.'))
        .setFooter({ text: `${tracks.length} track(s)${tracks.length > 25 ? ' (showing first 25)' : ''}` });
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
            cmd('queue', '', 'Show the queue'),
            cmd('remove', '<position>', 'Remove a track from the queue'),
            cmd('clear', '', 'Clear the queue'),
            cmd('shuffle', '', 'Shuffle the queue'),
            cmd('loop', '<off|track|queue>', 'Set the repeat mode'),
            cmd('nowplaying', '', 'Show what is playing'),
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
    nowPlaying, controlRow, secondControlRow, queueEmbed, searchSelect, searchEmbed,
    playlistListEmbed, playlistEmbed, status247Embed, successEmbed, errorEmbed, helpEmbed,
    stateLabel, repeatLabel, sourceLabel, trackLine,
};
