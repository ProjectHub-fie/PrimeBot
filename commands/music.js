/**
 * /music — the on-demand music command.
 *
 * Subcommands: play, search, pause, resume, skip, previous, stop, seek, queue,
 * remove, clear, shuffle, loop, nowplaying, volume, status, help.
 *
 * Permissions follow the requester-protection model (utils/music/musicPermissions):
 * playback control requires the member to be in the music channel (or hold the
 * DJ role / Manage Server); configuration is admin-only.
 */

const { SlashCommandBuilder, MessageFlags } = require('discord.js');
const ui = require('../utils/music/musicEmbed');
const perms = require('../utils/music/musicPermissions');
const musicFilters = require('../utils/music/musicFilters');
const { REPEAT_MODES, parseTimestamp, VALID_REPEAT_MODES } = require('../shared/musicConstants');

const PLAY_CONTROL = new Set(['pause', 'resume', 'skip', 'previous', 'stop', 'clear', 'shuffle', 'loop', 'remove', 'seek', 'volume', 'autoplay', 'filter', 'skipto', 'rewind']);

function manager(interaction) {
    const m = interaction.client.musicManager;
    if (!m) throw new Error('The music service is not available right now.');
    return m;
}

async function settingsFor(interaction) {
    try {
        const { getSettings } = require('../utils/music/musicStore');
        return await getSettings(interaction.guildId) || {};
    } catch (_) { return {}; }
}

async function requireControl(interaction, m) {
    const session = m.getSession(interaction.guildId);
    if (!session) throw new Error('Nothing is playing in this server.');
    if (!perms.canControl(interaction.member, session)) {
        throw new Error('Join the music voice channel (or hold the DJ role / Manage Server) to control playback.');
    }
    return session;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('music')
        .setDescription('Play and manage music')
        .setDMPermission(false)
        .addSubcommand(sub => sub.setName('play').setDescription('Play a song, or queue it if something is already playing')
            .addStringOption(o => o.setName('query').setDescription('Song name, YouTube/SoundCloud/Spotify URL, or direct audio URL').setRequired(true)))
        .addSubcommand(sub => sub.setName('search').setDescription('Search for a song and pick a result')
            .addStringOption(o => o.setName('query').setDescription('Search term').setRequired(true)))
        .addSubcommand(sub => sub.setName('pause').setDescription('Pause playback'))
        .addSubcommand(sub => sub.setName('resume').setDescription('Resume playback'))
        .addSubcommand(sub => sub.setName('skip').setDescription('Skip the current track')
            .addIntegerOption(o => o.setName('count').setDescription('How many tracks to skip').setMinValue(1).setMaxValue(25)))
        .addSubcommand(sub => sub.setName('previous').setDescription('Play the previous track'))
        .addSubcommand(sub => sub.setName('stop').setDescription('Stop playback and clear the queue (stays connected)'))
        .addSubcommand(sub => sub.setName('seek').setDescription('Jump to a position in the current track')
            .addStringOption(o => o.setName('timestamp').setDescription('e.g. 90, 1:30, or 1h2m3s').setRequired(true)))
        .addSubcommand(sub => sub.setName('rewind').setDescription('Rewind the current track a few seconds')
            .addIntegerOption(o => o.setName('seconds').setDescription('Seconds to rewind (default 10)').setMinValue(1).setMaxValue(600)))
        .addSubcommand(sub => sub.setName('skipto').setDescription('Skip directly to a position in the queue')
            .addIntegerOption(o => o.setName('position').setDescription('Queue position (1 = next)').setRequired(true).setMinValue(1)))
        .addSubcommand(sub => sub.setName('queue').setDescription('Show the queue'))
        .addSubcommand(sub => sub.setName('remove').setDescription('Remove a track from the queue')
            .addIntegerOption(o => o.setName('position').setDescription('Queue position (1 = next)').setRequired(true).setMinValue(1)))
        .addSubcommand(sub => sub.setName('clear').setDescription('Clear the queue'))
        .addSubcommand(sub => sub.setName('shuffle').setDescription('Shuffle the queue'))
        .addSubcommand(sub => sub.setName('loop').setDescription('Set the repeat mode')
            .addStringOption(o => o.setName('mode').setDescription('Repeat mode').setRequired(true)
                .addChoices({ name: 'Off', value: 'off' }, { name: 'Track', value: 'track' }, { name: 'Queue', value: 'queue' })))
        .addSubcommand(sub => sub.setName('autoplay').setDescription('Toggle autoplay — keep music playing when the queue ends')
            .addBooleanOption(o => o.setName('enabled').setDescription('Force on/off (omit to toggle)')))
        .addSubcommand(sub => sub.setName('filter').setDescription('Apply an audio filter preset')
            .addStringOption(o => o.setName('preset').setDescription('Filter preset (omit to pick from a menu)')
                .addChoices(...musicFilters.FILTER_LIST.slice(0, 25).map(f => ({ name: f.label, value: f.id })), { name: 'Clear', value: 'clear' })))
        .addSubcommand(sub => sub.setName('nowplaying').setDescription('Show what is playing'))
        .addSubcommand(sub => sub.setName('track').setDescription('Show detailed information about the current track'))
        .addSubcommand(sub => sub.setName('lyrics').setDescription('Show the lyrics of the current (or a named) song')
            .addStringOption(o => o.setName('song').setDescription('Song name (defaults to the current track)')))
        .addSubcommand(sub => sub.setName('grab').setDescription('DM yourself the track that is currently playing'))
        .addSubcommand(sub => sub.setName('volume').setDescription('Set the volume')
            .addIntegerOption(o => o.setName('level').setDescription('Volume 1-100').setRequired(true).setMinValue(1).setMaxValue(100)))
        .addSubcommand(sub => sub.setName('status').setDescription('Show the music and connection status'))
        .addSubcommand(sub => sub.setName('help').setDescription('Show music commands')),

    async execute(interaction) {
        const m = interaction.client.musicManager;
        if (!m) {
            return interaction.reply({ embeds: [ui.errorEmbed('The music service is not available right now.')], flags: MessageFlags.Ephemeral });
        }
        const sub = interaction.options.getSubcommand();
        const guildId = interaction.guildId;

        try {
            switch (sub) {
                case 'play': {
                    const query = interaction.options.getString('query');
                    await interaction.deferReply();
                    const settings = await settingsFor(interaction);
                    const voiceChannelId = interaction.member && interaction.member.voice ? interaction.member.voice.channelId : null;
                    const session = m.getSession(guildId);
                    // Non-admins must be in (or join) a voice channel to start music.
                    const channelId = voiceChannelId || (session && session.channelId) || null;
                    if (!channelId) {
                        return interaction.editReply({ embeds: [ui.errorEmbed('Join a voice channel first, then run `/music play`.')] });
                    }
                    const res = await m.play(guildId, query, { channelId, textChannelId: interaction.channelId, requesterId: interaction.user.id, settings });
                    const t = res.track;
                    // Keep the Now Playing embed (artwork + controls) and only
                    // change the headline so the thumbnail/image still renders.
                    const payload = ui.nowPlayingPayload(m.describe(guildId), {
                        title: res.queued ? '➕ Queued' : '▶️ Playing',
                        track: res.queued ? t : undefined,
                    });
                    await interaction.editReply(payload);
                    // Track the reply message so the bounded refresh timer keeps
                    // its position bar live from real playback state.
                    try {
                        const sent = await interaction.fetchReply();
                        if (sent && sent.id) m.trackNowPlaying(guildId, { channelId: sent.channelId || interaction.channelId, messageId: sent.id });
                    } catch (_) {}
                    return undefined;
                }
                case 'search': {
                    const query = interaction.options.getString('query');
                    await interaction.deferReply();
                    const { searchQuery } = require('../utils/music/resolve');
                    const tracks = await searchQuery(interaction.client, query, 10).catch(err => { throw err; });
                    if (!tracks.length) return interaction.editReply({ embeds: [ui.errorEmbed(`No results for **${query}**.`)] });
                    // Stash the candidates for the select-menu handler.
                    const token = `${interaction.id}`;
                    interaction.client.musicSearchCache = interaction.client.musicSearchCache || new Map();
                    interaction.client.musicSearchCache.set(token, { tracks, userId: interaction.user.id, guildId });
                    setTimeout(() => { try { interaction.client.musicSearchCache.delete(token); } catch (_) {} }, 120000).unref?.();
                    return interaction.editReply({ embeds: [ui.searchEmbed(query, tracks)], components: [ui.searchSelect(tracks, token)] });
                }
                case 'pause': { await requireControl(interaction, m); const s = await m.pause(guildId, { actor: interaction.user.id }); return interaction.reply({ embeds: [ui.successEmbed('⏸️ Paused', `Queue: ${s.queueLength} track(s). Still connected.`)] }); }
                case 'resume': { await requireControl(interaction, m); const s = await m.resume(guildId); return interaction.reply({ embeds: [ui.successEmbed('▶️ Resumed', s.current ? `Playing **${s.current.title}**.` : 'Continuing the queue.')] }); }
                case 'skip': { await requireControl(interaction, m); const count = interaction.options.getInteger('count') || 1; const s = await m.skip(guildId, { actor: interaction.user.id, count }); return interaction.reply({ embeds: [ui.successEmbed('⏭️ Skipped', s.current ? `Now playing **${s.current.title}**.` : 'The queue is empty — still connected.')] }); }
                case 'previous': { await requireControl(interaction, m); const r = await m.previous(guildId); return interaction.reply({ embeds: [ui.successEmbed('⏮️ Previous', `Playing **${r.track.title}**.`)] }); }
                case 'stop': { await requireControl(interaction, m); await m.stop(guildId, { actor: interaction.user.id }); return interaction.reply({ embeds: [ui.successEmbed('⏹️ Stopped', 'Playback stopped. PrimeBot stays in the voice channel.')] }); }
                case 'seek': { await requireControl(interaction, m); const sec = parseTimestamp(interaction.options.getString('timestamp')); if (sec == null) throw new Error('Invalid timestamp. Use e.g. `90`, `1:30` or `1h2m3s`.'); const s = await m.seek(guildId, sec); return interaction.reply({ embeds: [ui.successEmbed('⏩ Seeked', `Jumped to ${sec}s in **${s.current ? s.current.title : 'the track'}**.`)] }); }
                case 'rewind': { await requireControl(interaction, m); const secs = interaction.options.getInteger('seconds') || 10; const s = await m.rewind(guildId, secs); return interaction.reply({ embeds: [ui.successEmbed('⏪ Rewound', `Rewound ${secs}s in **${s.current ? s.current.title : 'the track'}**.`)] }); }
                case 'skipto': { await requireControl(interaction, m); const pos = interaction.options.getInteger('position'); const s = await m.skipTo(guildId, pos); return interaction.reply({ embeds: [ui.successEmbed('⏭️ Skipped', s.current ? `Now playing **${s.current.title}**.` : 'The queue is empty — still connected.')] }); }
                case 'queue': { const s = m.getSession(guildId); if (!s) throw new Error('Nothing is playing in this server.'); const { embed, components } = ui.queueEmbed(m.describe(guildId, { queueLimit: 100 }), 0); return interaction.reply({ embeds: [embed], components }); }
                case 'remove': { const session = await requireControl(interaction, m); const position = interaction.options.getInteger('position'); if (!perms.canRemoveTrack(interaction.member, session, position)) throw new Error('You can only remove your own queued tracks (or hold the DJ role / Manage Server).'); const r = await m.remove(guildId, position); return interaction.reply({ embeds: [ui.successEmbed('🗑️ Removed', `Removed **${r.removed.title}** from the queue.`)] }); }
                case 'clear': { await requireControl(interaction, m); const r = await m.clear(guildId); return interaction.reply({ embeds: [ui.successEmbed('🧹 Queue cleared', `Removed ${r.removed} track(s).`)] }); }
                case 'shuffle': { await requireControl(interaction, m); const s = await m.shuffle(guildId); return interaction.reply({ embeds: [ui.successEmbed('🔀 Shuffled', `Shuffled ${s.queueLength} track(s).`)] }); }
                case 'loop': { await requireControl(interaction, m); const mode = interaction.options.getString('mode'); if (!VALID_REPEAT_MODES.includes(mode)) throw new Error('Repeat mode must be off, track or queue.'); const s = await m.setRepeat(guildId, mode); return interaction.reply({ embeds: [ui.successEmbed('🔁 Repeat', `Repeat mode is now **${ui.repeatLabel(s.repeat)}**.`)] }); }
                case 'autoplay': {
                    await requireControl(interaction, m);
                    const forced = interaction.options.getBoolean('enabled');
                    const session = m.getSession(guildId);
                    const next = forced == null ? !session.autoplay : forced;
                    const s = await m.setAutoplay(guildId, next);
                    return interaction.reply({ embeds: [ui.successEmbed('♾️ Autoplay', s.autoplay ? 'Autoplay is now **enabled** — related tracks will keep playing.' : 'Autoplay is now **disabled**.')] });
                }
                case 'filter': {
                    await requireControl(interaction, m);
                    const preset = interaction.options.getString('preset');
                    if (!preset) {
                        const session = m.getSession(guildId);
                        const { embed, components } = ui.filterEmbed(session ? session.filter : null);
                        return interaction.reply({ embeds: [embed], components });
                    }
                    const s = await m.setFilter(guildId, preset === 'clear' ? null : preset);
                    const label = preset === 'clear' ? 'Filters cleared' : `Filter set to **${musicFilters.filterLabel(preset)}**`;
                    return interaction.reply({ embeds: [ui.successEmbed('🎛️ Filter', label)] });
                }
                case 'nowplaying': { const s = m.getSession(guildId); if (!s) throw new Error('Nothing is playing in this server.'); const snap = m.describe(guildId); const { embed, components } = ui.nowPlaying(snap); return interaction.reply({ embeds: [embed], components: [components[0], ui.secondControlRow(snap)] }); }
                case 'track': { const snap = m.describe(guildId); if (!snap || !snap.current) throw new Error('Nothing is playing in this server.'); return interaction.reply({ embeds: [ui.trackInfoEmbed(snap.current)] }); }
                case 'lyrics': {
                    const song = interaction.options.getString('song');
                    const snap = m.describe(guildId);
                    if (!song && (!snap || !snap.current)) throw new Error('Nothing is playing — provide a song name.');
                    await interaction.deferReply();
                    const { fetchLyrics } = require('../utils/music/lyricsService');
                    const res = await fetchLyrics(song ? { query: song } : { track: snap.current });
                    if (!res.lyrics) return interaction.editReply({ embeds: [ui.errorEmbed(res.reason || 'No lyrics found.')] });
                    const text = res.lyrics.length > 4000 ? res.lyrics.slice(0, 3980) + '\n…' : res.lyrics;
                    const embed = song ? ui.trackInfoEmbed({ title: song }).setDescription(text) : ui.trackInfoEmbed(snap.current).setDescription(text);
                    return interaction.editReply({ embeds: [embed] });
                }
                case 'grab': {
                    const snap = m.describe(guildId);
                    if (!snap || !snap.current) throw new Error('Nothing is playing in this server.');
                    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
                    const dm = await interaction.user.send({ embeds: [ui.trackInfoEmbed(snap.current)] }).catch(() => null);
                    return interaction.editReply({ embeds: [dm ? ui.successEmbed('📬 Sent', 'Check your DMs for the track details.') : ui.errorEmbed('I could not DM you — enable direct messages from this server.')] });
                }
                case 'volume': { await requireControl(interaction, m); const level = interaction.options.getInteger('level'); const s = await m.setVolume(guildId, level); return interaction.reply({ embeds: [ui.successEmbed('🔊 Volume', `Volume set to **${s.volume}%**.`)] }); }
                case 'status': {
                    const snap = m.describe(guildId);
                    if (!snap) return interaction.reply({ embeds: [ui.successEmbed('🎵 Music', 'No active session. Use `/music play` to start.')] });
                    const { embed, components } = ui.nowPlaying(snap);
                    return interaction.reply({ embeds: [embed], components: [components[0], ui.secondControlRow(snap)] });
                }
                case 'help':
                default:
                    return interaction.reply({ embeds: [ui.helpEmbed({ slash: true })] });
            }
        } catch (err) {
            const payload = { embeds: [ui.errorEmbed(err.message || 'Something went wrong.')] };
            if (interaction.deferred || interaction.replied) return interaction.editReply(payload).catch(() => {});
            return interaction.reply(payload).catch(() => {});
        }
    },
};
