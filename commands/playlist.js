/**
 * /playlist — public + personal playlists.
 *
 * Subcommands: list, create, rename, delete, view, add, addqueue, save, play,
 * remove. Public playlists are shared (managed by their owner or an admin);
 * personal playlists are owner-only. Every mutation enforces ownership.
 */

const { SlashCommandBuilder, MessageFlags } = require('discord.js');
const ui = require('../utils/music/musicEmbed');
const perms = require('../utils/music/musicPermissions');

function store() { return require('../utils/music/musicStore'); }

async function loadOwned(interaction, id) {
    const pl = await store().getPlaylist(interaction.guildId, id);
    if (!pl) throw new Error(`No playlist #${id} in this server.`);
    const isOwner = pl.ownerId && pl.ownerId === interaction.user.id;
    if (!isOwner && !pl.isPublic && !perms.isAdmin(interaction.member)) {
        throw new Error('That is a personal playlist you do not own.');
    }
    if (!isOwner && perms.isAdmin(interaction.member)) return pl; // admins may manage public/shared
    if (!isOwner && !pl.isPublic) throw new Error('You can only manage your own playlists.');
    return pl;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('playlist')
        .setDescription('Manage music playlists')
        .setDMPermission(false)
        .addSubcommand(sub => sub.setName('list').setDescription('List playlists'))
        .addSubcommand(sub => sub.setName('create').setDescription('Create a playlist')
            .addStringOption(o => o.setName('name').setDescription('Playlist name').setRequired(true))
            .addBooleanOption(o => o.setName('public').setDescription('Share with everyone in the server')))
        .addSubcommand(sub => sub.setName('rename').setDescription('Rename a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true))
            .addStringOption(o => o.setName('name').setDescription('New name').setRequired(true)))
        .addSubcommand(sub => sub.setName('delete').setDescription('Delete a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true)))
        .addSubcommand(sub => sub.setName('view').setDescription('View a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true)))
        .addSubcommand(sub => sub.setName('add').setDescription('Add a track to a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true))
            .addStringOption(o => o.setName('query').setDescription('Track name or URL').setRequired(true)))
        .addSubcommand(sub => sub.setName('remove').setDescription('Remove a track from a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true))
            .addIntegerOption(o => o.setName('position').setDescription('Track position (1-based)').setRequired(true)))
        .addSubcommand(sub => sub.setName('save').setDescription('Save the current queue as a playlist')
            .addStringOption(o => o.setName('name').setDescription('Playlist name').setRequired(true))
            .addBooleanOption(o => o.setName('public').setDescription('Share with everyone')))
        .addSubcommand(sub => sub.setName('play').setDescription('Play a playlist')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true)))
        .addSubcommand(sub => sub.setName('queue').setDescription('Add a playlist to the queue')
            .addIntegerOption(o => o.setName('id').setDescription('Playlist id').setRequired(true))),

    async execute(interaction) {
        const m = interaction.client.musicManager;
        const sub = interaction.options.getSubcommand();
        const guildId = interaction.guildId;
        try {
            switch (sub) {
                case 'list': {
                    const lists = await store().listPlaylists(guildId, { ownerId: interaction.user.id });
                    return interaction.reply({ embeds: [ui.playlistListEmbed(lists)] });
                }
                case 'create': {
                    const name = interaction.options.getString('name');
                    const isPublic = !!interaction.options.getBoolean('public');
                    const pl = await store().createPlaylist(guildId, { name, isPublic, ownerId: interaction.user.id });
                    return interaction.reply({ embeds: [ui.successEmbed('🗂️ Playlist created', `**#${pl.id}** ${pl.name} (${isPublic ? 'public' : 'personal'})`)] });
                }
                case 'rename': {
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    const updated = await store().renamePlaylist(guildId, pl.id, interaction.options.getString('name'));
                    return interaction.reply({ embeds: [ui.successEmbed('✏️ Renamed', `**#${updated.id}** is now “${updated.name}”.`)] });
                }
                case 'delete': {
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    await store().deletePlaylist(guildId, pl.id);
                    return interaction.reply({ embeds: [ui.successEmbed('🗑️ Deleted', `Playlist “${pl.name}” was deleted.`)] });
                }
                case 'view': {
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    const tracks = await store().listPlaylistTracks(pl.id);
                    return interaction.reply({ embeds: [ui.playlistEmbed(pl, tracks)] });
                }
                case 'add': {
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    await interaction.deferReply();
                    const { resolveQuery } = require('../utils/music/providers/registry');
                    const track = await resolveQuery(interaction.options.getString('query'), { searchLimit: 1 });
                    await store().addPlaylistTrack(pl.id, track, { addedBy: interaction.user.id });
                    return interaction.editReply({ embeds: [ui.successEmbed('➕ Added', `**${track.title}** added to “${pl.name}”.`)] });
                }
                case 'remove': {
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    const position = interaction.options.getInteger('position');
                    const ok = await store().removePlaylistTrack(pl.id, position - 1);
                    if (!ok) throw new Error(`No track at position ${position}.`);
                    return interaction.reply({ embeds: [ui.successEmbed('🗑️ Removed', `Removed position ${position} from “${pl.name}”.`)] });
                }
                case 'save': {
                    if (!m) throw new Error('The music service is not available right now.');
                    const session = m.getSession(guildId);
                    if (!session) throw new Error('Nothing is playing to save.');
                    const isPublic = !!interaction.options.getBoolean('public');
                    const pl = await store().createPlaylist(guildId, { name: interaction.options.getString('name'), isPublic, ownerId: interaction.user.id });
                    const tracks = [session.current, ...session.queue].filter(Boolean).map(t => ({ provider: t.provider, id: t.id, title: t.title, artist: t.artist, durationMs: t.durationMs, url: t.url, artworkUrl: t.artworkUrl }));
                    await store().replacePlaylistTracks(pl.id, tracks, { addedBy: interaction.user.id });
                    return interaction.reply({ embeds: [ui.successEmbed('💾 Saved', `Saved ${tracks.length} track(s) to **#${pl.id}** ${pl.name}.`)] });
                }
                case 'play':
                case 'queue': {
                    if (!m) throw new Error('The music service is not available right now.');
                    const pl = await loadOwned(interaction, interaction.options.getInteger('id'));
                    const rows = await store().listPlaylistTracks(pl.id);
                    if (!rows.length) throw new Error('That playlist is empty.');
                    await interaction.deferReply();
                    const tracks = rows.map(r => ({ provider: r.provider, id: r.trackId, title: r.title, artist: r.artist, durationMs: r.durationMs, url: r.url, artworkUrl: r.artworkUrl }));
                    const voiceChannelId = interaction.member && interaction.member.voice ? interaction.member.voice.channelId : null;
                    const session = m.getSession(guildId);
                    const channelId = voiceChannelId || (session && session.channelId) || null;
                    if (!channelId) return interaction.editReply({ embeds: [ui.errorEmbed('Join a voice channel first.')] });
                    const { getSettings } = require('../utils/music/musicStore');
                    const settings = await getSettings(guildId).catch(() => ({}));
                    const s = m._ensureSession(guildId, channelId, settings || {});
                    if (!s) return interaction.editReply({ embeds: [ui.errorEmbed('This node does not own that guild.')] });
                    s.channelId = channelId;
                    await m._ensureConnected(s);
                    m.enqueue(s, tracks, { requesterId: interaction.user.id });
                    if (sub === 'play') { s.queue = tracks.map(t => ({ ...t, _key: `${t.provider}:${t.id}` })); }
                    await m._playNext(s);
                    return interaction.editReply({ embeds: [ui.successEmbed('▶️ Playlist', `${sub === 'play' ? 'Playing' : 'Queued'} **${pl.name}** (${tracks.length} track(s)).`)] });
                }
                default:
                    return interaction.reply({ embeds: [ui.errorEmbed('Unknown playlist subcommand.')], flags: MessageFlags.Ephemeral });
            }
        } catch (err) {
            const payload = { embeds: [ui.errorEmbed(err.message || 'Something went wrong.')] };
            if (interaction.deferred || interaction.replied) return interaction.editReply(payload).catch(() => {});
            return interaction.reply(payload).catch(() => {});
        }
    },
};
