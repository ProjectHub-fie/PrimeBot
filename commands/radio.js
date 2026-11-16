const { SlashCommandBuilder, PermissionFlagsBits, ChannelType, MessageFlags } = require('discord.js');
const { statusEmbed, stationsEmbed, successEmbed, errorEmbed } = require('../utils/radioEmbed');
const { VALID_SOURCES } = require('../shared/radioConstants');

/**
 * /radio — manage the 24/7 SoundCloud radio.
 *
 * Subcommands:
 *   start    — start radio in the current (or given) voice channel
 *   stop     — stop radio and disconnect (administrators)
 *   pause    — manually pause (a listener joining will NOT resume)
 *   resume   — resume after a manual pause
 *   skip     — skip the current track
 *   station  — select a station
 *   stations — list available stations
 *   status   — show the current radio status
 *   volume   — set the volume (0-100)
 *   channel  — set the permanent radio voice channel
 *
 * Permission model (mirrors the rest of PrimeBot): configuration / lifecycle
 * actions (start, stop, station, channel) require ManageGuild; everyday
 * playback controls (pause, resume, skip, volume) require the member to be
 * connected to the radio channel OR ManageGuild. Status/stations are open.
 */

const ADMIN_SUBCOMMANDS = new Set(['start', 'stop', 'station', 'channel']);
const PLAYBACK_SUBCOMMANDS = new Set(['pause', 'resume', 'skip', 'volume']);

function isAdmin(member) {
    return !!member && (member.permissions.has(PermissionFlagsBits.ManageGuild) || member.permissions.has(PermissionFlagsBits.Administrator));
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('radio')
        .setDescription('Manage the 24/7 SoundCloud radio')
        .setDMPermission(false)
        .addSubcommand(sub => sub.setName('start').setDescription('Start the radio in a voice channel')
            .addChannelOption(o => o.setName('channel').setDescription('Voice channel (defaults to yours)').addChannelTypes(ChannelType.GuildVoice, ChannelType.GuildStageVoice)))
        .addSubcommand(sub => sub.setName('stop').setDescription('Stop the radio and disconnect'))
        .addSubcommand(sub => sub.setName('pause').setDescription('Pause playback (listeners joining will not resume it)'))
        .addSubcommand(sub => sub.setName('resume').setDescription('Resume playback after a pause'))
        .addSubcommand(sub => sub.setName('skip').setDescription('Skip the current track'))
        .addSubcommand(sub => sub.setName('station').setDescription('Select a radio station')
            .addStringOption(o => o.setName('id').setDescription('Station id (see /radio stations)').setRequired(true).setAutocomplete(true)))
        .addSubcommand(sub => sub.setName('stations').setDescription('List available radio stations'))
        .addSubcommand(sub => sub.setName('status').setDescription('Show the current radio status'))
        .addSubcommand(sub => sub.setName('volume').setDescription('Set the radio volume (0-100)')
            .addIntegerOption(o => o.setName('level').setDescription('Volume 0-100').setRequired(true).setMinValue(0).setMaxValue(100)))
        .addSubcommand(sub => sub.setName('channel').setDescription('Set the permanent radio voice channel')
            .addChannelOption(o => o.setName('channel').setDescription('Voice channel').setRequired(true).addChannelTypes(ChannelType.GuildVoice, ChannelType.GuildStageVoice))),

    async autocomplete(interaction) {
        const focused = interaction.options.getFocused(true);
        if (focused.name !== 'id') return interaction.respond([]);
        const manager = interaction.client.radioManager;
        const stations = manager ? manager.stations.listForGuild(interaction.guild.id) : [];
        const q = String(focused.value || '').toLowerCase();
        const matches = stations
            .filter(s => s.enabled && (!q || s.name.toLowerCase().includes(q) || s.id.includes(q)))
            .slice(0, 25)
            .map(s => ({ name: `${s.name} (${s.id})`.slice(0, 100), value: s.id }));
        return interaction.respond(matches);
    },

    async execute(interaction) {
        if (!interaction.guild) {
            return interaction.reply({ content: 'This command can only be used inside a server.', flags: MessageFlags.Ephemeral });
        }
        const manager = interaction.client.radioManager;
        if (!manager) {
            return interaction.reply({ embeds: [errorEmbed('The radio service is not available right now.')], flags: MessageFlags.Ephemeral });
        }
        const sub = interaction.options.getSubcommand();
        const guildId = interaction.guild.id;

        // Permission checks.
        if (ADMIN_SUBCOMMANDS.has(sub) && !isAdmin(interaction.member)) {
            return interaction.reply({ embeds: [errorEmbed('You need the **Manage Server** permission to configure the radio.')], flags: MessageFlags.Ephemeral });
        }
        if (PLAYBACK_SUBCOMMANDS.has(sub) && !isAdmin(interaction.member)) {
            // Non-admins may only control playback if they are in the radio channel.
            const session = manager.getSession(guildId);
            const inRadio = session && interaction.member.voice && interaction.member.voice.channelId === session.channelId;
            if (!inRadio) {
                return interaction.reply({ embeds: [errorEmbed('Join the radio voice channel (or have **Manage Server**) to control playback.')], flags: MessageFlags.Ephemeral });
            }
        }

        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

        try {
            switch (sub) {
                case 'start': {
                    const channel = interaction.options.getChannel('channel') || (interaction.member.voice && interaction.member.voice.channel);
                    if (!channel) return interaction.editReply({ embeds: [errorEmbed('Join a voice channel or pass the `channel` option.')] });
                    const status = await manager.start(guildId, channel.id, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [successEmbed('📻 Radio started', `Now broadcasting in <#${channel.id}>.`), statusEmbed(status)] });
                }
                case 'stop': {
                    const ok = await manager.stop(guildId, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [ok ? successEmbed('📻 Radio stopped', 'Disconnected and cleared the session.') : errorEmbed('Radio is not active in this server.')] });
                }
                case 'pause': {
                    const status = await manager.pause(guildId, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [statusEmbed(status)] });
                }
                case 'resume': {
                    const status = await manager.resume(guildId, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [statusEmbed(status)] });
                }
                case 'skip': {
                    const status = await manager.skip(guildId, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [statusEmbed(status)] });
                }
                case 'station': {
                    const id = interaction.options.getString('id');
                    const status = await manager.setStation(guildId, id, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [statusEmbed(status)] });
                }
                case 'stations': {
                    const session = manager.getSession(guildId);
                    const stations = manager.stations.listForGuild(guildId).filter(s => s.enabled);
                    return interaction.editReply({ embeds: [stationsEmbed(stations, session && session.stationId)] });
                }
                case 'status': {
                    return interaction.editReply({ embeds: [statusEmbed(manager.describe(guildId))] });
                }
                case 'volume': {
                    const level = interaction.options.getInteger('level');
                    const status = await manager.setVolume(guildId, level, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [statusEmbed(status)] });
                }
                case 'channel': {
                    const channel = interaction.options.getChannel('channel');
                    // Reconfigure the permanent channel: if radio is running,
                    // restart it in the new channel; otherwise persist the config.
                    const session = manager.getSession(guildId);
                    if (session && session.enabled) {
                        const status = await manager.start(guildId, channel.id, { stationId: session.stationId, actor: interaction.user.id });
                        return interaction.editReply({ embeds: [successEmbed('📻 Radio channel updated', `Moved to <#${channel.id}>.`), statusEmbed(status)] });
                    }
                    await manager.setChannel(guildId, channel.id, { actor: interaction.user.id });
                    return interaction.editReply({ embeds: [successEmbed('📻 Radio channel set', `The radio will use <#${channel.id}>.`)] });
                }
                default:
                    return interaction.editReply({ embeds: [errorEmbed('Unknown subcommand.')] });
            }
        } catch (err) {
            return interaction.editReply({ embeds: [errorEmbed(err.message || 'Something went wrong.')] });
        }
    },
};
