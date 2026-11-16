/**
 * Shared radio embeds — used by BOTH the slash command (commands/radio.js) and
 * the prefix command handler (events/messageCreate.js), so both paths render
 * identical output (the same pattern as utils/npEmbed.js and utils/devEmbed.js).
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { RADIO_STATES, SOURCE_LABELS } = require('../shared/radioConstants');

const STATE_META = {
    [RADIO_STATES.STOPPED]: { label: 'Stopped', color: config.colors.error, icon: '⏹️' },
    [RADIO_STATES.CONNECTING]: { label: 'Connecting…', color: config.colors.warning, icon: '🔄' },
    [RADIO_STATES.PLAYING]: { label: 'Playing', color: config.colors.success, icon: '▶️' },
    [RADIO_STATES.PAUSED_EMPTY]: { label: 'Paused (channel empty)', color: config.colors.warning, icon: '⏸️' },
    [RADIO_STATES.PAUSED_MANUAL]: { label: 'Paused (by an admin)', color: config.colors.warning, icon: '⏸️' },
    [RADIO_STATES.IDLE]: { label: 'Idle', color: config.colors.secondary, icon: '💤' },
};

function stateLabel(state) {
    return (STATE_META[state] || STATE_META[RADIO_STATES.STOPPED]).label;
}

function footer(embed) {
    return embed.setFooter({ text: `PrimeBot Radio • v${config.version}` }).setTimestamp();
}

function statusEmbed(status) {
    if (!status) {
        return footer(new EmbedBuilder()
            .setColor(config.colors.secondary)
            .setTitle('📻 Radio')
            .setDescription('Radio is **not active** in this server.\n\nUse `/radio start` in a voice channel to begin.'));
    }
    const meta = STATE_META[status.state] || STATE_META[RADIO_STATES.STOPPED];
    const track = status.currentTrack;
    const trackLine = track
        ? `**${track.title || 'Unknown'}**${track.artist && track.artist.username ? ` — ${track.artist.username}` : ''}`
        : '—';

    const embed = new EmbedBuilder()
        .setColor(meta.color)
        .setTitle(`${meta.icon} Radio — ${meta.label}`)
        .addFields(
            { name: 'Station', value: status.stationName || status.stationId || '—', inline: true },
            { name: 'Voice channel', value: status.channelId ? `<#${status.channelId}>` : '—', inline: true },
            { name: 'Listeners', value: String(status.listeners ?? 0), inline: true },
            { name: 'Now playing', value: trackLine, inline: false },
            { name: 'Queue', value: `${status.queueLength || 0} track(s)`, inline: true },
            { name: 'Connection', value: status.connected ? 'Connected' : 'Disconnected', inline: true },
        );
    if (track && track.artworkUrl) embed.setThumbnail(track.artworkUrl);
    return footer(embed);
}

function stationsEmbed(stations, currentId) {
    const lines = stations.length
        ? stations.map(s => {
            const active = s.id === currentId ? ' ✅' : '';
            const scope = s.guildId ? '' : ' *(global)*';
            return `**${s.name}**${active}${scope}\n\`${s.id}\` · ${SOURCE_LABELS[s.source] || s.source}${s.genre ? ` · ${s.genre}` : ''}`;
        })
        : ['No stations available.'];
    return footer(new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📻 Radio stations')
        .setDescription(lines.join('\n\n'))
        .addFields({ name: 'Select one', value: 'Use `/radio station <id>` to switch.' }));
}

function successEmbed(title, description) {
    return footer(new EmbedBuilder().setColor(config.colors.success).setTitle(title).setDescription(description));
}

function errorEmbed(description) {
    return footer(new EmbedBuilder().setColor(config.colors.error).setTitle('📻 Radio').setDescription(description));
}

module.exports = { statusEmbed, stationsEmbed, successEmbed, errorEmbed, stateLabel, STATE_META };
