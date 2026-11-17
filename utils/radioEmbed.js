/**
 * Shared radio embeds — used by BOTH the slash command (commands/radio.js) and
 * the prefix command handler (events/messageCreate.js), so both paths render
 * identical output (the same pattern as utils/npEmbed.js and utils/devEmbed.js).
 *
 * The layout reuses the music presentation language (artwork thumbnail, a
 * colour-coded state pill, a numbered/structured field grid) so the radio feels
 * like part of the same premium console — the radio ENGINE and station database
 * are untouched.
 */

const { EmbedBuilder, ActionRowBuilder, StringSelectMenuBuilder, StringSelectMenuOptionBuilder } = require('discord.js');
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
        ? `**[${track.title || 'Unknown'}](${track.url || 'https://soundcloud.com'})**${track.artist && track.artist.username ? ` — ${track.artist.username}` : ''}`
        : '—';

    const embed = new EmbedBuilder()
        .setColor(meta.color)
        .setAuthor({ name: `${meta.icon} Radio — ${meta.label}` })
        .setDescription(trackLine)
        .addFields(
            { name: 'Station', value: status.stationName || status.stationId || '—', inline: true },
            { name: 'Voice channel', value: status.channelId ? `<#${status.channelId}>` : '—', inline: true },
            { name: 'Listeners', value: `🎧 ${status.listeners ?? 0}`, inline: true },
            { name: 'Queue', value: `${status.queueLength || 0} track(s)`, inline: true },
            { name: 'Connection', value: status.connected ? '🟢 Connected' : '🔴 Disconnected', inline: true },
            { name: 'Position', value: `Track #${(status.positionIndex || 0) + 1}`, inline: true },
        );
    if (track && track.artworkUrl) embed.setThumbnail(track.artworkUrl);
    return footer(embed);
}

/** A station dropdown (select menu) — ≤25 options, disabled ones excluded. */
function stationSelectRow(stations, currentId, { customId = 'radio_station_select' } = {}) {
    const usable = (stations || []).filter(s => s.enabled).slice(0, 25);
    if (!usable.length) return null;
    const menu = new StringSelectMenuBuilder()
        .setCustomId(customId)
        .setPlaceholder(currentId ? `Station: ${(stations.find(s => s.id === currentId) || {}).name || currentId}` : '📻 Select a station')
        .addOptions(usable.map(s => new StringSelectMenuOptionBuilder()
            .setLabel(String(s.name).slice(0, 95))
            .setDescription(`${SOURCE_LABELS[s.source] || s.source}${s.genre ? ` • ${s.genre}` : ''}`.slice(0, 95))
            .setValue(s.id)
            .setDefault(s.id === currentId)));
    return new ActionRowBuilder().addComponents(menu);
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
        .setFooter({ text: `${stations.length} station(s) • PrimeBot Radio • v${config.version}` })
        .setTimestamp()
        .addFields({ name: 'Select one', value: 'Use `/radio station <id>` to switch.' }));
}

/**
 * The interactive stations view: the stations embed plus a station dropdown
 * (when any station is enabled). Used by the commands so a listener can switch
 * stations without typing an id.
 */
function stationsView(stations, currentId) {
    const embed = stationsEmbed(stations, currentId);
    const row = stationSelectRow(stations, currentId);
    return { embeds: [embed], components: row ? [row] : [] };
}

function successEmbed(title, description) {
    return footer(new EmbedBuilder().setColor(config.colors.success).setTitle(title).setDescription(description));
}

function errorEmbed(description) {
    return footer(new EmbedBuilder().setColor(config.colors.error).setTitle('📻 Radio').setDescription(description));
}

module.exports = { statusEmbed, stationsEmbed, stationsView, stationSelectRow, successEmbed, errorEmbed, stateLabel, STATE_META };
