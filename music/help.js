/**
 * `$music` overview card.
 *
 * Linix's `$help` lives in the bot's own help command; PrimeBot keeps its help
 * system, so `$music` (with no subcommand) renders a short pointer to the
 * Linix command tree instead of dumping every command. The command list is read
 * from the loaded tree, so it can never drift.
 */

const { linixEmbed } = require('../utils/linixEmbed');

/**
 * The configured audio-node name (LNODE by default) plus its live state. The
 * Lavalink node is NOT one of the three shard clusters, so it is labelled
 * explicitly to avoid the two being confused.
 */
function nodeLine(client) {
    try {
        // Lazy require: keeps this module loadable before the music subsystem
        // has finished initialising.
        const { musicNodeStatus } = require('./index');
        const status = musicNodeStatus(client);
        const state = status.connected ? 'connected' : (status.registered ? 'connecting' : 'not connected');
        return `\`${status.name}\` — ${state}`;
    } catch (_) {
        return '`LNODE` — not connected';
    }
}

function musicHelpEmbed(client, prefix = '$') {
    const e = (key, fallback) => client.emoji?.[key] || fallback;

    const names = [];
    if (client.musicCommands) {
        for (const cmd of client.musicCommands.values()) {
            if (cmd.category === 'Music' || cmd.category === 'Playlist' || cmd.category === 'Config') {
                names.push(`\`${prefix}${cmd.name}\``);
            }
        }
    }
    names.sort();

    return linixEmbed()
        .a('| Music', client.user ? client.user.displayAvatarURL() : undefined)
        .d(
            `**${e('play', '▶️')} Playback** — \`${prefix}play <song or URL>\`, \`${prefix}search\`, \`${prefix}pause\`, `
            + `\`${prefix}resume\`, \`${prefix}skip\`, \`${prefix}stop\`, \`${prefix}seek\`, \`${prefix}queue\`\n`
            + `**${e('filter', '🎛️')} Extras** — \`${prefix}filter\`, \`${prefix}autoplay\`, \`${prefix}lyrics\`, \`${prefix}grab\`, `
            + `\`${prefix}nowplaying\`, \`${prefix}volume\`, \`${prefix}playlist\`, \`${prefix}247\`\n`
            + `**${e('autoplay', '♾️')} Radio** — \`${prefix}247 enable\` keeps a station playing 24/7 in a voice channel.`,
        )
        .addFields({
            name: `${e('music', '🎵')} Music Commands`,
            value: names.length ? names.join(', ') : 'No music commands loaded',
        })
        .addFields({
            name: 'Lavalink Node',
            value: nodeLine(client),
        })
        .f(names.length ? `${names.length} music commands loaded` : 'Music is not configured on this deployment');
}

module.exports = { musicHelpEmbed };
