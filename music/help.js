/**
 * `$music` overview card.
 *
 * Linix's `$help` lives in the bot's own help command; PrimeBot keeps its help
 * system, so `$music` (with no subcommand) renders a short pointer to the
 * Linix command tree instead of dumping every command. The command list is read
 * from the loaded tree, so it can never drift.
 */

const { EmbedBuilder } = require('discord.js');

function musicHelpEmbed(client, prefix = '$') {
    const names = [];
    if (client.musicCommands) {
        for (const cmd of client.musicCommands.values()) {
            if (cmd.category === 'Music' || cmd.category === 'Playlist' || cmd.category === 'Config') {
                names.push(`\`${prefix}${cmd.name}\``);
            }
        }
    }
    names.sort();

    return new EmbedBuilder()
        .setColor(client.color)
        .setAuthor({ name: '| Music', iconURL: client.user ? client.user.displayAvatarURL() : undefined })
        .setDescription(
            `**Playback** — \`${prefix}play <song or URL>\`, \`${prefix}search\`, \`${prefix}pause\`, `
            + `\`${prefix}resume\`, \`${prefix}skip\`, \`${prefix}stop\`, \`${prefix}seek\`, \`${prefix}queue\`\n`
            + `**Extras** — \`${prefix}filter\`, \`${prefix}autoplay\`, \`${prefix}lyrics\`, \`${prefix}grab\`, `
            + `\`${prefix}nowplaying\`, \`${prefix}volume\`, \`${prefix}playlist\`, \`${prefix}247\`\n`
            + `**Radio** — \`${prefix}247 enable\` keeps a station playing 24/7 in a voice channel.`,
        )
        .setFooter({ text: names.length ? `${names.length} music commands loaded` : 'Music is not configured on this deployment' });
}

module.exports = { musicHelpEmbed };
