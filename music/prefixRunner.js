/**
 * Linix `src/events/Client/messageCreate.js` — the command-execution portion.
 *
 * Preserved from Linix: resolve the command from the music command tree by name or
 * alias, then enforce, in the same order, `botPerms`, `userPerms`, the
 * `player` / `inVoiceChannel` / `sameVoiceChannel` preconditions, and finally
 * `command.execute(message, args, client, prefix)`.
 *
 * PrimeBot adaptations (integration only): the prefix is PrimeBot's per-guild
 * prefix, the invocation errors reply through the message object (PrimeBot has
 * already established the channel is usable), and there is no Linix webhook
 * command-log — PrimeBot's own logging feature covers that.
 */

const { EmbedBuilder } = require('discord.js');
const { resolvePerms } = require('./utils/perms');

function findCommand(client, commandName) {
    const tree = client.musicCommands;
    if (!tree) return null;
    const direct = tree.get(commandName);
    if (direct) return direct;
    for (const cmd of tree.values()) {
        if (cmd.aliases && cmd.aliases.includes(commandName)) return cmd;
    }
    return null;
}

async function runPrefixCommand(client, message, commandName, args, prefix) {
    const command = findCommand(client, commandName);
    if (!command) return;

    const me = message.guild && message.guild.members.me;

    // Linix's modules declare these as `botPrams` / `userPrams` (typo
    // preserved); accept both spellings here too. `resolvePerms` maps Linix's
    // SCREAMING_SNAKE names (EMBED_LINKS) to the camelCase flags the installed
    // discord.js resolves — an unrecognized name must not throw and break the
    // command.
    const commandPerms = (key) =>
        command[key] || command[key.replace(/Prams$/, 'Perms')];

    const botPerms = commandPerms('botPrams');
    if (botPerms && me && !me.permissions.has(resolvePerms(botPerms))) {
        return message.channel.send({
            embeds: [new EmbedBuilder().setColor(client.color).setDescription(
                `I don't have **\`${botPerms}\`** permission in <#${message.channelId}> to execute this **\`${command.name}\`** command.`,
            )],
        }).catch(() => null);
    }

    const userPerms = commandPerms('userPrams');
    if (userPerms && message.member && !message.member.permissions.has(resolvePerms(userPerms))) {
        return message.channel.send({
            embeds: [new EmbedBuilder().setColor(client.color).setDescription(
                `You don't have **\`${userPerms}\`** permission in <#${message.channelId}> to execute this **\`${command.name}\`** command.`,
            )],
        }).catch(() => null);
    }

    const player = client.manager && client.manager.players.get(message.guild.id);

    if (command.player && !player) {
        return message.channel.send('i\'m not in any vc!').catch(() => null);
    }

    if (command.inVoiceChannel && !(message.member.voice && message.member.voice.channelId)) {
        return message.channel.send({
            embeds: [new EmbedBuilder().setColor(client.color).setAuthor({
                name: 'Your are not in any vc',
                iconURL: message.author.displayAvatarURL(),
            })],
        }).catch(() => null);
    }

    if (command.sameVoiceChannel && me && me.voice.channel) {
        if (me.voice.channelId !== (message.member.voice && message.member.voice.channelId)) {
            return message.channel.send({
                embeds: [new EmbedBuilder().setColor(client.color).setAuthor({
                    name: 'Your are not in same vc',
                    iconURL: message.author.displayAvatarURL(),
                })],
            }).catch(() => null);
        }
    }

    // Kazagumo resolves the node lazily, so a registration that failed at boot
    // would break every music command until a restart. Heal it here (throttled).
    const { ensureMusicNodes, describeNodes, isNodeUnavailableError, musicNodeStatus } = require('./index');
    ensureMusicNodes(client);

    return command.execute(message, args, client, prefix).catch((err) => {
        // No usable Lavalink node is an infrastructure state, not a user error —
        // say so plainly (naming the audio node) instead of surfacing a provider
        // stack trace, and log the sanitized endpoint/state to diagnose it.
        if (isNodeUnavailableError(err)) {
            const status = musicNodeStatus(client);
            console.error(
                `[MUSIC] $${command.name}: no usable Lavalink node (registered: ${describeNodes(client)}, `
                + `endpoint: ${status.endpoint || 'none'}, state: ${status.stateName}`
                + `${status.lastError ? `, last error: ${status.lastError}` : ''})`,
            );
            return message.channel.send(
                `Music is temporarily unavailable — the audio node \`${status.name}\` isn't connected yet.`,
            ).catch(() => null);
        }
        console.error(`[MUSIC] $${command.name} failed:`, err && err.message ? err.message : err);
    });
}


module.exports = { runPrefixCommand, findCommand };
