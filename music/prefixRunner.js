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

const { EmbedBuilder, PermissionsBitField } = require('discord.js');

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
    // preserved); accept both spellings here too.
    const commandPerms = (key) =>
        command[key] || command[key.replace(/Prams$/, 'Perms')];

    const botPerms = commandPerms('botPrams');
    if (botPerms && me && !me.permissions.has(PermissionsBitField.resolve(botPerms || []))) {
        return message.channel.send({
            embeds: [new EmbedBuilder().setColor(client.color).setDescription(
                `I don't have **\`${botPerms}\`** permission in <#${message.channelId}> to execute this **\`${command.name}\`** command.`,
            )],
        }).catch(() => null);
    }

    const userPerms = commandPerms('userPrams');
    if (userPerms && message.member && !message.member.permissions.has(PermissionsBitField.resolve(userPerms || []))) {
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

    return command.execute(message, args, client, prefix).catch((err) => {
        console.error(`[MUSIC] $${command.name} failed:`, err);
    });
}

module.exports = { runPrefixCommand, findCommand };
