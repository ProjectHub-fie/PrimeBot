/**
 * Linix `src/events/Client/interactionCreate.js` — the music portion.
 *
 * Preserved from Linix: the slash-command dispatch with its permission gates
 * (`botPerms`/`userPerms`), the `player` / `inVoiceChannel` / `sameVoiceChannel`
 * preconditions, and `command.run(client, interaction, prefix)`. The same
 * preconditions and the same call shape are used, so the vendored commands run
 * unmodified.
 *
 * PrimeBot adaptations (integration only):
 *   • the music slash commands live in `client.slashCommands` (their own tree),
 *     so they are dispatched here and never merged into `client.commands` —
 *     PrimeBot's own slash commands keep working untouched;
 *   • Linix's prefix lookup (a Mongo `prefix` collection) is replaced by
 *     PrimeBot's per-guild prefix from the server-settings manager;
 *   • the now-playing control buttons are handled by the collector Linix itself
 *     attaches to the player message, so the router only has to let the
 *     interaction pass through to it (PrimeBot's own button switch is skipped
 *     for music custom ids).
 */

const { EmbedBuilder, MessageFlags } = require('discord.js');
const { resolvePerms } = require('./utils/perms');

/**
 * customIds owned by the Linix collectors (the now-playing control row, the
 * filter select, the search select and the queue/playlist pagination rows).
 * PrimeBot's generic button/select switch must not consume them: each is
 * answered by the collector Linix attaches to the message that owns it, and
 * double-answering fails the interaction ("This button is not currently
 * functional" / "already acknowledged").
 */
const MUSIC_CUSTOM_IDS = new Set([
    // now-playing control row + filter select
    'disable_h',
    'select-song',
    'pause', 'resume', 'skip', 'stop', 'loop', 'shuffle',
    'clearbut', 'bassbut', '8dbut', 'nightbut', 'pitchbut',
    'lofibut', 'distortbut', 'speedbut', 'vapobut',
    // prefix queue pagination
    'queue_cmd_but_1', 'queue_cmd_but_2', 'queue_cmd_but_3',
    // slash queue pagination
    'queue_next', 'queue_prev', 'queue_stop',
    // playlist list / share
    'Previous', 'Next', 'Stop', 'help_pop', 'select-playlist',
]);

/** True when PrimeBot's generic button handler must NOT consume this interaction. */
function isMusicCustomId(customId) {
    return MUSIC_CUSTOM_IDS.has(customId);
}

function isMusicSlashCommand(client, interaction) {
    return Boolean(client.slashCommands && client.slashCommands.has(interaction.commandName));
}

function guildPrefix(client, interaction) {
    try {
        return client.serverSettingsManager?.getGuildPrefix?.(interaction.guildId) || client.prefix || '$';
    } catch (_) {
        return client.prefix || '$';
    }
}

/**
 * Dispatch a music slash command. Returns true when it handled the interaction.
 */
async function handleMusicSlash(client, interaction) {
    if (!isMusicSlashCommand(client, interaction)) return false;

    const command = client.slashCommands.get(interaction.commandName);
    const prefix = guildPrefix(client, interaction);
    const embed = new EmbedBuilder().setColor(client.color);

    // Linix's slash modules declare the permission fields as `botPrams` /
    // `userPrams` (typo preserved from the original source). Reading both
    // spellings here means the gates actually run instead of silently passing.
    // `resolvePerms` also maps Linix's SCREAMING_SNAKE names (EMBED_LINKS) to
    // the camelCase flags the installed discord.js resolves — an unrecognized
    // name must not throw and break the command.
    const commandPerms = (key) =>
        command[key] || command[key.replace(/Prams$/, 'Perms')];

    const botPerms = commandPerms('botPrams');
    if (botPerms && !interaction.guild.members.me.permissions.has(resolvePerms(botPerms))) {
        embed.setDescription(`I don't have **\`${botPerms}\`** permission in ${interaction.channel.toString()} to execute this **\`${command.name}\`** command.`);
        await interaction.reply({ embeds: [embed] }).catch(() => {});
        return true;
    }

    const userPerms = commandPerms('userPrams');
    if (userPerms && !interaction.member.permissions.has(resolvePerms(userPerms))) {
        embed.setDescription(`You don't have **\`${userPerms}\`** permission in ${interaction.channel.toString()} to execute this **\`${command.name}\`** command.`);
        await interaction.reply({ embeds: [embed] }).catch(() => {});
        return true;
    }

    const player = client.manager && client.manager.players.get(interaction.guildId);
    if (command.player && !player) {
        const payload = { content: 'There is no player for this guild.', flags: MessageFlags.Ephemeral };
        if (interaction.replied) await interaction.editReply(payload).catch(() => {});
        else await interaction.reply(payload).catch(() => {});
        return true;
    }
    if (command.inVoiceChannel && !(interaction.member.voice && interaction.member.voice.channel)) {
        const payload = { content: 'You must be in a voice channel!', flags: MessageFlags.Ephemeral };
        if (interaction.replied) await interaction.editReply(payload).catch(() => {});
        else await interaction.reply(payload).catch(() => {});
        return true;
    }
    if (command.sameVoiceChannel) {
        if (!interaction.guild || !interaction.guild.members.me) {
            await interaction.reply({
                content: 'An error occurred. It seems the bot is not properly connected to the guild.',
                flags: MessageFlags.Ephemeral,
            }).catch(() => {});
            return true;
        }
        const botVoiceChannel = interaction.guild.members.me.voice.channel;
        const userVoiceChannel = interaction.member.voice.channel;
        if (botVoiceChannel && userVoiceChannel !== botVoiceChannel) {
            await interaction.reply({
                content: `You must be in the same ${botVoiceChannel.toString()} to use this command!`,
                flags: MessageFlags.Ephemeral,
            }).catch(() => {});
            return true;
        }
    }

    try {
        // Same lazy self-heal as the prefix path (see music/prefixRunner.js).
        require('./index').ensureMusicNodes(client);
        await command.run(client, interaction, prefix);
    } catch (error) {
        // A missing Lavalink node is an infrastructure state, not a user error.
        const music = require('./index');
        if (music.isNodeUnavailableError(error)) {
            const status = music.musicNodeStatus(client);
            console.error(
                `[MUSIC] /${command.name}: no usable Lavalink node (registered: ${music.describeNodes(client)}, `
                + `endpoint: ${status.endpoint || 'none'}, state: ${status.stateName}`
                + `${status.lastError ? `, last error: ${status.lastError}` : ''})`,
            );
            const payload = { content: `Music is temporarily unavailable — the audio node \`${status.name}\` isn't connected yet.` };
            if (interaction.replied) await interaction.editReply(payload).catch(() => {});
            else await interaction.reply({ ...payload, flags: MessageFlags.Ephemeral }).catch(() => {});
            return true;
        }
        console.error(`[MUSIC] /${command.name} failed:`, error && error.message ? error.message : error);
        const payload = { content: 'An unexcepted error occured.' };
        if (interaction.replied) await interaction.editReply(payload).catch(() => {});
        else await interaction.reply({ ...payload, flags: MessageFlags.Ephemeral }).catch(() => {});
    }
    return true;
}

module.exports = {
    handleMusicSlash,
    isMusicSlashCommand,
    isMusicCustomId,
    MUSIC_CUSTOM_IDS,
};
