const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');
const { logError } = require('../utils/logUtils');
const { toMessagePayload } = require('../shared/embedPayload');
const { findSavedEmbed, listSavedEmbeds, savedEmbedNames } = require('../utils/savedEmbedStore');

const FOOTER = `Embed Builder • Version ${config.version}`;

function errorEmbed(description) {
    return new EmbedBuilder()
        .setColor(config.colors.error)
        .setTitle('❌ Embed not sent')
        .setDescription(description)
        .setFooter({ text: FOOTER });
}

/**
 * /embed — post an embed built in the dashboard's Embed Builder.
 *
 * Embeds are created and saved on the dashboard (Features → Embed); these
 * subcommands just send an existing one into a channel.
 */
module.exports = {
    data: new SlashCommandBuilder()
        .setName('embed')
        .setDescription('Send an embed saved in the dashboard Embed Builder')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .setDMPermission(false)
        .addSubcommand(sub =>
            sub.setName('send')
                .setDescription('Send a saved embed to a channel')
                .addStringOption(opt =>
                    opt.setName('embed')
                        .setDescription('Which saved embed to send')
                        .setRequired(true)
                        .setAutocomplete(true))
                .addChannelOption(opt =>
                    opt.setName('channel')
                        .setDescription('Channel to send it in (defaults to the current channel)')
                        .setRequired(false)))
        .addSubcommand(sub =>
            sub.setName('list')
                .setDescription('List the embeds saved for this server')),

    async autocomplete(interaction) {
        const focused = interaction.options.getFocused();
        const choices = await savedEmbedNames(interaction.guildId, focused);
        await interaction.respond(choices).catch(() => {});
    },

    async execute(interaction) {
        const subcommand = interaction.options.getSubcommand();

        if (subcommand === 'list') return listEmbeds(interaction);
        return sendEmbed(interaction);
    },
};

async function listEmbeds(interaction) {
    try {
        const embeds = await listSavedEmbeds(interaction.guildId);
        if (!embeds.length) {
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(config.colors.warning)
                    .setTitle('📋 No saved embeds')
                    .setDescription('Build one on the dashboard under **Features → Embed**, then send it with `/embed send`.')
                    .setFooter({ text: FOOTER })],
                ephemeral: true,
            });
        }

        const lines = embeds.map((e, i) => `**${i + 1}.** ${e.name} — \`/embed send embed:${e.name}\``);
        return interaction.reply({
            embeds: [new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('📋 Saved embeds')
                .setDescription(lines.join('\n').slice(0, 4096))
                .setFooter({ text: `${embeds.length} saved embed(s) • ${FOOTER}` })],
            ephemeral: true,
        });
    } catch (error) {
        logError('Embed list command', error);
        return interaction.reply({ embeds: [errorEmbed('I could not load the saved embeds.')], ephemeral: true });
    }
}

async function sendEmbed(interaction) {
    try {
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) {
            return interaction.reply({
                embeds: [errorEmbed('You need the **Manage Server** permission to send saved embeds.')],
                ephemeral: true,
            });
        }

        const query = interaction.options.getString('embed');
        const channel = interaction.options.getChannel('channel') || interaction.channel;

        const record = await findSavedEmbed(interaction.guildId, query);
        if (!record) {
            return interaction.reply({
                embeds: [errorEmbed(`No saved embed named **${query}** was found. Use \`/embed list\` to see the available embeds.`)],
                ephemeral: true,
            });
        }

        const payload = toMessagePayload(record.payload);
        if (!payload) {
            return interaction.reply({
                embeds: [errorEmbed(`**${record.name}** has no content to send — open it in the Embed Builder and save it again.`)],
                ephemeral: true,
            });
        }

        await interaction.deferReply({ ephemeral: true });

        const me = interaction.guild?.members?.me;
        const perms = me && channel.permissionsFor ? channel.permissionsFor(me) : null;
        if (perms && (!perms.has(PermissionFlagsBits.SendMessages) || !perms.has(PermissionFlagsBits.EmbedLinks))) {
            return interaction.editReply({
                embeds: [errorEmbed(`I need **Send Messages** and **Embed Links** in <#${channel.id}> to post there.`)],
            });
        }

        const sent = await channel.send(payload);

        await interaction.editReply({
            embeds: [new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('✅ Embed sent')
                .setDescription(`Posted **${record.name}** in <#${channel.id}> — [jump to message](${sent.url}).`)
                .setFooter({ text: FOOTER })],
        });
    } catch (error) {
        logError('Embed send command', error);
        const message = errorEmbed('Something went wrong while sending that embed. Please try again.');
        try {
            if (interaction.deferred || interaction.replied) await interaction.editReply({ embeds: [message] });
            else await interaction.reply({ embeds: [message], ephemeral: true });
        } catch (_) { /* interaction already gone */ }
    }
}