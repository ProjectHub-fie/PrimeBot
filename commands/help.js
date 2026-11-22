const { SlashCommandBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');
const { scheduleComponentExpiry } = require('../utils/stabilityUtils');
const { emoji } = require('../utils/emoji');
const { linixEmbed } = require('../utils/linixEmbed');
const {
    CATALOG,
    CATEGORY_ORDER,
    mainMenuEmbed,
    categoryEmbed,
    categorySelectRow,
    homeButtonRow,
} = require('../utils/prefixHelp');

// Discord embeds cannot animate, so the loading state is a short sequence of
// edited frames before the real menu appears (same trick Linix uses elsewhere).
const HELP_ANIMATION_FRAMES = [
    { emoji: () => emoji('loading', '🌌'), text: 'Summoning the command menu' },
    { emoji: () => emoji('extra', '✨'), text: 'Gathering all PrimeBot commands' },
    { emoji: () => emoji('information', '📚'), text: 'Almost there — organizing categories' },
];

async function playHelpAnimation(replyTarget) {
    for (let i = 0; i < HELP_ANIMATION_FRAMES.length; i++) {
        const frame = HELP_ANIMATION_FRAMES[i];
        const embed = linixEmbed()
            .t(`${frame.emoji()} Loading`)
            .d(`${frame.text} ${'·'.repeat(i + 1)}`)
            .f(`PrimeBot • Version ${config.version}`);
        try {
            await replyTarget.editReply({ embeds: [embed], components: [] });
        } catch (_) {
            break;
        }
        await new Promise(r => setTimeout(r, 450));
    }
}

function helpActionRow() {
    const row = homeButtonRow('help_back');
    row.addComponents(
        new ButtonBuilder()
            .setCustomId('help_prefix')
            .setLabel('Sash')
            .setStyle(ButtonStyle.Secondary)
            .setEmoji(emoji('utility', '💬')),
        new ButtonBuilder()
            .setLabel('Support')
            .setStyle(ButtonStyle.Link)
            .setURL(config.supportServer || 'https://discord.gg/primebot')
            .setEmoji(emoji('information', '🆘')),
    );
    return row;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('help')
        .setDescription('Shows a categorized list of all available commands')
        .setDefaultMemberPermissions('0')
        .addStringOption(option =>
            option.setName('category')
                .setDescription('Choose a specific category to view')
                .setRequired(false)
                .addChoices(
                    ...CATEGORY_ORDER.map(key => ({ name: CATALOG[key].label, value: key })),
                )),

    async execute(interaction) {
        try {
            const category = interaction.options.getString('category');

            await interaction.deferReply();
            await playHelpAnimation(interaction);

            if (category) {
                await showCategoryHelp(interaction, category);
            } else {
                await showMainHelp(interaction);
            }
        } catch (error) {
            console.error('[HELP] Error executing help command:', error);
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: 'There was an error displaying the help menu. Please try again later.',
                    ephemeral: true,
                });
            }
        }
    },
};

async function showMainHelp(interaction) {
    const mainEmbed = mainMenuEmbed('/', interaction.client, {
        user: interaction.user,
        kind: 'slash',
    });

    await interaction.editReply({
        embeds: [mainEmbed],
        components: [categorySelectRow(null, 'help_select'), helpActionRow()],
    });
    const sent = await interaction.fetchReply().catch(() => null);
    scheduleComponentExpiry(sent || interaction.message || { editReply: () => {} });
}

async function showCategoryHelp(interaction, category) {
    const embed = categoryEmbed(category, '/', {
        iconURL: interaction.client?.user?.displayAvatarURL?.({ dynamic: true }),
    });

    await interaction.editReply({
        embeds: [embed],
        components: [categorySelectRow(category, 'help_select'), helpActionRow()],
    });
    const sent = await interaction.fetchReply().catch(() => null);
    scheduleComponentExpiry(sent || interaction.message || { editReply: () => {} });
}

module.exports.showMainHelp = showMainHelp;
module.exports.showCategoryHelp = showCategoryHelp;
