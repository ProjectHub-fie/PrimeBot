const { SlashCommandBuilder, MessageFlags } = require('discord.js');
const { scheduleComponentExpiry } = require('../utils/stabilityUtils');
const { emoji } = require('../utils/emoji');
const {
    CATALOG,
    CATEGORY_ORDER,
    buildHelpPayload,
    mainMenuText,
    categoryTitle,
    categoryText,
    categorySelectRow,
    helpActionRow,
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
        try {
            await replyTarget.editReply(buildHelpPayload({
                title: `${frame.emoji()} Loading`,
                text: `${frame.text} ${'·'.repeat(i + 1)}`,
            }));
        } catch (_) {
            break;
        }
        await new Promise(r => setTimeout(r, 450));
    }
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
                    flags: MessageFlags.Ephemeral,
                });
            }
        }
    },
};

async function showMainHelp(interaction) {
    await interaction.editReply(buildHelpPayload({
        text: mainMenuText(),
        rows: [categorySelectRow(null, 'help_select'), helpActionRow()],
    }));
    const sent = await interaction.fetchReply().catch(() => null);
    if (sent) scheduleComponentExpiry(sent);
}

async function showCategoryHelp(interaction, category) {
    await interaction.editReply(buildHelpPayload({
        title: categoryTitle(category),
        text: categoryText(category),
        rows: [categorySelectRow(category, 'help_select'), helpActionRow()],
    }));
    const sent = await interaction.fetchReply().catch(() => null);
    if (sent) scheduleComponentExpiry(sent);
}

module.exports.showMainHelp = showMainHelp;
module.exports.showCategoryHelp = showCategoryHelp;
