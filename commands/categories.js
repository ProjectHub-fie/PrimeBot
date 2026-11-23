const { SlashCommandBuilder } = require('discord.js');
const { scheduleComponentExpiry } = require('../utils/stabilityUtils');
const {
    buildHelpPayload,
    mainMenuText,
    categoryTitle,
    categoryText,
    categorySelectRow,
    homeButtonRow,
} = require('../utils/prefixHelp');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('categories')
        .setDescription('Browse commands by category with interactive menus')
        .setDefaultMemberPermissions('0'),

    async execute(interaction) {
        await showCategorySelector(interaction);
    },
};

async function showCategorySelector(interaction) {
    await interaction.reply(buildHelpPayload({
        text: mainMenuText({ prefix: '/', client: interaction.client }),
        rows: [categorySelectRow(null, 'category_select'), homeButtonRow('categories_refresh')],
    }));
    const sent = await interaction.fetchReply().catch(() => null);
    if (sent) scheduleComponentExpiry(sent);
}

async function showCategoryDetails(interaction, category) {
    await interaction.update(buildHelpPayload({
        title: categoryTitle(category),
        text: categoryText(category, { prefix: '/', client: interaction.client }),
        rows: [categorySelectRow(category, 'category_select'), homeButtonRow('categories_refresh')],
    }));
    scheduleComponentExpiry(interaction.message);
}

module.exports.showCategorySelector = showCategorySelector;
module.exports.showCategoryDetails = showCategoryDetails;
