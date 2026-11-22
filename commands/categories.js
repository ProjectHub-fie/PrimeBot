const { SlashCommandBuilder } = require('discord.js');
const { scheduleComponentExpiry } = require('../utils/stabilityUtils');
const {
    mainMenuEmbed,
    categoryEmbed,
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
    const embed = mainMenuEmbed('/', interaction.client, {
        user: interaction.user,
        kind: 'slash',
    });

    await interaction.reply({
        embeds: [embed],
        components: [categorySelectRow(null, 'category_select'), homeButtonRow('categories_refresh')],
    });
    const sent = await interaction.fetchReply().catch(() => null);
    scheduleComponentExpiry(sent || interaction.message || { editReply: () => {} });
}

async function showCategoryDetails(interaction, category) {
    const embed = categoryEmbed(category, '/', {
        iconURL: interaction.client?.user?.displayAvatarURL?.({ dynamic: true }),
    });

    await interaction.update({
        embeds: [embed],
        components: [categorySelectRow(category, 'category_select'), homeButtonRow('categories_refresh')],
    });
    scheduleComponentExpiry(interaction.message);
}

module.exports.showCategorySelector = showCategorySelector;
module.exports.showCategoryDetails = showCategoryDetails;
