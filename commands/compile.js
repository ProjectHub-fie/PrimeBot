const { SlashCommandBuilder, MessageFlags } = require('discord.js');
const {
    buildLanguagesCard,
    languageChoices,
    runCompileRequest,
} = require('../utils/compile/compileCommand');
const { buildHelpPayload } = require('../utils/compile/compileView');

/**
 * /compile — compile and run code through the configured execution provider
 * (Judge0 CE by default). The prefix equivalent is `$compile`.
 *
 * Discord cannot mix top-level options with subcommands, so the run form is
 * `/compile run language:<language> code:<code> [stdin:<input>]`, alongside
 * `/compile languages` and `/compile help`.
 */
module.exports = {
    data: new SlashCommandBuilder()
        .setName('compile')
        .setDescription('Compile and run code in 12 languages')
        .setDMPermission(false)
        .addSubcommand(sub => sub
            .setName('run')
            .setDescription('Compile and run a snippet')
            .addStringOption(option => option
                .setName('language')
                .setDescription('Programming language (python, javascript, cpp, …)')
                .setRequired(true)
                .setAutocomplete(true))
            .addStringOption(option => option
                .setName('code')
                .setDescription('Source code (max 15 KB)')
                .setRequired(true))
            .addStringOption(option => option
                .setName('stdin')
                .setDescription('Program input (max 5 KB)')
                .setRequired(false)))
        .addSubcommand(sub => sub
            .setName('languages')
            .setDescription('List the supported languages and their provider ids'))
        .addSubcommand(sub => sub
            .setName('help')
            .setDescription('How to use /compile')),

    async autocomplete(interaction) {
        try {
            const focused = interaction.options.getFocused(true);
            if (focused.name !== 'language') return interaction.respond([]);
            return await interaction.respond(await languageChoices({ query: focused.value }));
        } catch (err) {
            console.error('[COMPILE] Autocomplete failed:', err && err.message ? err.message : err);
            return interaction.respond([]).catch(() => {});
        }
    },

    async execute(interaction) {
        const sub = interaction.options.getSubcommand(false) || 'help';

        if (sub === 'help') {
            return interaction.reply({
                ...buildHelpPayload('/'),
                flags: MessageFlags.IsComponentsV2 | MessageFlags.Ephemeral,
            }).catch(() => {});
        }

        // Both remaining paths are slow enough to need a deferred reply.
        await interaction.deferReply();

        if (sub === 'languages') {
            const payload = await buildLanguagesCard();
            return interaction.editReply(payload).catch(() => {});
        }

        const language = interaction.options.getString('language');
        const code = interaction.options.getString('code');
        const stdin = interaction.options.getString('stdin') || '';

        return runCompileRequest({
            userId: interaction.user.id,
            guildId: interaction.guildId || null,
            language,
            code,
            stdin,
            edit: payload => interaction.editReply(payload),
        });
    },
};
