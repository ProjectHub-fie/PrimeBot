const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');

/**
 * /autoresponder — configure the Auto-Responder from Discord.
 *
 * Subcommands (mirror the dashboard's Auto-Responder tab + the prefix command):
 *   enable / disable / status / list
 *   add      (trigger, response, exact)   — contains match by default
 *   remove   (trigger)
 *
 * The bot and dashboard share the same server_settings row (auto_responder
 * JSONB column), so changes made here appear in the dashboard (and vice-versa)
 * within the cache reload window (~30s).
 */

module.exports = {
    data: new SlashCommandBuilder()
        .setName('autoresponder')
        .setDescription('Configure the Auto-Responder (automatic replies to trigger words)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .addSubcommand(sub => sub.setName('enable').setDescription('Enable the auto-responder'))
        .addSubcommand(sub => sub.setName('disable').setDescription('Disable the auto-responder'))
        .addSubcommand(sub => sub.setName('status').setDescription('Show the current auto-responder configuration'))
        .addSubcommand(sub => sub.setName('list').setDescription('List configured auto-responses'))
        .addSubcommand(sub =>
            sub.setName('add')
                .setDescription('Add an auto-response (contains match by default)')
                .addStringOption(o => o.setName('trigger').setDescription('Trigger word/phrase').setRequired(true))
                .addStringOption(o => o.setName('response').setDescription('Reply text to send').setRequired(true))
                .addBooleanOption(o => o.setName('exact').setDescription('Only fire on an EXACT message match (default: false)').setRequired(false)))
        .addSubcommand(sub =>
            sub.setName('remove')
                .setDescription('Remove an auto-response')
                .addStringOption(o => o.setName('trigger').setDescription('Trigger to remove').setRequired(true))),

    async execute(interaction) {
        const sub = interaction.options.getSubcommand();
        const mgr = interaction.client.serverSettingsManager;
        if (!mgr || typeof mgr.getAutoResponder !== 'function') {
            return interaction.reply({ content: 'Auto-responder is not available right now.', ephemeral: true });
        }
        const guildId = interaction.guild.id;

        switch (sub) {
            case 'enable': {
                let state = mgr.getAutoResponder(guildId);
                if (!state.enabled) state = { enabled: mgr.toggleAutoResponder(guildId), responses: state.responses };
                return interaction.reply({
                    embeds: [new EmbedBuilder()
                        .setColor(0x57F287)
                        .setTitle('✅ Auto-Responder Enabled')
                        .setDescription('Messages containing trigger words will now receive automatic replies.')
                        .setTimestamp()],
                    ephemeral: true,
                });
            }
            case 'disable': {
                let state = mgr.getAutoResponder(guildId);
                if (state.enabled) state = { enabled: mgr.toggleAutoResponder(guildId), responses: state.responses };
                return interaction.reply({
                    embeds: [new EmbedBuilder()
                        .setColor(0xED4245)
                        .setTitle('❌ Auto-Responder Disabled')
                        .setDescription('Automatic replies to trigger words have been disabled.')
                        .setTimestamp()],
                    ephemeral: true,
                });
            }
            case 'status':
            case 'list': {
                const data = mgr.getAutoResponder(guildId);
                if (data.responses.length === 0) {
                    return interaction.reply({
                        embeds: [new EmbedBuilder()
                            .setColor(0x5865F2)
                            .setTitle('💬 Auto-Responder')
                            .setDescription(`Status: **${data.enabled ? 'Enabled' : 'Disabled'}**\n\nNo auto-responses configured yet. Use \`/autoresponder add\`.`)],
                        ephemeral: true,
                    });
                }
                const fields = data.responses.slice(0, 25).map(r => ({
                    name: `Trigger: ${r.trigger} (${r.exactMatch ? 'exact' : 'contains'})`,
                    value: r.response.length > 200 ? r.response.slice(0, 200) + '…' : r.response,
                    inline: false,
                }));
                return interaction.reply({
                    embeds: [new EmbedBuilder()
                        .setColor(0x5865F2)
                        .setTitle('💬 Auto-Responder List')
                        .setDescription(`Status: **${data.enabled ? 'Enabled' : 'Disabled'}**\nTotal auto-responses: ${data.responses.length}`)
                        .addFields(fields)
                        .setFooter({ text: data.responses.length > 25 ? `Showing first 25 of ${data.responses.length}` : 'PrimeBot Auto-Responder' })
                        .setTimestamp()],
                    ephemeral: true,
                });
            }
            case 'add': {
                const trigger = interaction.options.getString('trigger');
                const response = interaction.options.getString('response');
                const exact = interaction.options.getBoolean('exact') === true;
                mgr.addAutoResponse(guildId, trigger, response, { exactMatch: exact });
                const data = mgr.getAutoResponder(guildId);
                if (!data.enabled) mgr.toggleAutoResponder(guildId);
                return interaction.reply({
                    embeds: [new EmbedBuilder()
                        .setColor(0x57F287)
                        .setTitle('✅ Auto-Response Added')
                        .setDescription(`Trigger: **${trigger}**\nResponse: ${response}\nMatch: **${exact ? 'exact' : 'contains'}**`)
                        .setTimestamp()],
                    ephemeral: true,
                });
            }
            case 'remove': {
                const trigger = interaction.options.getString('trigger');
                const removed = mgr.removeAutoResponse(guildId, trigger);
                if (!removed) {
                    return interaction.reply({ content: `Couldn't find an auto-response with trigger: **${trigger}**`, ephemeral: true });
                }
                return interaction.reply({
                    embeds: [new EmbedBuilder()
                        .setColor(0x57F287)
                        .setTitle('✅ Auto-Response Removed')
                        .setDescription(`Removed auto-response for trigger: **${trigger}**`)
                        .setTimestamp()],
                    ephemeral: true,
                });
            }
            default:
                return interaction.reply({ content: 'Unknown subcommand.', ephemeral: true });
        }
    },
};
