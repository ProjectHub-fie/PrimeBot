const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const config = require('../config');
const betaManager = require('../utils/betaManager');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('betaserver')
        .setDescription('Manage which servers are allowed in the beta program (bot owner only)')
        .setDMPermission(true)
        .addSubcommand(sub =>
            sub.setName('add')
                .setDescription('Add a server to the beta allowed list')
                .addStringOption(opt =>
                    opt.setName('server_id')
                        .setDescription('The Discord server (guild) ID to allow')
                        .setRequired(true))
                .addStringOption(opt =>
                    opt.setName('label')
                        .setDescription('Optional label/name for your reference')
                        .setRequired(false)))
        .addSubcommand(sub =>
            sub.setName('remove')
                .setDescription('Remove a server from the beta allowed list')
                .addStringOption(opt =>
                    opt.setName('server_id')
                        .setDescription('The Discord server (guild) ID to remove')
                        .setRequired(true)))
        .addSubcommand(sub =>
            sub.setName('list')
                .setDescription('List all servers currently on the beta allowed list')),

    async execute(interaction) {
        // Bot owner only
        if (!config.developerIds.includes(interaction.user.id)) {
            return interaction.reply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle('🔒 Bot Owner Only')
                        .setDescription('This command can only be used by the bot owner.')
                        .setTimestamp()
                ],
                ephemeral: true
            });
        }

        await interaction.deferReply({ ephemeral: true });

        const sub = interaction.options.getSubcommand();

        // ── /betaserver add ──────────────────────────────────────────
        if (sub === 'add') {
            const serverId = interaction.options.getString('server_id').trim();
            const label    = interaction.options.getString('label') || null;

            if (!/^\d{17,20}$/.test(serverId)) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Invalid Server ID')
                            .setDescription('Please provide a valid Discord server ID (17–20 digit number).')
                            .setTimestamp()
                    ]
                });
            }

            // Try to resolve the server name from the bot's cache
            const guild = interaction.client.guilds.cache.get(serverId);
            const displayName = label || guild?.name || `Server \`${serverId}\``;

            const ok = await betaManager.allowServer(serverId);
            if (!ok) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Database Error')
                            .setDescription('Failed to add server to the beta allowed list. Please try again.')
                            .setTimestamp()
                    ]
                });
            }

            return interaction.editReply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('✅ Server Added to Beta')
                        .setDescription(`**${displayName}** (\`${serverId}\`) can now opt in to beta features.`)
                        .addFields({ name: 'Next step', value: 'The server owner must run `$beta enable` in their server to activate beta features.', inline: false })
                        .setFooter({ text: `Added by ${interaction.user.tag}` })
                        .setTimestamp()
                ]
            });
        }

        // ── /betaserver remove ───────────────────────────────────────
        if (sub === 'remove') {
            const serverId = interaction.options.getString('server_id').trim();

            if (!/^\d{17,20}$/.test(serverId)) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Invalid Server ID')
                            .setDescription('Please provide a valid Discord server ID (17–20 digit number).')
                            .setTimestamp()
                    ]
                });
            }

            const guild = interaction.client.guilds.cache.get(serverId);
            const displayName = guild?.name || `Server \`${serverId}\``;

            const ok = await betaManager.denyServer(serverId);
            if (!ok) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Database Error')
                            .setDescription('Failed to remove server from the beta allowed list. Please try again.')
                            .setTimestamp()
                    ]
                });
            }

            return interaction.editReply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🚫 Server Removed from Beta')
                        .setDescription(`**${displayName}** (\`${serverId}\`) has been removed from the beta allowed list.\nBeta features are also disabled for that server.`)
                        .setFooter({ text: `Removed by ${interaction.user.tag}` })
                        .setTimestamp()
                ]
            });
        }

        // ── /betaserver list ─────────────────────────────────────────
        if (sub === 'list') {
            const rows = await betaManager.listAllowedServers();

            // Also include config.betaServers entries (hard-coded seeds)
            const configSeeds = Array.isArray(config.betaServers) ? config.betaServers : [];

            if (rows.length === 0 && configSeeds.length === 0) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle('🔬 Beta Allowed Servers')
                            .setDescription('No servers are currently on the beta allowed list.')
                            .setTimestamp()
                    ]
                });
            }

            const dbIds = new Set(rows.map(r => r.guildId));
            // Merge DB rows with config seeds (deduped)
            const allIds = [...new Set([...rows.map(r => r.guildId), ...configSeeds])];

            const lines = allIds.map(id => {
                const guild   = interaction.client.guilds.cache.get(id);
                const name    = guild ? `**${guild.name}**` : '*Unknown Server*';
                const row     = rows.find(r => r.guildId === id);
                const enabled = row?.enabled ? '🟢 beta on' : '🔴 beta off';
                const source  = configSeeds.includes(id) && !dbIds.has(id) ? ' *(config)*' : '';
                return `• ${name} \`${id}\` — ${enabled}${source}`;
            });

            // Split into chunks of 10 to avoid embed field limits
            const chunks = [];
            for (let i = 0; i < lines.length; i += 10) chunks.push(lines.slice(i, i + 10));

            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle(`🔬 Beta Allowed Servers (${allIds.length})`)
                .setTimestamp();

            chunks.forEach((chunk, i) => {
                embed.addFields({
                    name: chunks.length > 1 ? `Servers (${i + 1}/${chunks.length})` : 'Servers',
                    value: chunk.join('\n'),
                    inline: false
                });
            });

            return interaction.editReply({ embeds: [embed] });
        }
    },
};
