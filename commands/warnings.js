const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('warnings')
        .setDescription('View warnings for a member (or yourself)')
        .addUserOption(option =>
            option.setName('member').setDescription('Member to look up (defaults to you)').setRequired(false)
        ),

    async execute(interaction) {
        const member = interaction.options.getMember('member') || interaction.member;
        if (!member) {
            return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
        }

        try {
            const warnings = await interaction.client.automodManager.getWarnings(interaction.guild.id, member.id);
            if (warnings.length === 0) {
                return interaction.reply({ content: `**${member.user.tag}** has no warnings. ✨`, ephemeral: true });
            }
            const list = warnings.slice(0, 10).map((w, i) => {
                const when = `<t:${Math.floor(new Date(w.createdAt).getTime() / 1000)}:R>`;
                return `**${i + 1}.** ${w.ruleType ? `\`${w.ruleType}\` · ` : ''}${w.reason} — ${when}`;
            }).join('\n');
            const embed = new EmbedBuilder()
                .setColor(0xFEE75C)
                .setTitle(`⚠️ Warnings — ${member.user.tag}`)
                .setDescription(`**${warnings.length}** warning(s) on record.\n\n${list}`)
                .setFooter({ text: 'PrimeBot Automod' })
                .setTimestamp();
            return interaction.reply({ embeds: [embed], ephemeral: true });
        } catch (error) {
            console.error('[WARNINGS] failed:', error);
            return interaction.reply({ content: 'I could not fetch warnings for that member.', ephemeral: true });
        }
    },
};
