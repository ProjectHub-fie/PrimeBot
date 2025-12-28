const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('birthday')
        .setDescription('Manage birthdays in the server')
		.setDefaultMemberPermissions('0')
        
        .addSubcommand(subcommand =>
            subcommand
                .setName('set')
                .setDescription('Set your birthday or someone else\'s birthday')
                .addIntegerOption(option => 
                    option.setName('month')
                        .setDescription('Month of birth (1-12)')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(12))
                .addIntegerOption(option => 
                    option.setName('day')
                        .setDescription('Day of birth (1-31)')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(31))
                .addIntegerOption(option => 
                    option.setName('year')
                        .setDescription('Year of birth (optional)')
                        .setRequired(false))
                .addUserOption(option =>
                    option.setName('user')
                        .setDescription('The user to set the birthday for (admins only)')
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('remove')
                .setDescription('Remove your birthday or someone else\'s birthday')
                .addUserOption(option =>
                    option.setName('user')
                        .setDescription('The user to remove the birthday for (admins only)')
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('list')
                .setDescription('List upcoming birthdays in the server')
                .addIntegerOption(option =>
                    option.setName('limit')
                        .setDescription('Number of birthdays to show (default: 10)')
                        .setRequired(false)
                        .setMinValue(1)
                        .setMaxValue(25)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('check')
                .setDescription('Check your birthday or someone else\'s birthday')
                .addUserOption(option =>
                    option.setName('user')
                        .setDescription('The user to check the birthday for')
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('channel')
                .setDescription('Set the birthday announcement channel (admin only)')
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('The channel to announce birthdays in')
                        .setRequired(true)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('role')
                .setDescription('Set the birthday role (admin only)')
                .addRoleOption(option =>
                    option.setName('role')
                        .setDescription('The role to assign on birthdays')
                        .setRequired(true))),
    
    async execute(interaction) {
        try {
            const subcommand = interaction.options.getSubcommand();
            const birthdayManager = interaction.client.birthdayManager;
            
            switch (subcommand) {
                case 'set': {
                    const month = interaction.options.getInteger('month');
                    const day = interaction.options.getInteger('day');
                    const year = interaction.options.getInteger('year');
                    const targetUser = interaction.options.getUser('user') || interaction.user;
                    
                    // If setting for someone else, check permissions
                    if (targetUser.id !== interaction.user.id && 
                        !interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        return interaction.reply({ 
                            content: 'You need the Manage Server permission to set birthdays for others!', 
                            ephemeral: false 
                        });
                    }
                    
                    // Set the birthday
                    const success = await birthdayManager.setBirthday({
                        guildId: interaction.guild.id,
                        userId: targetUser.id,
                        month,
                        day,
                        year
                    });
                    
                    if (success) {
                        const formattedDate = birthdayManager.formatDate(month, day);
                        const userText = targetUser.id === interaction.user.id ? 'your' : `${targetUser.username}'s`;
                        
                        const embed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setTitle('🎂 Birthday Set')
                            .setDescription(`Successfully set ${userText} birthday to **${formattedDate}**${year ? ` (${year})` : ''}!`).setFooter({ text: 'Version 2.5.0' });
                        
                        return interaction.reply({ embeds: [embed] });
                    } else {
                        return interaction.reply({ 
                            content: 'Failed to set the birthday. Please make sure the date is valid.', 
                            ephemeral: false 
                        });
                    }
                }
                
                case 'remove': {
                    const targetUser = interaction.options.getUser('user') || interaction.user;
                    
                    // If removing for someone else, check permissions
                    if (targetUser.id !== interaction.user.id && 
                        !interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        return interaction.reply({ 
                            content: 'You need the Manage Server permission to remove birthdays for others!', 
                            ephemeral: false 
                        });
                    }
                    
                    // Remove the birthday
                    const success = birthdayManager.removeBirthday(interaction.guild.id, targetUser.id);
                    
                    if (success) {
                        const userText = targetUser.id === interaction.user.id ? 'Your' : `${targetUser.username}'s`;
                        
                        const embed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(`✅ ${userText} birthday has been removed.`).setFooter({ text: 'Version 2.5.0' });
                        
                        return interaction.reply({ embeds: [embed] });
                    } else {
                        return interaction.reply({ 
                            content: `No birthday was set for ${targetUser.id === interaction.user.id ? 'you' : targetUser.username}.`, 
                            ephemeral: false 
                        });
                    }
                }
                
                case 'list': {
                    const limit = interaction.options.getInteger('limit') || 10;
                    
                    // Get upcoming birthdays
                    const birthdays = birthdayManager.getUpcomingBirthdays(interaction.guild.id, limit);
                    
                    if (birthdays.length === 0) {
                        return interaction.reply('No birthdays have been set in this server yet.');
                    }
                    
                    // Create embed
                    const embed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🎂 Upcoming Birthdays')
                        .setDescription(birthdays.map((b, index) => {
                            const user = interaction.client.users.cache.get(b.userId).setFooter({ text: 'Version 2.5.0' });
                            const username = user ? user.username : 'Unknown User';
                            return `${index + 1}. **${username}** - ${b.formattedDate}${b.daysUntil === 0 ? ' (Today! 🎉)' : ` (in ${b.daysUntil} days)`}`;
                        }).join('\n'));
                    
                    return interaction.reply({ embeds: [embed] });
                }
                
                case 'check': {
                    const targetUser = interaction.options.getUser('user') || interaction.user;
                    const birthday = birthdayManager.getBirthday(interaction.guild.id, targetUser.id);
                    
                    if (!birthday) {
                        const userText = targetUser.id === interaction.user.id ? 'You don\'t' : `${targetUser.username} doesn't`;
                        return interaction.reply(`${userText} have a birthday set.`);
                    }
                    
                    // Create embed
                    const formattedDate = birthdayManager.formatDate(birthday.month, birthday.day);
                    const userText = targetUser.id === interaction.user.id ? 'Your' : `${targetUser.username}'s`;
                    
                    const embed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🎂 Birthday Information')
                        .setDescription(`${userText} birthday is set to **${formattedDate}**${birthday.year ? ` (${birthday.year})` : ''}`).setFooter({ text: 'Version 2.5.0' });
                    
                    return interaction.reply({ embeds: [embed] });
                }
                
                case 'channel': {
                    // Check permissions
                    if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        return interaction.reply({ 
                            content: 'You need the Manage Server permission to set the birthday channel!', 
                            ephemeral: false 
                        });
                    }
                    
                    const channel = interaction.options.getChannel('channel');
                    
                    // Set the channel
                    const success = birthdayManager.setAnnouncementChannel(interaction.guild.id, channel.id);
                    
                    if (success) {
                        const embed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(`✅ Birthday announcements will now be sent to ${channel}.`).setFooter({ text: 'Version 2.5.0' });
                        
                        return interaction.reply({ embeds: [embed] });
                    } else {
                        return interaction.reply({ 
                            content: 'Failed to set the birthday announcement channel.', 
                            ephemeral: false 
                        });
                    }
                }
                
                case 'role': {
                    // Check permissions
                    if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        return interaction.reply({ 
                            content: 'You need the Manage Server permission to set the birthday role!', 
                            ephemeral: false 
                        });
                    }
                    
                    const role = interaction.options.getRole('role');
                    
                    // Set the role
                    const success = birthdayManager.setBirthdayRole(interaction.guild.id, role.id);
                    
                    if (success) {
                        const embed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(`✅ The ${role} role will now be assigned to members on their birthday.`).setFooter({ text: 'Version 2.5.0' });
                        
                        return interaction.reply({ embeds: [embed] });
                    } else {
                        return interaction.reply({ 
                            content: 'Failed to set the birthday role.', 
                            ephemeral: false 
                        });
                    }
                }
            }
            
        } catch (error) {
            console.error('Error executing birthday command:', error);
            return interaction.reply({
                content: 'There was an error executing the command! Please try again later.',
                ephemeral: false
            });
        }
    },
};