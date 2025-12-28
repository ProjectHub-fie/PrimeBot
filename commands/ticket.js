const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('ticket')
        .setDescription('Create a ticket panel for support requests')
		.setDefaultMemberPermissions('0')
        .addChannelOption(option => 
            option.setName('channel')
                .setDescription('The channel to place the ticket panel in (defaults to current channel)')
                .setRequired(false))
        .addStringOption(option => 
            option.setName('title')
                .setDescription('Title for the ticket panel (defaults to "Support Tickets")')
                .setRequired(false))
        .addStringOption(option => 
            option.setName('description')
                .setDescription('Description for the ticket panel')
                .setRequired(false))
        .addStringOption(option => 
            option.setName('button_text')
                .setDescription('Text for the ticket creation button (defaults to "Create Ticket")')
                .setRequired(false))
        .addRoleOption(option => 
            option.setName('support_role')
                .setDescription('Main support role that can access tickets')
                .setRequired(false))
        .addRoleOption(option => 
            option.setName('support_role_2')
                .setDescription('Additional support role')
                .setRequired(false))
        .addRoleOption(option => 
            option.setName('support_role_3')
                .setDescription('Additional support role')
                .setRequired(false))
        ,
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            // Check permissions
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                return interaction.reply({ 
                    content: 'You need the Manage Server permission to set up ticket systems!', 
                    ephemeral: false 
                });
            }
            
            // Get command options
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            const title = interaction.options.getString('title') || 'Support Tickets';
            const description = interaction.options.getString('description') || 'Click the button below to create a support ticket';
            const buttonText = interaction.options.getString('button_text') || 'Create Ticket';
            
            // Get support roles
            const supportRoles = [];
            const role1 = interaction.options.getRole('support_role');
            const role2 = interaction.options.getRole('support_role_2');
            const role3 = interaction.options.getRole('support_role_3');
            
            if (role1) supportRoles.push(role1.id);
            if (role2) supportRoles.push(role2.id);
            if (role3) supportRoles.push(role3.id);
            
            // Create ticket panel
            await interaction.client.ticketManager.sendTicketEmbed({
                channelId: channel.id,
                title,
                description,
                buttonText,
                supportRoles
            });
            
            // Confirm to the user
            await interaction.reply({ 
                content: `Ticket panel created in ${channel}!`, 
                ephemeral: false 
            });
            
        } catch (error) {
            console.error('Error creating ticket panel:', error);
            await interaction.reply({ 
                content: 'There was an error creating the ticket panel! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};