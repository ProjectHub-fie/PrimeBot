/**
 * Interaction debugger utility for Discord.js bot
 * 
 * This module helps debug interaction issues by providing detailed 
 * information about interactions and their context.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');

class InteractionDebugger {
    constructor() {
        this.debugMode = false;
        this.debugChannelId = null;
        this.client = null;
    }
    
    /**
     * Initialize the debugger
     * @param {Client} client - Discord.js client instance
     */
    init(client) {
        this.client = client;
        console.log('Interaction debugger initialized');
    }
    
    /**
     * Enable or disable debug mode
     * @param {boolean} enabled - Whether to enable debug mode
     * @param {string} channelId - Channel ID to send debug info to (optional)
     */
    setDebugMode(enabled, channelId = null) {
        this.debugMode = enabled;
        this.debugChannelId = channelId;
        console.log(`Interaction debugger ${enabled ? 'enabled' : 'disabled'}${channelId ? ` with channel ID ${channelId}` : ''}`);
    }
    
    /**
     * Log interaction details
     * @param {Interaction} interaction - Discord.js interaction
     * @param {string} context - Context of the interaction (command, button, etc.)
     */
    async logInteraction(interaction, context = '') {
        if (!this.debugMode) return;
        
        const details = this.getInteractionDetails(interaction);
        
        // Log to console
        console.log(`[INTERACTION DEBUG] ${context}:`, details);
        
        // Log to channel if configured
        if (this.debugChannelId && this.client) {
            try {
                const channel = await this.client.channels.fetch(this.debugChannelId);
                if (channel && channel.isTextBased()) {
                    const debugEmbed = this.createDebugEmbed(interaction, context, details);
                    await channel.send({ embeds: [debugEmbed] });
                }
            } catch (error) {
                console.error('Failed to send debug message to channel:', error);
            }
        }
    }
    
    /**
     * Get detailed information about an interaction
     * @param {Interaction} interaction - Discord.js interaction
     * @returns {Object} Interaction details
     */
    getInteractionDetails(interaction) {
        const base = {
            type: interaction.type,
            id: interaction.id,
            user: `${interaction.user.tag} (${interaction.user.id})`,
            guild: interaction.guild ? `${interaction.guild.name} (${interaction.guild.id})` : 'DM',
            channel: interaction.channel ? `${interaction.channel.name} (${interaction.channel.id})` : 'Unknown',
            commandName: interaction.commandName || 'N/A',
            timestamp: new Date().toISOString()
        };
        
        // Add type-specific details
        if (interaction.isChatInputCommand()) {
            return {
                ...base,
                interactionType: 'ChatInputCommand',
                commandName: interaction.commandName,
                options: interaction.options.data.map(opt => ({
                    name: opt.name,
                    type: opt.type,
                    value: opt.value
                }))
            };
        } else if (interaction.isButton()) {
            return {
                ...base,
                interactionType: 'Button',
                customId: interaction.customId
            };
        } else if (interaction.isSelectMenu()) {
            return {
                ...base,
                interactionType: 'SelectMenu',
                customId: interaction.customId,
                values: interaction.values
            };
        } else if (interaction.isModalSubmit()) {
            return {
                ...base,
                interactionType: 'ModalSubmit',
                customId: interaction.customId,
                fields: Array.from(interaction.fields.fields).map(([id, field]) => ({
                    id,
                    value: field.value
                }))
            };
        } else {
            return {
                ...base,
                interactionType: 'Other'
            };
        }
    }
    
    /**
     * Create a debug embed from interaction details
     * @param {Interaction} interaction - Discord.js interaction
     * @param {string} context - Context of the interaction
     * @param {Object} details - Interaction details
     * @returns {EmbedBuilder} Debug embed
     */
    createDebugEmbed(interaction, context, details) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.warning)
            .setTitle(`🔍 Interaction Debug: ${context}`)
            .setDescription(`Type: ${details.interactionType}`)
            .setFooter({ text: `ID: ${details.id}` })
            .setTimestamp();
            
        // Add basic fields
        embed.addFields(
            { name: 'User', value: details.user, inline: true },
            { name: 'Guild', value: details.guild, inline: true },
            { name: 'Channel', value: details.channel, inline: true }
        );
        
        // Add type-specific fields
        if (details.interactionType === 'ChatInputCommand') {
            embed.addFields({ name: 'Command', value: details.commandName });
            
            if (details.options && details.options.length > 0) {
                const optionsText = details.options.map(opt => 
                    `${opt.name}: ${String(opt.value).slice(0, 100)}`
                ).join('\n');
                
                embed.addFields({ name: 'Options', value: optionsText || 'None' });
            }
        } else if (details.interactionType === 'Button') {
            embed.addFields({ name: 'Custom ID', value: details.customId });
        } else if (details.interactionType === 'SelectMenu') {
            embed.addFields(
                { name: 'Custom ID', value: details.customId },
                { name: 'Values', value: details.values?.join(', ') || 'None' }
            );
        } else if (details.interactionType === 'ModalSubmit') {
            embed.addFields({ name: 'Custom ID', value: details.customId });
            
            if (details.fields && details.fields.length > 0) {
                const fieldsText = details.fields.map(field => 
                    `${field.id}: ${field.value.slice(0, 100)}`
                ).join('\n');
                
                embed.addFields({ name: 'Fields', value: fieldsText || 'None' });
            }
        }
        
        return embed;
    }
    
    /**
     * Debug an error that occurred during interaction handling
     * @param {Interaction} interaction - Discord.js interaction
     * @param {Error} error - The error that occurred
     * @param {string} context - Context of the interaction
     */
    async debugInteractionError(interaction, error, context = '') {
        if (!this.debugMode) return;
        
        // Log to console
        console.error(`[INTERACTION ERROR] ${context}:`, error);
        
        // Log to channel if configured
        if (this.debugChannelId && this.client) {
            try {
                const channel = await this.client.channels.fetch(this.debugChannelId);
                if (channel && channel.isTextBased()) {
                    const errorEmbed = new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle(`⚠️ Interaction Error: ${context}`)
                        .setDescription(`\`\`\`\n${error.message}\n\`\`\``)
                        .addFields(
                            { name: 'User', value: `${interaction.user.tag} (${interaction.user.id})`, inline: true },
                            { name: 'Type', value: this.getInteractionTypeName(interaction), inline: true },
                            { name: 'ID', value: interaction.id, inline: true },
                            { name: 'Stack Trace', value: `\`\`\`\n${error.stack?.slice(0, 1000) || 'No stack trace'}\n\`\`\`` }
                        )
                        .setTimestamp();
                        
                    await channel.send({ embeds: [errorEmbed] });
                }
            } catch (channelError) {
                console.error('Failed to send error debug message to channel:', channelError);
            }
        }
    }
    
    /**
     * Get a human-readable name for the interaction type
     * @param {Interaction} interaction - Discord.js interaction
     * @returns {string} Interaction type name
     */
    getInteractionTypeName(interaction) {
        if (interaction.isChatInputCommand()) return `Command (/${interaction.commandName})`;
        if (interaction.isButton()) return `Button (${interaction.customId})`;
        if (interaction.isSelectMenu()) return `Select Menu (${interaction.customId})`;
        if (interaction.isModalSubmit()) return `Modal (${interaction.customId})`;
        return `Unknown (${interaction.type})`;
    }
}

module.exports = new InteractionDebugger();