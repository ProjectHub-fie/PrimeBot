const { SlashCommandBuilder, EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const config = require('../config');
const ms = require('ms');

/**
 * Creates a visual progress bar for the broadcast progress
 * @param {number} percentage - The percentage complete (0-100)
 * @returns {string} A text-based progress bar
 */
function createProgressBar(percentage) {
    const barLength = 20;
    const filledLength = Math.round((percentage / 100) * barLength);
    const emptyLength = barLength - filledLength;
    
    const filled = '█'.repeat(filledLength);
    const empty = '░'.repeat(emptyLength);
    
    return `[${filled}${empty}]`;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('broadcast')
        .setDescription('Send an announcement to all servers (Developer only)')
        .setDefaultMemberPermissions('0')
        .addStringOption(option =>
            option.setName('message')
                .setDescription('The message to broadcast to all servers')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('title')
                .setDescription('The title for the announcement (optional)')
                .setRequired(false))
        .addStringOption(option =>
            option.setName('image')
                .setDescription('Optional image URL to include in the announcement')
                .setRequired(false))
        .addStringOption(option =>
            option.setName('color')
                .setDescription('Color of the embed (hex code or color name)')
                .setRequired(false)
                .addChoices(
                    { name: '🔴 Red', value: '#FF0000' },
                    { name: '🟢 Green', value: '#00FF00' },
                    { name: '🔵 Blue', value: '#0000FF' },
                    { name: '🟡 Yellow', value: '#FFFF00' },
                    { name: '🟣 Purple', value: '#800080' },
                    { name: '🟠 Orange', value: '#FFA500' },
                    { name: '⚫ Black', value: '#000000' },
                    { name: '⚪ White', value: '#FFFFFF' }
                ))
        .addBooleanOption(option =>
            option.setName('preview')
                .setDescription('Preview the announcement before sending it')
                .setRequired(false))
        .setDMPermission(false),
    
    async execute(interaction) {
        try {
            // Check if user is a developer
            if (!config.developerIds.includes(interaction.user.id)) {
                return interaction.reply({
                    content: "You do not have permission to use this command.",
                    ephemeral: true
                });
            }
            
            // Get command options
            const broadcastMessage = interaction.options.getString('message');
            const customTitle = interaction.options.getString('title') || "📣 Announcement from Developers";
            const imageUrl = interaction.options.getString('image');
            const embedColor = interaction.options.getString('color') || config.colors.primary;
            const preview = interaction.options.getBoolean('preview') || false;
            
            console.log(`[BROADCAST] Command triggered by ${interaction.user.tag} with message: ${broadcastMessage}`);
            console.log(`[BROADCAST] Developer IDs in config: ${config.developerIds.join(', ')}`);
            console.log(`[BROADCAST] User ID: ${interaction.user.id}, In developer list: ${config.developerIds.includes(interaction.user.id)}`);
            
            // Create the broadcast embed with modern styling
            const broadcastEmbed = new EmbedBuilder()
                .setColor(embedColor)
                .setTitle(customTitle)
                .setDescription(broadcastMessage)
                .setTimestamp()
                .setFooter({
                    text: `Sent by ${interaction.user.tag} • ${interaction.client.user.username} • Version 2.5.0`,
                    iconURL: interaction.client.user.displayAvatarURL()
                });
                
            // Add image if provided
            if (imageUrl) {
                if (imageUrl.match(/\.(jpeg|jpg|gif|png)$/)) {
                    broadcastEmbed.setImage(imageUrl);
                    console.log(`[BROADCAST] Added image: ${imageUrl}`);
                } else {
                    console.log(`[BROADCAST] Invalid image URL format: ${imageUrl}`);
                }
            }
            
            // Get count of servers that will receive broadcasts
            const totalServers = interaction.client.guilds.cache.size;
            const receptiveServers = interaction.client.serverSettingsManager.getBroadcastReceptionCount();
            const optedOutCount = totalServers - receptiveServers;
            
            // Add server count with opt-out information
            broadcastEmbed.addFields(
                { 
                    name: '📊 Servers', 
                    value: `This announcement is being sent to ${receptiveServers} servers that have enabled broadcasts. ${optedOutCount} servers have opted out.`, 
                    inline: false 
                },
                {
                    name: '⚙️ Manage This Server\'s Broadcasts',
                    value: 'Use `$broadcast enable` / `$broadcast disable` to control broadcast. Use `$broadcast channel` to set the channel.',
                    inline: false
                }
            );

            // If preview is enabled, show a preview with confirm/cancel buttons
            if (preview) {
                console.log(`[BROADCAST] Showing preview to ${interaction.user.tag}`);
                
                const confirmButton = new ButtonBuilder()
                    .setCustomId('broadcast_confirm')
                    .setLabel('Send Broadcast')
                    .setStyle(ButtonStyle.Success);
                
                const cancelButton = new ButtonBuilder()
                    .setCustomId('broadcast_cancel')
                    .setLabel('Cancel')
                    .setStyle(ButtonStyle.Danger);
                
                const row = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
                
                const previewEmbed = new EmbedBuilder()
                    .setColor(config.colors.warning)
                    .setTitle('📣 Broadcast Preview')
                    .setDescription('Here is a preview of your broadcast message. Review it and click "Send Broadcast" to send it to servers that have enabled broadcasts, or "Cancel" to cancel.')
                    .addFields(
                        { name: 'Server Stats', value: `Total: ${totalServers} | Receiving: ${receptiveServers} | Opted Out: ${optedOutCount}`, inline: false },
                        { name: '💬 Visibility', value: 'This broadcast will be sent to the first available text channel in each server that has not opted out.', inline: false },
                        { name: '⏰ Timing', value: `Estimated time to complete: ${Math.ceil(receptiveServers * 0.5)} seconds`, inline: false },
                        { name: 'Opt-Out Compliance', value: 'Servers can opt out using `/broadcastsettings disable` or `$broadcast disable` to comply with Discord ToS.', inline: false }
                    )
                    .setFooter({ text: 'Version 2.5.0', iconURL: interaction.client.user.displayAvatarURL() }).setTimestamp();
                
                // Send the preview with buttons
                await interaction.reply({
                    embeds: [previewEmbed, broadcastEmbed],
                    components: [row],
                    ephemeral: true
                });
                
                // Add a note explaining how it works
                await interaction.followUp({
                    content: '**Note:** Click "Send Broadcast" to confirm and send this message only to servers that have not opted out of broadcasts. The buttons will be handled automatically.',
                    ephemeral: true
                });
                
                // The buttons will be handled by interactionCreate.js
                
            } else {
                // No preview requested, proceed directly with broadcast
                console.log(`[BROADCAST] No preview requested, proceeding with broadcast`);
                
                await interaction.reply({
                    content: "📣 Starting broadcast to all servers...",
                    embeds: [broadcastEmbed],
                    ephemeral: true
                });
                
                // Track statistics
                let successCount = 0;
                let failCount = 0;
                let skippedOptOut = 0;
                let totalGuilds = interaction.client.guilds.cache.size;
                
                // Broadcast to guilds that haven't opted out
                console.log(`[BROADCAST] Starting broadcast to ${receptiveServers} guilds that haven't opted out (total: ${totalGuilds})`);
                
                // Process each guild
                let processedCount = 0;
                for (const guild of interaction.client.guilds.cache.values()) {
                    try {
                        console.log(`[BROADCAST] Processing guild: ${guild.name} (${guild.id})`);
                        processedCount++;
                        
                        // Check if the guild has opted out of broadcasts
                        if (!interaction.client.serverSettingsManager.receivesBroadcasts(guild.id)) {
                            console.log(`[BROADCAST] Guild ${guild.name} has opted out of broadcasts, skipping`);
                            skippedOptOut++;
                            continue;
                        }
                        
                        // Use the guild's configured broadcast channel if set, otherwise fall back
                        // to the first available text channel
                        const customChannelId = interaction.client.serverSettingsManager.getBroadcastChannel(guild.id);
                        let channel = customChannelId ? guild.channels.cache.get(customChannelId) : null;

                        if (!channel || channel.type !== 0) {
                            channel = guild.channels.cache
                                .filter(ch => ch.type === 0) // 0 is GuildText channel type
                                .sort((a, b) => a.position - b.position)
                                .first();
                        }
                        
                        if (!channel) {
                            console.log(`[BROADCAST] No suitable text channel found in guild: ${guild.name}`);
                            failCount++;
                            continue;
                        }
                        
                        console.log(`[BROADCAST] Selected channel: ${channel.name} (${channel.id})`);
                        
                        // Check if bot has SendMessages permission
                        const hasPermission = channel.permissionsFor(guild.members.me).has("SendMessages");
                        console.log(`[BROADCAST] Bot has SendMessages permission: ${hasPermission}`);
                        
                        if (hasPermission) {
                            await channel.send({ embeds: [broadcastEmbed] });
                            console.log(`[BROADCAST] Successfully sent broadcast to guild: ${guild.name}`);
                            successCount++;
                        } else {
                            console.log(`[BROADCAST] Missing SendMessages permission in channel: ${channel.name}`);
                            failCount++;
                        }
                        
                        // Update progress every 5 guilds or when done
                        if (processedCount % 5 === 0 || processedCount === totalGuilds) {
                            try {
                                // Calculate progress percentage
                                const progressPercent = Math.round((processedCount / totalGuilds) * 100);
                                const progressBar = createProgressBar(progressPercent);
                                const elapsedTime = Math.round((Date.now() - interaction.createdTimestamp) / 1000);
                                
                                await interaction.editReply({
                                    content: `📣 Broadcasting message to servers...
${progressBar} ${progressPercent}% Complete

Progress: ${processedCount}/${totalGuilds} servers
✅ Success: ${successCount} | ❌ Failed: ${failCount} | 🔕 Opted Out: ${skippedOptOut}
⏱️ Time elapsed: ${elapsedTime}s`,
                                    embeds: [broadcastEmbed]
                                });
                            } catch (e) {
                                console.error('[BROADCAST] Failed to update progress:', e);
                            }
                        }
                        
                    } catch (error) {
                        console.error(`[BROADCAST] Error broadcasting to guild ${guild.name}:`, error);
                        failCount++;
                    }
                }
                
                // Calculate completion metrics
                const completionTime = Math.round((Date.now() - interaction.createdTimestamp) / 1000);
                const eligibleServers = totalGuilds - skippedOptOut;
                const successRate = eligibleServers > 0 ? Math.round((successCount / eligibleServers) * 100) : 0;
                
                // Update with final results - modern design
                const resultEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle("📣 Broadcast Complete")
                    .setDescription(`Your announcement has been broadcast to ${successCount} out of ${eligibleServers} eligible servers.\n${skippedOptOut} servers were skipped due to opt-out preferences.`)
                    .addFields(
                        { name: "✅ Success", value: `${successCount} servers`, inline: true },
                        { name: "❌ Failed", value: `${failCount} servers`, inline: true },
                        { name: "🔕 Opted Out", value: `${skippedOptOut} servers`, inline: true },
                        { name: "📊 Success Rate", value: `${successRate}%`, inline: true },
                        { name: "⏰ Time Taken", value: `${completionTime} seconds`, inline: true },
                        { name: "📝 Opt-Out Note", value: "Servers can configure broadcast preferences with `/broadcastsettings` or `$broadcast enable/disable/channel`", inline: false },
                        { name: "💬 Potential Reach", value: `Message potentially reached all members across ${successCount} servers`, inline: false }
                    )
                    .setTimestamp()
                    .setFooter({ text: `Broadcast ID: ${Date.now().toString(36)} • Version 2.5.0` });
                    
                await interaction.editReply({
                    content: "✅ Broadcast successfully completed!",
                    embeds: [resultEmbed, broadcastEmbed]
                });
            }
            
        } catch (error) {
            console.error('[BROADCAST] Error executing broadcast command:', error);
            if (!interaction.replied) {
                await interaction.reply({
                    content: 'There was an error executing the broadcast command.',
                    ephemeral: true
                });
            } else {
                await interaction.followUp({
                    content: 'There was an error completing the broadcast.',
                    ephemeral: true
                });
            }
        }
    },
};