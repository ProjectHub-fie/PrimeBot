const fs = require('fs');
const path = require('path');
const { EmbedBuilder } = require('discord.js');
const config = require('../config');

class EmojiManager {
    constructor() {
        this.emojis = new Map();
        this.dataPath = path.join(__dirname, '../data/emojis.json');
        
        // Ensure data directory exists
        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        this.loadEmojis();
    }
    
    /**
     * Load saved emojis from the data file
     */
    loadEmojis() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                
                // Reset the Map
                this.emojis.clear();
                
                // Load all emojis
                for (const [name, emoji] of Object.entries(data)) {
                    this.emojis.set(name, emoji);
                }
                
                console.log(`Loaded ${this.emojis.size} custom emojis.`);
            } else {
                // Create the file if it doesn't exist
                this.saveEmojis();
            }
        } catch (error) {
            console.error('Error loading emojis:', error);
            this.emojis = new Map();
        }
    }
    
    /**
     * Save emojis to the data file
     */
    saveEmojis() {
        try {
            const data = {};
            
            // Convert the Map to a plain object for JSON serialization
            for (const [name, emoji] of this.emojis.entries()) {
                data[name] = emoji;
            }
            
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving emojis:', error);
        }
    }
    
    /**
     * Add a new emoji
     * @param {string} name - The name of the emoji
     * @param {string} emoji - The emoji character or code
     * @returns {boolean} Whether the emoji was added successfully
     */
    addEmoji(name, emoji) {
        // Check if the name already exists
        if (this.emojis.has(name)) {
            return false;
        }
        
        // Add the emoji
        this.emojis.set(name, emoji);
        
        // Save the updated emojis
        this.saveEmojis();
        
        return true;
    }
    
    /**
     * Remove an emoji
     * @param {string} name - The name of the emoji to remove
     * @returns {boolean} Whether the emoji was removed successfully
     */
    removeEmoji(name) {
        // Check if the name exists
        if (!this.emojis.has(name)) {
            return false;
        }
        
        // Remove the emoji
        this.emojis.delete(name);
        
        // Save the updated emojis
        this.saveEmojis();
        
        return true;
    }
    
    /**
     * Get all emojis
     * @returns {Map} Map of all emojis
     */
    getAllEmojis() {
        return this.emojis;
    }
    
    /**
     * Get an emoji by name
     * @param {string} name - The name of the emoji
     * @returns {string|null} The emoji or null if not found
     */
    getEmoji(name) {
        return this.emojis.get(name) || null;
    }
    
    /**
     * Create an embed for displaying all emojis with pagination
     * @param {number} page - The page number to display (starting at 1)
     * @returns {Object} Object containing embed, pagination info and components
     */
    createEmojiListEmbed(page = 1) {
        const { ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
        const emojisPerPage = 5; // Show 5 emojis per page
        const emojiEntries = Array.from(this.emojis.entries());
        
        // Calculate pagination info
        const totalEmojis = emojiEntries.length;
        const totalPages = Math.max(1, Math.ceil(totalEmojis / emojisPerPage));
        
        // Ensure page is within valid range
        page = Math.max(1, Math.min(page, totalPages));
        
        // Calculate start and end indices for the current page
        const startIndex = (page - 1) * emojisPerPage;
        const endIndex = Math.min(startIndex + emojisPerPage, totalEmojis);
        
        // Get the emojis for the current page
        const pageEmojis = emojiEntries.slice(startIndex, endIndex);
        
        // Create the embed
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('📋 Custom Emoji List')
            .setDescription(totalEmojis > 0 
                ? `Here are custom emojis (Page ${page}/${totalPages}):`
                : 'No custom emojis have been added yet.');
        
        // Add emojis to the embed
        if (pageEmojis.length > 0) {
            let emojiDisplay = '';
            
            for (const [name, emoji] of pageEmojis) {
                emojiDisplay += `**${name}**: ${emoji}\n`;
            }
            
            embed.addFields({ 
                name: `Showing ${startIndex + 1} to ${endIndex} of ${totalEmojis} emojis`, 
                value: emojiDisplay 
            });
        }
        
        // Create buttons for pagination
        const components = [];
        
        if (totalPages > 1) {
            const prevButton = new ButtonBuilder()
                .setCustomId('emoji_prev_page')
                .setLabel('⬅️ Previous')
                .setStyle(ButtonStyle.Secondary)
                .setDisabled(page === 1);
                
            const nextButton = new ButtonBuilder()
                .setCustomId('emoji_next_page')
                .setLabel('Next ➡️')
                .setStyle(ButtonStyle.Secondary)
                .setDisabled(page === totalPages);
                
            const row = new ActionRowBuilder().addComponents(prevButton, nextButton);
            components.push(row);
        }
        
        return {
            embed,
            currentPage: page,
            totalPages,
            components: components.length > 0 ? components : null
        };
    }
}

module.exports = EmojiManager;