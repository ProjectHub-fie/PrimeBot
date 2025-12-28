const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const fs = require('fs');
const path = require('path');
const config = require('../config');

class TicTacToeManager {
    constructor(client) {
        this.client = client;
        this.games = new Map();
        this.dataPath = path.join(__dirname, '../data/ticTacToe.json');
        
        // Ensure data directory exists
        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        this.loadGames();
    }
    
    /**
     * Load saved games from the data file
     */
    loadGames() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                for (const [channelId, game] of Object.entries(data)) {
                    // Convert object to Map for active games
                    this.games.set(channelId, game);
                }
                console.log(`Loaded ${this.games.size} TicTacToe games from file.`);
            }
        } catch (error) {
            console.error('Error loading TicTacToe games:', error);
            this.games = new Map();
        }
    }
    
    /**
     * Save games to the data file
     */
    saveGames() {
        try {
            const data = {};
            for (const [channelId, game] of this.games.entries()) {
                data[channelId] = game;
            }
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving TicTacToe games:', error);
        }
    }
    
    /**
     * Start a new TicTacToe game in a channel
     * @param {Object} options - Game options
     * @returns {Promise<Object>} The created game object
     */
    async startGame({ channelId, playerId }) {
        // Check if there's already a game in this channel
        if (this.games.has(channelId)) {
            throw new Error('There is already a TicTacToe game in progress in this channel.');
        }
        
        // Create a new game
        const game = {
            channelId,
            startedBy: playerId,
            currentPlayer: playerId,
            board: [
                [null, null, null],
                [null, null, null],
                [null, null, null]
            ],
            status: 'active', // 'active', 'ended'
            winner: null,     // null, playerId, 'draw'
            startTime: Date.now(),
            players: [playerId],
            moves: 0
        };
        
        // Save the game
        this.games.set(channelId, game);
        this.saveGames();
        
        // Get the channel
        const channel = await this.client.channels.fetch(channelId);
        if (channel) {
            // Send a message inviting others to join
            await channel.send(`<@${playerId}> has started a new TicTacToe game! They'll be playing as ❌.\nAnyone can join as the second player (⭕) by using the \`$move\` command.`);
        }
        
        // Send the game board
        const message = await this.sendGameBoard(channelId);
        
        return game;
    }
    
    /**
     * Send or update the game board in a channel
     * @param {string} channelId - The channel ID
     * @returns {Promise<Message>} The sent message
     */
    async sendGameBoard(channelId) {
        const game = this.games.get(channelId);
        if (!game) throw new Error('No game found in this channel.');
        
        const channel = await this.client.channels.fetch(channelId);
        if (!channel) throw new Error('Channel not found.');
        
        const embed = this.createGameEmbed(game);
        const content = this.getGameContent(game);
        
        return await channel.send({ content, embeds: [embed] });
    }
    
    /**
     * Create an embed for the game
     * @param {Object} game - The game object
     * @returns {EmbedBuilder} The game embed
     */
    createGameEmbed(game) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('Multiplayer Tic Tac Toe')
            .setTimestamp();
        
        // Add game status
        if (game.status === 'active') {
            const currentPlayer = `<@${game.currentPlayer}>`;
            
            if (game.players.length === 1) {
                // Only one player so far
                embed.setDescription(`It's ${currentPlayer}'s turn! Waiting for a second player to join.\n\nAnyone can join by using the \`$move\` command.`);
                embed.setFooter({ text: `Use $move <1-9> to make a move or join the game` });
            } else {
                // Two players
                const nextPlayer = game.players.find(p => p !== game.currentPlayer);
                embed.setDescription(`It's ${currentPlayer}'s turn! <@${nextPlayer}> will play next.`);
                embed.setFooter({ text: `Use $move <1-9> to make a move • Use $tend to end the game` });
            }
        } else if (game.status === 'ended') {
            if (game.winner === 'draw') {
                embed.setDescription('Game ended in a draw between the players!');
                embed.setColor(config.colors.warning);
            } else {
                const winner = `<@${game.winner}>`;
                // Find the loser (if there was a second player)
                if (game.players.length > 1) {
                    const loser = game.players.find(p => p !== game.winner);
                    embed.setDescription(`${winner} won the game against <@${loser}>!`);
                } else {
                    embed.setDescription(`${winner} won the game!`);
                }
                embed.setColor(config.colors.success);
            }
            embed.setFooter({ text: `Game ended • Use $tictactoe to start a new game` });
        }
        
        return embed;
    }
    
    /**
     * Get the game board as a string
     * @param {Object} game - The game object
     * @returns {string} The game board as a string
     */
    getGameContent(game) {
        // Map the board to symbols
        const symbols = game.board.map(row => 
            row.map(cell => {
                if (cell === null) return '⬜'; // Empty cell
                if (cell === game.startedBy) return '❌'; // First player
                return '⭕'; // Second player
            })
        );
        
        // Create the board display with position numbers
        let content = '**Multiplayer Tic Tac Toe Game**\n\n';
        
        // Add players section
        content += '**Players:**\n';
        content += `Player 1 (❌): <@${game.startedBy}>\n`;
        
        if (game.players.length > 1) {
            const player2 = game.players.find(p => p !== game.startedBy);
            content += `Player 2 (⭕): <@${player2}>\n\n`;
        } else {
            content += `Player 2 (⭕): Waiting for someone to join...\n\n`;
        }
        
        // Add number reference guide
        content += '**Reference positions:**\n';
        content += '1️⃣2️⃣3️⃣\n';
        content += '4️⃣5️⃣6️⃣\n';
        content += '7️⃣8️⃣9️⃣\n\n';
        
        // Add current board
        content += '**Current board:**\n';
        content += `${symbols[0][0]}${symbols[0][1]}${symbols[0][2]}\n`;
        content += `${symbols[1][0]}${symbols[1][1]}${symbols[1][2]}\n`;
        content += `${symbols[2][0]}${symbols[2][1]}${symbols[2][2]}\n`;
        
        return content;
    }
    
    /**
     * Make a move in the game
     * @param {Object} options - Move options
     * @returns {Promise<boolean>} Whether the move was successful
     */
    async makeMove({ channelId, playerId, position }) {
        const game = this.games.get(channelId);
        if (!game) throw new Error('No game found in this channel.');
        if (game.status !== 'active') throw new Error('This game has already ended.');
        
        // Always allow a second player to join as the opponent
        if (game.players.length === 1 && playerId !== game.startedBy) {
            game.players.push(playerId);
            // Send a message to the channel about the new player
            const channel = await this.client.channels.fetch(channelId);
            if (channel) {
                await channel.send(`<@${playerId}> has joined the game as the second player (⭕)!`);
            }
        }
        
        // Check if it's the player's turn
        if (game.currentPlayer !== playerId && game.players.length === 2) {
            throw new Error("It's not your turn! Please wait for the other player to make their move.");
        }
        
        // Check if the player is part of the game
        if (!game.players.includes(playerId)) {
            // If there's already 2 players, don't allow a third to join
            if (game.players.length === 2) {
                throw new Error("This game already has 2 players. Please wait for this game to end or start a new one in another channel.");
            }
            
            // If there's only 1 player, add this player as the second
            game.players.push(playerId);
            
            // Send a message to the channel about the new player
            const channel = await this.client.channels.fetch(channelId);
            if (channel) {
                await channel.send(`<@${playerId}> has joined the game as the second player (⭕)!`);
            }
        }
        
        // Validate position (1-9)
        if (position < 1 || position > 9) {
            throw new Error('Invalid position. Please choose a number between 1 and 9.');
        }
        
        // Convert position to row and column (0-indexed)
        position--; // Convert to 0-indexed
        const row = Math.floor(position / 3);
        const col = position % 3;
        
        // Check if the cell is already occupied
        if (game.board[row][col] !== null) {
            throw new Error('This position is already taken!');
        }
        
        // Make the move
        game.board[row][col] = playerId;
        game.moves++;
        
        // Check for win or draw
        const result = this.checkGameResult(game);
        if (result === 'win') {
            game.status = 'ended';
            game.winner = playerId;
        } else if (result === 'draw') {
            game.status = 'ended';
            game.winner = 'draw';
        } else {
            // Switch player if there are 2 players
            if (game.players.length === 2) {
                game.currentPlayer = game.players.find(p => p !== playerId);
            }
        }
        
        // Save the game
        this.saveGames();
        
        // Send updated game board
        await this.sendGameBoard(channelId);
        
        return true;
    }
    
    /**
     * Check if the game has a winner or ended in a draw
     * @param {Object} game - The game object
     * @returns {string|null} 'win', 'draw', or null if the game is still active
     */
    checkGameResult(game) {
        const board = game.board;
        
        // Check rows
        for (let i = 0; i < 3; i++) {
            if (board[i][0] !== null && board[i][0] === board[i][1] && board[i][1] === board[i][2]) {
                return 'win';
            }
        }
        
        // Check columns
        for (let i = 0; i < 3; i++) {
            if (board[0][i] !== null && board[0][i] === board[1][i] && board[1][i] === board[2][i]) {
                return 'win';
            }
        }
        
        // Check diagonals
        if (board[0][0] !== null && board[0][0] === board[1][1] && board[1][1] === board[2][2]) {
            return 'win';
        }
        if (board[0][2] !== null && board[0][2] === board[1][1] && board[1][1] === board[2][0]) {
            return 'win';
        }
        
        // Check for draw
        if (game.moves === 9) {
            return 'draw';
        }
        
        // Game is still active
        return null;
    }
    
    /**
     * End a game in progress
     * @param {string} channelId - The channel ID
     * @returns {Promise<boolean>} Whether the game was successfully ended
     */
    async endGame(channelId) {
        if (!this.games.has(channelId)) {
            throw new Error('No game found in this channel.');
        }
        
        // Remove the game
        this.games.delete(channelId);
        this.saveGames();
        
        const channel = await this.client.channels.fetch(channelId);
        if (channel) {
            const embed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('Tic Tac Toe')
                .setDescription('The game has been forcefully ended.')
                .setFooter({ text: `Use $tictactoe to start a new game` })
                .setTimestamp();
            
            await channel.send({ embeds: [embed] });
        }
        
        return true;
    }
    
    /**
     * Get a game by channel ID
     * @param {string} channelId - The channel ID
     * @returns {Object|null} The game object or null if not found
     */
    getGame(channelId) {
        return this.games.get(channelId) || null;
    }
}

module.exports = TicTacToeManager;