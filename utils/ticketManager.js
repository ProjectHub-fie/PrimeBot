const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder, ChannelType, PermissionFlagsBits } = require('discord.js');
const { pool } = require('../server/db');

class TicketManager {
    constructor(client) {
        this.client = client;
        this.tickets = new Map(); // channelId → ticket object

        this._init().catch(err =>
            console.error('[TICKETS] Initialisation failed:', err.message)
        );
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    async _ensureTable() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tickets (
                channel_id        VARCHAR(50) PRIMARY KEY,
                user_id           VARCHAR(50) NOT NULL,
                guild_id          VARCHAR(50) NOT NULL,
                category          VARCHAR(50) NOT NULL DEFAULT 'general',
                created_at        BIGINT NOT NULL,
                closed            BOOLEAN NOT NULL DEFAULT false,
                is_thread         BOOLEAN NOT NULL DEFAULT false,
                parent_channel_id VARCHAR(50),
                control_message_id VARCHAR(50),
                closed_at         BIGINT,
                closed_by         VARCHAR(50),
                reopened_at       BIGINT,
                reopened_by       VARCHAR(50)
            )
        `);
    }

    async _init() {
        await this._ensureTable();
        await this._migrateFromJson();
        await this.loadTickets();
    }

    /** One-time import of existing tickets.json data. */
    async _migrateFromJson() {
        const fs = require('fs');
        const path = require('path');
        const jsonPath = path.join(__dirname, '../data/tickets.json');
        const donePath = jsonPath + '.migrated';
        if (!fs.existsSync(jsonPath) || fs.existsSync(donePath)) return;

        try {
            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            let count = 0;
            for (const [channelId, t] of Object.entries(data)) {
                try {
                    await pool.query(`
                        INSERT INTO tickets (
                            channel_id, user_id, guild_id, category,
                            created_at, closed, is_thread, parent_channel_id,
                            control_message_id, closed_at, closed_by, reopened_at, reopened_by
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                        ON CONFLICT (channel_id) DO NOTHING
                    `, [
                        channelId,
                        t.userId || 'unknown',
                        t.guildId || 'unknown',
                        t.category || 'general',
                        t.createdAt || Date.now(),
                        t.closed || false,
                        t.isThread || false,
                        t.parentChannelId || null,
                        t.controlMessageId || null,
                        t.closedAt || null,
                        t.closedBy || null,
                        t.reopenedAt || null,
                        t.reopenedBy || null,
                    ]);
                    count++;
                } catch (e) {
                    console.error(`[TICKETS] Migration: failed on ticket ${channelId}:`, e.message);
                }
            }
            fs.renameSync(jsonPath, donePath);
            console.log(`[TICKETS] Migrated ${count} tickets from JSON → DB.`);
        } catch (err) {
            console.error('[TICKETS] JSON migration failed:', err.message);
        }
    }

    async loadTickets() {
        try {
            const res = await pool.query('SELECT * FROM tickets');
            for (const row of res.rows) {
                this.tickets.set(row.channel_id, this._rowToTicket(row));
            }
            console.log(`[TICKETS] Loaded ${this.tickets.size} tickets from database.`);
        } catch (error) {
            console.error('[TICKETS] Error loading tickets:', error);
        }
    }

    _rowToTicket(row) {
        return {
            channelId: row.channel_id,
            userId: row.user_id,
            guildId: row.guild_id,
            category: row.category,
            createdAt: Number(row.created_at),
            closed: row.closed,
            isThread: row.is_thread,
            parentChannelId: row.parent_channel_id || null,
            controlMessageId: row.control_message_id || null,
            closedAt: row.closed_at ? Number(row.closed_at) : null,
            closedBy: row.closed_by || null,
            reopenedAt: row.reopened_at ? Number(row.reopened_at) : null,
            reopenedBy: row.reopened_by || null,
        };
    }

    async _saveTicket(ticket) {
        await pool.query(`
            INSERT INTO tickets (
                channel_id, user_id, guild_id, category,
                created_at, closed, is_thread, parent_channel_id,
                control_message_id, closed_at, closed_by, reopened_at, reopened_by
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT (channel_id) DO UPDATE SET
                closed             = EXCLUDED.closed,
                control_message_id = EXCLUDED.control_message_id,
                closed_at          = EXCLUDED.closed_at,
                closed_by          = EXCLUDED.closed_by,
                reopened_at        = EXCLUDED.reopened_at,
                reopened_by        = EXCLUDED.reopened_by
        `, [
            ticket.channelId,
            ticket.userId,
            ticket.guildId,
            ticket.category,
            ticket.createdAt,
            ticket.closed,
            ticket.isThread,
            ticket.parentChannelId || null,
            ticket.controlMessageId || null,
            ticket.closedAt || null,
            ticket.closedBy || null,
            ticket.reopenedAt || null,
            ticket.reopenedBy || null,
        ]);
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    async createTicket(interaction, category = 'general') {
        const guildId = interaction.guild.id;
        const userId = interaction.user.id;

        try {
            const parentChannel = interaction.channel;

            const ticketThread = await parentChannel.threads.create({
                name: `🎫 ${interaction.user.username}'s ticket`,
                autoArchiveDuration: 1440,
                type: ChannelType.PrivateThread,
                reason: `Support ticket created by ${interaction.user.tag}`,
            });

            await ticketThread.members.add(userId);

            const adminMembers = interaction.guild.members.cache.filter(m =>
                m.permissions.has(PermissionFlagsBits.Administrator)
            );
            for (const [, member] of adminMembers) {
                try { await ticketThread.members.add(member.id); } catch (_) {}
            }

            const ticketData = {
                channelId: ticketThread.id,
                userId,
                guildId,
                category,
                createdAt: Date.now(),
                closed: false,
                isThread: true,
                parentChannelId: parentChannel.id,
                controlMessageId: null,
                closedAt: null,
                closedBy: null,
                reopenedAt: null,
                reopenedBy: null,
            };

            const embed = new EmbedBuilder()
                .setColor('#0099ff')
                .setTitle('🎫 Support Ticket')
                .setDescription(`Hello ${interaction.user}, welcome to your support ticket!\n\nPlease describe your issue and our staff will assist you shortly.`)
                .addFields(
                    { name: '📂 Category', value: category, inline: true },
                    { name: '🕐 Created', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true }
                )
                .setThumbnail(interaction.user.displayAvatarURL())
                .setTimestamp();

            const toggleButton = new ButtonBuilder()
                .setCustomId('ticket_toggle')
                .setLabel('Close Ticket')
                .setStyle(ButtonStyle.Danger)
                .setEmoji('🔒');

            const row = new ActionRowBuilder().addComponents(toggleButton);

            const controlMessage = await ticketThread.send({
                content: `${interaction.user} Welcome to your support ticket!\n\n**Note:** You or an administrator can close/open this ticket at any time using the button below.`,
                embeds: [embed],
                components: [row],
            });

            ticketData.controlMessageId = controlMessage.id;
            this.tickets.set(ticketThread.id, ticketData);

            await this._saveTicket(ticketData).catch(err =>
                console.error('[TICKETS] Failed to save new ticket:', err.message)
            );

            return interaction.reply({
                content: `Your ticket thread has been created: ${ticketThread}`,
                ephemeral: true,
            });
        } catch (error) {
            console.error('[TICKETS] Error creating ticket:', error);
            return interaction.reply({
                content: 'There was an error creating your ticket. Please try again later.',
                ephemeral: true,
            });
        }
    }

    async toggleTicket(interaction) {
        const channelId = interaction.channel.id;
        const ticket = this.tickets.get(channelId);

        if (!ticket) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }

        const isOwner = interaction.user.id === ticket.userId;
        const isAdmin = interaction.member.permissions.has(PermissionFlagsBits.Administrator);

        if (!isOwner && !isAdmin) {
            return interaction.reply({ content: 'Only the ticket owner or administrators can toggle this ticket.', ephemeral: true });
        }

        try {
            if (ticket.closed) {
                // Reopen
                ticket.closed = false;
                ticket.reopenedAt = Date.now();
                ticket.reopenedBy = interaction.user.id;
                ticket.closedAt = null;
                ticket.closedBy = null;

                if (ticket.isThread) {
                    await interaction.channel.setArchived(false);
                    await interaction.channel.setLocked(false);
                }

                const toggleButton = new ButtonBuilder()
                    .setCustomId('ticket_toggle').setLabel('Close Ticket').setStyle(ButtonStyle.Danger).setEmoji('🔒');
                const row = new ActionRowBuilder().addComponents(toggleButton);

                const embed = new EmbedBuilder()
                    .setColor('#00ff00').setTitle('🔓 Ticket Reopened')
                    .setDescription('This ticket has been reopened and is now active again.')
                    .addFields(
                        { name: '👤 Reopened by', value: `${interaction.user}`, inline: true },
                        { name: '🕐 Reopened at', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true }
                    ).setTimestamp();

                await interaction.update({ embeds: [embed], components: [row] });
            } else {
                // Close
                ticket.closed = true;
                ticket.closedAt = Date.now();
                ticket.closedBy = interaction.user.id;

                const toggleButton = new ButtonBuilder()
                    .setCustomId('ticket_toggle').setLabel('Open Ticket').setStyle(ButtonStyle.Success).setEmoji('🔓');
                const row = new ActionRowBuilder().addComponents(toggleButton);

                const embed = new EmbedBuilder()
                    .setColor('#ff0000').setTitle('🔒 Ticket Closed')
                    .setDescription('This ticket has been closed and archived.\n\nYou or an administrator can reopen this ticket using the button below.')
                    .addFields(
                        { name: '👤 Closed by', value: `${interaction.user}`, inline: true },
                        { name: '🕐 Closed at', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true }
                    ).setTimestamp();

                await interaction.update({ embeds: [embed], components: [row] });

                setTimeout(async () => {
                    try {
                        if (ticket.isThread) {
                            await interaction.channel.setArchived(true);
                            await interaction.channel.setLocked(true);
                        } else {
                            await interaction.channel.delete();
                        }
                    } catch (err) {
                        console.error('[TICKETS] Error archiving ticket:', err);
                    }
                }, 5000);
            }

            this.tickets.set(channelId, ticket);
            await this._saveTicket(ticket).catch(err =>
                console.error('[TICKETS] Failed to save ticket update:', err.message)
            );
        } catch (error) {
            console.error('[TICKETS] Error toggling ticket:', error);
            return interaction.reply({ content: 'There was an error toggling this ticket.', ephemeral: true });
        }
    }

    async sendTicketEmbed({ channelId, title = 'Support Tickets', description = 'Click the button below to create a support ticket', buttonText = 'Create Ticket', supportRoles = [] }) {
        try {
            const channel = await this.client.channels.fetch(channelId);
            if (!channel) throw new Error('Channel not found');

            const embed = new EmbedBuilder()
                .setColor('#0099ff')
                .setTitle(`🎫 ${title}`)
                .setDescription(description)
                .setTimestamp();

            if (supportRoles.length > 0) {
                embed.addFields({ name: '👥 Support Team', value: supportRoles.map(id => `<@&${id}>`).join(', ') });
            }

            const button = new ButtonBuilder()
                .setCustomId('ticket_create').setLabel(buttonText).setStyle(ButtonStyle.Primary).setEmoji('🎫');
            const row = new ActionRowBuilder().addComponents(button);

            await channel.send({ embeds: [embed], components: [row] });
            return true;
        } catch (error) {
            console.error('[TICKETS] Error sending ticket embed:', error);
            throw error;
        }
    }

    getTicketHistory(guildId, userId = null) {
        return Array.from(this.tickets.values())
            .filter(t => t.guildId === guildId)
            .filter(t => userId ? t.userId === userId : true)
            .sort((a, b) => b.createdAt - a.createdAt);
    }
}

module.exports = TicketManager;
