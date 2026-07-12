const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { pool } = require('../server/db');
const ms = require('ms');

class BirthdayManager {
    constructor(client) {
        this.client = client;
        this.birthdays = new Map();
        this.isReady = false;
        this.currentEmbedIndex = 0;

        this.loadBirthdays().then(() => {
            this.isReady = true;
            this.startCheckingBirthdays();
        }).catch(err => {
            console.error('[BIRTHDAYS] Failed to initialize BirthdayManager:', err);
            this.isReady = false;
        });
    }

    async loadBirthdays() {
        try {
            this.birthdays.clear();

            // Load guild configs
            const guildsRes = await pool.query('SELECT guild_id, announcement_channel, role_id FROM birthdays_guilds');
            for (const row of guildsRes.rows) {
                this.birthdays.set(row.guild_id, {
                    channel: row.announcement_channel || null,
                    role: row.role_id || null,
                    users: new Map(),
                });
            }

            // Load individual birthdays
            const bdRes = await pool.query('SELECT guild_id, user_id, month, day, year, last_celebrated FROM birthdays');
            for (const row of bdRes.rows) {
                if (!this.birthdays.has(row.guild_id)) {
                    this.birthdays.set(row.guild_id, { channel: null, role: null, users: new Map() });
                }
                this.birthdays.get(row.guild_id).users.set(row.user_id, {
                    month: row.month,
                    day: row.day,
                    year: row.year || null,
                    lastCelebrated: row.last_celebrated || null,
                });
            }

            console.log(`[BIRTHDAYS] Loaded birthdays for ${this.birthdays.size} guilds from database.`);
        } catch (error) {
            console.error('[BIRTHDAYS] Error loading birthdays:', error);
            throw error;
        }
    }

    startCheckingBirthdays() {
        setInterval(() => this.checkBirthdays(), 60 * 60 * 1000); // every hour
        this.checkBirthdays();
        console.log('[BIRTHDAYS] Birthday checking started.');
    }

    async checkBirthdays() {
        if (!this.isReady) return;

        const now = new Date();
        const currentMonth = now.getMonth() + 1;
        const currentDay = now.getDate();
        const currentYear = now.getFullYear().toString();

        for (const [guildId, guildData] of this.birthdays.entries()) {
            if (!guildData.channel) continue;

            for (const [userId, birthday] of guildData.users.entries()) {
                if (birthday.month === currentMonth && birthday.day === currentDay) {
                    if (birthday.lastCelebrated === currentYear) continue;

                    try {
                        await this.sendBirthdayCelebration(guildId, userId, guildData);
                        birthday.lastCelebrated = currentYear;

                        await pool.query(
                            `UPDATE birthdays SET last_celebrated = $1 WHERE guild_id = $2 AND user_id = $3`,
                            [currentYear, guildId, userId]
                        );
                    } catch (err) {
                        console.error(`[BIRTHDAYS] Error celebrating birthday for ${userId} in ${guildId}:`, err);
                    }
                }
            }
        }
    }

    async sendBirthdayCelebration(guildId, userId, guildData) {
        const guild = this.client.guilds.cache.get(guildId);
        if (!guild) return;

        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) return;

        const channel = guild.channels.cache.get(guildData.channel);
        if (!channel) return;

        const embedStyles = [
            () => new EmbedBuilder()
                .setColor('#FF69B4')
                .setTitle('🎂 Happy Birthday!')
                .setDescription(`Today is **${member.displayName}**'s birthday! 🎉\n\nWishing you a wonderful day filled with joy and happiness! 🎈`)
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
                .setFooter({ text: `🎁 Make it a special day!` })
                .setTimestamp(),
            () => new EmbedBuilder()
                .setColor('#FFD700')
                .setTitle('🎉 Birthday Celebration!')
                .setDescription(`🥳 Everyone wish **${member.displayName}** a Happy Birthday! 🥳\n\n🌟 May all your wishes come true! 🌟`)
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
                .setImage('https://media.giphy.com/media/artj92V8o75VPL7AeQ/giphy.gif')
                .setTimestamp(),
            () => new EmbedBuilder()
                .setColor('#9B59B6')
                .setTitle('🎊 It\'s a Special Day!')
                .setDescription(`🎂 Today we celebrate **${member.displayName}**! 🎂\n\n✨ Wishing you the best birthday ever! ✨`)
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
                .setFooter({ text: '🎈 Have an amazing day!' })
                .setTimestamp(),
            () => new EmbedBuilder()
                .setColor('#2ECC71')
                .setTitle('🌟 Birthday Alert!')
                .setDescription(`📣 Say Happy Birthday to **${member.displayName}**! 🎁\n\n💫 Another year of awesome adventures ahead! 💫`)
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
                .setTimestamp(),
        ];

        const embed = embedStyles[this.currentEmbedIndex % embedStyles.length]();
        this.currentEmbedIndex++;

        await channel.send({ content: `🎂 <@${userId}>`, embeds: [embed] });

        if (guildData.role) {
            try {
                await member.roles.add(guildData.role);
                setTimeout(async () => {
                    try { await member.roles.remove(guildData.role); } catch (_) {}
                }, 24 * 60 * 60 * 1000);
            } catch (_) {}
        }
    }

    async setBirthday(guildId, userId, month, day, year = null) {
        try {
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, { channel: null, role: null, users: new Map() });
            }

            this.birthdays.get(guildId).users.set(userId, { month, day, year, lastCelebrated: null });

            await pool.query(`
                INSERT INTO birthdays (guild_id, user_id, month, day, year, last_celebrated)
                VALUES ($1, $2, $3, $4, $5, NULL)
                ON CONFLICT (guild_id, user_id) DO UPDATE SET
                    month = EXCLUDED.month, day = EXCLUDED.day, year = EXCLUDED.year, last_celebrated = NULL
            `, [guildId, userId, month, day, year]);

            return true;
        } catch (error) {
            console.error('[BIRTHDAYS] Error setting birthday:', error);
            return false;
        }
    }

    async removeBirthday(guildId, userId) {
        try {
            if (this.birthdays.has(guildId)) {
                this.birthdays.get(guildId).users.delete(userId);
            }
            await pool.query(`DELETE FROM birthdays WHERE guild_id = $1 AND user_id = $2`, [guildId, userId]);
            return true;
        } catch (error) {
            console.error('[BIRTHDAYS] Error removing birthday:', error);
            return false;
        }
    }

    async setChannel(guildId, channelId) {
        try {
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, { channel: channelId, role: null, users: new Map() });
            } else {
                this.birthdays.get(guildId).channel = channelId;
            }
            await pool.query(`
                INSERT INTO birthdays_guilds (guild_id, announcement_channel)
                VALUES ($1, $2)
                ON CONFLICT (guild_id) DO UPDATE SET announcement_channel = EXCLUDED.announcement_channel
            `, [guildId, channelId]);
            return true;
        } catch (error) {
            console.error('[BIRTHDAYS] Error setting channel:', error);
            return false;
        }
    }

    async setRole(guildId, roleId) {
        try {
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, { channel: null, role: roleId, users: new Map() });
            } else {
                this.birthdays.get(guildId).role = roleId;
            }
            await pool.query(`
                INSERT INTO birthdays_guilds (guild_id, role_id)
                VALUES ($1, $2)
                ON CONFLICT (guild_id) DO UPDATE SET role_id = EXCLUDED.role_id
            `, [guildId, roleId]);
            return true;
        } catch (error) {
            console.error('[BIRTHDAYS] Error setting role:', error);
            return false;
        }
    }

    getBirthday(guildId, userId) {
        return this.birthdays.get(guildId)?.users.get(userId) || null;
    }

    getGuildBirthdays(guildId) {
        return this.birthdays.get(guildId) || { channel: null, role: null, users: new Map() };
    }

    getUpcomingBirthdays(guildId, days = 7) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) return [];

        const now = new Date();
        const upcoming = [];

        for (const [userId, birthday] of guildData.users.entries()) {
            const nextBirthday = new Date(now.getFullYear(), birthday.month - 1, birthday.day);
            if (nextBirthday < now) nextBirthday.setFullYear(now.getFullYear() + 1);
            const daysUntil = Math.ceil((nextBirthday - now) / (1000 * 60 * 60 * 24));
            if (daysUntil <= days) {
                upcoming.push({ userId, ...birthday, daysUntil, nextBirthday });
            }
        }

        return upcoming.sort((a, b) => a.daysUntil - b.daysUntil);
    }
}

module.exports = BirthdayManager;
