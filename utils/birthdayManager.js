const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { birthdayPool: pool } = require('../server/birthdayDb');
const ms = require('ms');

// How often the manager re-reads the tables so dashboard edits (settings,
// custom embed image, added/removed birthdays) take effect without a restart.
const RELOAD_INTERVAL_MS = Math.max(1000, Number(process.env.BIRTHDAY_RELOAD_INTERVAL_MS) || 5000);

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
        this._startReloadInterval();
    }

    // Periodic re-read of the birthday tables. Dashboard saves write the DB
    // directly, so without this the bot would keep serving stale cached values
    // until a restart. A failed reload is logged and retried on the next tick.
    _startReloadInterval() {
        if (this._reloadTimer) return;
        this._reloadTimer = setInterval(() => {
            this.loadBirthdays().catch(err => {
                console.error('[BIRTHDAYS] Periodic reload failed:', err.message);
            });
        }, RELOAD_INTERVAL_MS);
        if (this._reloadTimer.unref) this._reloadTimer.unref();
    }

    // Self-create the birthday tables if they don't exist (mirrors the
    // countingManager pattern) so the feature works even if migration 0001 was
    // never applied to the database. The unique index on (guild_id, user_id) is
    // required by setBirthday's ON CONFLICT clause.
    async _ensureTables() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS birthdays_guilds (
                guild_id varchar(50) PRIMARY KEY,
                announcement_channel varchar(50),
                role_id varchar(50),
                embed_image_url text
            );
            ALTER TABLE birthdays_guilds ADD COLUMN IF NOT EXISTS embed_image_url text;
            CREATE TABLE IF NOT EXISTS birthdays (
                id serial PRIMARY KEY,
                guild_id varchar(50) NOT NULL,
                user_id varchar(50) NOT NULL,
                month integer NOT NULL,
                day integer NOT NULL,
                year integer,
                last_celebrated varchar(50),
                CONSTRAINT fk_birthdays_guild FOREIGN KEY (guild_id) REFERENCES birthdays_guilds(guild_id) ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS birthdays_guild_user_uniq ON birthdays (guild_id, user_id);
        `).catch(err => console.error('[BIRTHDAYS] ensure tables failed:', err.message));
    }

    async loadBirthdays() {
        try {
            await this._ensureTables();
            this.birthdays.clear();

            // Load guild configs
            const guildsRes = await pool.query('SELECT guild_id, announcement_channel, role_id, embed_image_url FROM birthdays_guilds');
            for (const row of guildsRes.rows) {
                this.birthdays.set(row.guild_id, {
                    channel: row.announcement_channel || null,
                    role: row.role_id || null,
                    imageUrl: row.embed_image_url || null,
                    users: new Map(),
                });
            }

            // Load individual birthdays
            const bdRes = await pool.query('SELECT guild_id, user_id, month, day, year, last_celebrated FROM birthdays');
            for (const row of bdRes.rows) {
                if (!this.birthdays.has(row.guild_id)) {
                    this.birthdays.set(row.guild_id, { channel: null, role: null, imageUrl: null, users: new Map() });
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
        const timer = setInterval(() => this.checkBirthdays(), 60 * 60 * 1000); // every hour
        if (timer.unref) timer.unref();
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
                .setImage('https://cdn.discordapp.com/attachments/1358057358009303120/1531595984134738052/images.jpeg?ex=6a69c96a&is=6a6877ea&hm=aa66ac4c4f27dd83e3b97d03bfcbcf0252801fe3b2b9e930cc3d92fdb0ef7e88&')
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
                .setImage('https://cdn.discordapp.com/attachments/1358057358009303120/1531595983840870460/b8121779858b64bb236641f58a9977b1.jpg?ex=6a69c96a&is=6a6877ea&hm=e95f478d03a8d14072fa8aecd1210676bf2b1f12bb6603a5810d1bb0e6fc32bd&')
                .setFooter({ text: '🎈 Have an amazing day!' })
                .setTimestamp(),
            () => new EmbedBuilder()
                .setColor('#2ECC71')
                .setTitle('🌟 Birthday Alert!')
                .setDescription(`📣 Say Happy Birthday to **${member.displayName}**! 🎁\n\n💫 Another year of awesome adventures ahead! 💫`)
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
                .setImage('https://cdn.discordapp.com/attachments/1358057358009303120/1531595983421706350/images_1.jpeg?ex=6a69c96a&is=6a6877ea&hm=043f9154583b7518858052bd76b3972819c262ee215d33976e1920f3b83d1175&')
                .setTimestamp(),
        ];

        const embed = embedStyles[this.currentEmbedIndex % embedStyles.length]();
        this.currentEmbedIndex++;

        // A dashboard-configured custom image overrides the built-in per-style
        // image on every birthday embed for this server.
        if (guildData.imageUrl) embed.setImage(guildData.imageUrl);

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
        // Accepts either positional args or a single options object
        // ({ guildId, userId, month, day, year }) — the slash command passes the latter.
        if (guildId && typeof guildId === 'object') {
            ({ guildId, userId, month, day, year = null } = guildId);
        }
        try {
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, { channel: null, role: null, imageUrl: null, users: new Map() });
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
                this.birthdays.set(guildId, { channel: channelId, role: null, imageUrl: null, users: new Map() });
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
                this.birthdays.set(guildId, { channel: null, role: roleId, imageUrl: null, users: new Map() });
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

    // Set (or clear, with null/empty) the custom image shown on every birthday
    // embed for this server. Configured from the dashboard Birthdays tab.
    async setEmbedImage(guildId, imageUrl) {
        try {
            const url = imageUrl || null;
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, { channel: null, role: null, imageUrl: url, users: new Map() });
            } else {
                this.birthdays.get(guildId).imageUrl = url;
            }
            await pool.query(`
                INSERT INTO birthdays_guilds (guild_id, embed_image_url)
                VALUES ($1, $2)
                ON CONFLICT (guild_id) DO UPDATE SET embed_image_url = EXCLUDED.embed_image_url
            `, [guildId, url]);
            return true;
        } catch (error) {
            console.error('[BIRTHDAYS] Error setting embed image:', error);
            return false;
        }
    }

    // Aliases used by the slash/prefix command paths.
    setAnnouncementChannel(guildId, channelId) { return this.setChannel(guildId, channelId); }
    setBirthdayRole(guildId, roleId) { return this.setRole(guildId, roleId); }

    getBirthday(guildId, userId) {
        return this.birthdays.get(guildId)?.users.get(userId) || null;
    }

    async getGuildBirthdays(guildId) {
        try {
            // Always read from DB so that rows inserted manually (outside the bot)
            // are visible immediately without requiring a restart.
            const [configRes, bdRes] = await Promise.all([
                pool.query(
                    'SELECT announcement_channel, role_id, embed_image_url FROM birthdays_guilds WHERE guild_id = $1',
                    [guildId]
                ),
                pool.query(
                    'SELECT user_id, month, day, year, last_celebrated FROM birthdays WHERE guild_id = $1',
                    [guildId]
                ),
            ]);

            const configRow = configRes.rows[0] || null;
            const users = new Map();
            for (const row of bdRes.rows) {
                users.set(row.user_id, {
                    month: row.month,
                    day: row.day,
                    year: row.year || null,
                    lastCelebrated: row.last_celebrated || null,
                });
            }

            // Sync the fresh data back into the in-memory map so the rest of the
            // manager (checkBirthdays, etc.) also benefits from it.
            const guildData = {
                channel:  configRow?.announcement_channel || null,
                role:     configRow?.role_id || null,
                imageUrl: configRow?.embed_image_url || null,
                users,
            };
            this.birthdays.set(guildId, guildData);

            return guildData;
        } catch (error) {
            console.error('[BIRTHDAYS] Error fetching guild birthdays from DB:', error);
            // Fall back to the cached map so the list command still works on DB error.
            return this.birthdays.get(guildId) || { channel: null, role: null, imageUrl: null, users: new Map() };
        }
    }

    async getUpcomingBirthdays(guildId, days = 7) {
        // Refresh from DB first so manually inserted rows are included immediately.
        const guildData = await this.getGuildBirthdays(guildId);
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

    // Returns ALL birthdays in the guild sorted by next occurrence — no day-window filter.
    async getAllBirthdays(guildId) {
        const guildData = await this.getGuildBirthdays(guildId);
        if (!guildData) return [];

        const now = new Date();
        const all = [];

        for (const [userId, birthday] of guildData.users.entries()) {
            const nextBirthday = new Date(now.getFullYear(), birthday.month - 1, birthday.day);
            if (nextBirthday < now) nextBirthday.setFullYear(now.getFullYear() + 1);
            const daysUntil = Math.ceil((nextBirthday - now) / (1000 * 60 * 60 * 24));
            all.push({ userId, ...birthday, daysUntil, nextBirthday });
        }

        return all.sort((a, b) => a.daysUntil - b.daysUntil);
    }
}

module.exports = BirthdayManager;
