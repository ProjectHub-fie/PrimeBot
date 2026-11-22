/**
 * Invite Tracking manager.
 *
 * Discord does not tell a bot which invite a member used. The only reliable
 * signal is the per-invite `uses` counter: it is captured for every invite code
 * (the "baseline"), and when a member joins the counters are re-read. Exactly
 * one code increasing ⇒ that invite was used. Anything else is recorded
 * honestly:
 *
 *   one code +N  → attributed (inviter = code owner)
 *   several codes → `ambiguous` (inviter Unknown — never guessed)
 *   no code delta → `vanity` when the guild has a vanity URL (vanity uses are
 *                   not exposed by Discord, so this is marked `probable`),
 *                   otherwise `unknown`
 *   fetch failed  → `unknown` and the baseline is NOT overwritten
 *
 * The baseline is persisted in `invite_snapshots`, so a restart keeps the
 * history and never re-attributes an old join.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const repo = require('../server/inviteRepo');
const { AdaptivePoller } = require('./adaptivePoller');
const { getCacheScheduler } = require('./cacheScheduler');

const DELTA_RETRIES = Math.max(1, parseInt(process.env.INVITE_DELTA_RETRIES, 10) || 4);
const DELTA_RETRY_MS = Math.max(200, parseInt(process.env.INVITE_DELTA_RETRY_MS, 10) || 1200);
const DEDUPE_MS = 10000;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function inviteToSnapshot(invite) {
    return {
        code: invite.code,
        inviterId: invite.inviter?.id || invite.inviterId || null,
        uses: Number(invite.uses) || 0,
        maxUses: invite.maxUses ?? null,
        maxAge: invite.maxAge ?? null,
        temporary: invite.temporary === true,
        channelId: invite.channel?.id || invite.channelId || null,
    };
}

class InviteTracker {
    constructor(client = null) {
        this.client = client;
        this._settings = new Map();     // guildId -> settings
        this._baselines = new Map();    // guildId -> Map<code, snapshot>
        this._locks = new Map();        // guildId -> promise chain
        this._recent = new Map();       // `${guildId}:${userId}` -> timestamp
        this._tableReady = false;
        this._initPromise = this._init();
    }

    async _init() {
        try {
            await repo.ensureInviteTables();
            this._tableReady = true;
            await this._loadSettings();
            await this._loadBaselines();
            this._startPoller();
            console.log('✅ InviteTracker database connection established');
        } catch (err) {
            this._tableReady = false;
            console.error('❌ InviteTracker initialization failed:', err.message);
            console.log('⚠️ Invite Tracking will use fallback mode (tracking disabled)');
        }
    }

    ready() { return this._initPromise; }

    _startPoller() {
        if (this._poller) return;
        this._poller = new AdaptivePoller({
            name: 'INVITE SETTINGS',
            task: () => this._loadSettings(),
            initialMs: 120000,
            maxMs: 30 * 60 * 1000,
        });
        this._poller.start();
    }

    stop() {
        if (this._poller) { this._poller.stop(); this._poller = null; }
    }

    async _loadSettings() {
        if (!this._tableReady) return false;
        try {
            const rows = await repo.getAllInviteSettings();
            const built = new Map();
            for (const row of rows) built.set(String(row.guildId), row);
            let changed = built.size !== this._settings.size;
            if (!changed) {
                for (const [id, s] of built) {
                    if (JSON.stringify(this._settings.get(id)) !== JSON.stringify(s)) { changed = true; break; }
                }
            }
            this._settings = built;
            return changed;
        } catch (err) {
            console.warn('[INVITE] settings reload failed:', err.message);
            return false;
        }
    }

    async _loadBaselines() {
        if (!this._tableReady) return;
        const guildIds = await repo.getSnapshotGuildIds();
        for (const guildId of guildIds) {
            const snaps = await repo.getSnapshots(guildId);
            this._baselines.set(String(guildId), new Map(snaps.map(s => [s.code, s])));
        }
    }

    getSettings(guildId) {
        return this._settings.get(String(guildId)) || { ...repo.DEFAULT_SETTINGS };
    }

    isEnabled(guildId) {
        return this.getSettings(guildId).enabled !== false;
    }

    async updateSettings(guildId, patch) {
        const next = await repo.upsertInviteSettings(guildId, patch);
        this._settings.set(String(guildId), next);
        return next;
    }

    _baselineFor(guildId) {
        const key = String(guildId);
        if (!this._baselines.has(key)) this._baselines.set(key, new Map());
        return this._baselines.get(key);
    }

    _withGuildLock(guildId, fn) {
        const key = String(guildId);
        const prev = this._locks.get(key) || Promise.resolve();
        const next = prev.then(fn, fn);
        // Keep the chain alive but never let a rejection poison later calls.
        this._locks.set(key, next.catch(() => {}));
        return next;
    }

    /** Fetch live invites. Returns null on failure — never an empty list. */
    async _fetchLive(guild) {
        try {
            const invites = await guild.invites.fetch();
            const map = new Map();
            for (const invite of invites.values()) {
                const snap = inviteToSnapshot(invite);
                map.set(snap.code, snap);
            }
            return map;
        } catch (err) {
            console.warn(`[INVITE] could not fetch invites for ${guild.id}: ${err.message}`);
            return null;
        }
    }

    _deltas(live) {
        const baseline = this._baselineFor(live.guildId);
        const increased = [];
        for (const [code, snap] of live.invites) {
            const prev = baseline.get(code);
            const prevUses = prev ? prev.uses : 0;
            const diff = snap.uses - prevUses;
            if (diff > 0) increased.push({ ...snap, diff });
        }
        return increased;
    }

    /**
     * Attribute a join from a live invite fetch. Retries briefly because
     * Discord's invite counters are eventually consistent.
     */
    async _attribute(guild, settings) {
        let live = await this._fetchLive(guild);
        if (!live) return { attribution: 'unknown', source: 'unknown', inviterId: null, code: null, live: null };

        let increased = this._deltas({ guildId: guild.id, invites: live });
        let attempt = 1;
        while (!increased.length && attempt < DELTA_RETRIES) {
            await sleep(DELTA_RETRY_MS);
            const again = await this._fetchLive(guild);
            if (!again) break;
            live = again;
            increased = this._deltas({ guildId: guild.id, invites: live });
            attempt += 1;
        }

        if (increased.length === 1) {
            const inv = increased[0];
            return {
                attribution: 'exact',
                source: 'invite',
                inviterId: inv.inviterId || null,
                code: inv.code,
                live,
            };
        }
        if (increased.length > 1) {
            return { attribution: 'ambiguous', source: 'invite', inviterId: null, code: null, live };
        }
        if (settings.vanityTracking !== false && guild.vanityURLCode) {
            return { attribution: 'probable', source: 'vanity', inviterId: null, code: guild.vanityURLCode, live };
        }
        return { attribution: 'unknown', source: 'unknown', inviterId: null, code: null, live };
    }

    async _persistBaseline(guildId, live) {
        if (!live) return;
        const key = String(guildId);
        try {
            await repo.replaceGuildSnapshots(guildId, Array.from(live.values()));
            this._baselines.set(key, new Map(Array.from(live.entries())));
        } catch (err) {
            console.warn('[INVITE] baseline persist failed:', err.message);
            this._baselines.set(key, new Map(Array.from(live.entries())));
        }
    }

    // ── Join ────────────────────────────────────────────────────────────────
    async handleMemberAdd(member) {
        if (!member || !member.guild) return null;
        const guild = member.guild;
        const settings = this.getSettings(guild.id);
        if (settings.enabled === false) return null;

        const key = `${guild.id}:${member.id}`;
        const last = this._recent.get(key);
        if (last && Date.now() - last < DEDUPE_MS) return null;
        this._recent.set(key, Date.now());

        return this._withGuildLock(guild.id, async () => {
            try {
                const isBot = member.user ? member.user.bot === true : false;
                const excluded = settings.excludedUserIds.includes(String(member.id));
                const username = member.user ? member.user.username : null;

                if (isBot && settings.excludeBots !== false) {
                    // Still refresh the baseline so a bot join cannot be
                    // mis-attributed to the next human join.
                    const live = await this._fetchLive(guild);
                    if (live) await this._persistBaseline(guild.id, live);
                    await repo.addJoin({
                        guildId: guild.id, userId: member.id, username,
                        inviterId: null, inviteCode: null, source: 'bot',
                        attribution: 'unknown', isBot: true,
                    }).catch(() => {});
                    return null;
                }

                if (excluded) {
                    const live = await this._fetchLive(guild);
                    if (live) await this._persistBaseline(guild.id, live);
                    return null;
                }

                const result = await this._attribute(guild, settings);
                if (result.live) await this._persistBaseline(guild.id, result.live);

                const join = await repo.addJoin({
                    guildId: guild.id,
                    userId: member.id,
                    username,
                    inviterId: result.inviterId,
                    inviteCode: result.code,
                    source: result.source,
                    attribution: result.attribution,
                    isBot,
                });

                if (result.inviterId && !settings.excludedUserIds.includes(String(result.inviterId))) {
                    await repo.addInviteStat(guild.id, result.inviterId, { joins: 1 }).catch(() => {});
                }
                await repo.addInviteActivity(guild.id, {
                    type: 'join',
                    userId: member.id,
                    username,
                    inviterId: result.inviterId,
                    detail: result.attribution === 'exact'
                        ? `via ${result.code}`
                        : `${result.source} (${result.attribution})`,
                }).catch(() => {});

                if (settings.logChannelId && settings.joinNotifications) {
                    this._notify(guild, settings.logChannelId, this._joinEmbed(member, result)).catch(() => {});
                }
                return join;
            } catch (err) {
                console.error('[INVITE] join tracking failed:', err.message);
                return null;
            }
        });
    }

    // ── Leave ───────────────────────────────────────────────────────────────
    async handleMemberRemove(member) {
        if (!member || !member.guild) return null;
        const guild = member.guild;
        const settings = this.getSettings(guild.id);
        if (settings.enabled === false) return null;

        return this._withGuildLock(guild.id, async () => {
            try {
                const open = await repo.findOpenJoin(guild.id, member.id);
                if (!open) return null;
                const closed = await repo.markJoinLeft(open.id);
                const username = member.user ? member.user.username : open.username;
                const counted = open.inviterId && !settings.excludedUserIds.includes(String(open.inviterId));
                if (counted) {
                    await repo.addInviteStat(guild.id, open.inviterId, { leaves: 1 }).catch(() => {});
                }
                await repo.addInviteActivity(guild.id, {
                    type: 'leave',
                    userId: member.id,
                    username,
                    inviterId: open.inviterId,
                    detail: open.inviterId ? 'invited member left' : 'unknown inviter left',
                }).catch(() => {});
                if (settings.logChannelId && settings.leaveNotifications) {
                    this._notify(guild, settings.logChannelId, this._leaveEmbed(member, open)).catch(() => {});
                }
                return closed;
            } catch (err) {
                console.error('[INVITE] leave tracking failed:', err.message);
                return null;
            }
        });
    }

    // ── Invite lifecycle ────────────────────────────────────────────────────
    async handleInviteCreate(invite) {
        if (!invite || !invite.guild) return;
        const snap = inviteToSnapshot(invite);
        const baseline = this._baselineFor(invite.guild.id);
        baseline.set(snap.code, snap);
        await repo.upsertSnapshot(invite.guild.id, snap).catch(() => {});
        await repo.addInviteActivity(invite.guild.id, {
            type: 'invite_create', inviterId: snap.inviterId, detail: `Invite ${snap.code} created`,
        }).catch(() => {});
    }

    async handleInviteDelete(invite) {
        if (!invite || !invite.guild) return;
        const baseline = this._baselineFor(invite.guild.id);
        baseline.delete(invite.code);
        await repo.markSnapshotDeleted(invite.guild.id, invite.code).catch(() => {});
        await repo.addInviteActivity(invite.guild.id, {
            type: 'invite_delete', detail: `Invite ${invite.code} deleted`,
        }).catch(() => {});
    }

    // ── Notifications ───────────────────────────────────────────────────────
    async _notify(guild, channelId, embed) {
        const channel = guild.channels.cache.get(channelId)
            || await guild.channels.fetch(channelId).catch(() => null);
        if (!channel || typeof channel.send !== 'function') return;
        await channel.send({ embeds: [embed], allowedMentions: { parse: [] } }).catch(err => {
            console.warn('[INVITE] notification failed:', err.message);
        });
    }

    _joinEmbed(member, result) {
        const lines = [
            `**Member:** ${member.user ? member.user.tag : member.id} (<@${member.id}>)`,
            `**Inviter:** ${result.inviterId ? `<@${result.inviterId}>` : 'Unknown'}`,
        ];
        if (result.code) lines.push(`**Invite:** \`${result.code}\`${result.source === 'vanity' ? ' (vanity URL)' : ''}`);
        if (result.attribution !== 'exact') {
            lines.push(`**Attribution:** ${result.attribution}${result.attribution === 'probable' ? ' (vanity usage is not exposed by Discord)' : ''}`);
        }
        lines.push(`**Members:** ${member.guild.memberCount}`);
        return new EmbedBuilder()
            .setColor(config.colors.success)
            .setAuthor({ name: 'Member Joined' })
            .setDescription(lines.join('\n'))
            .setFooter({ text: `Invite Tracking • ${config.version}` })
            .setTimestamp();
    }

    _leaveEmbed(member, join) {
        return new EmbedBuilder()
            .setColor(config.colors.error || 0xed4245)
            .setAuthor({ name: 'Member Left' })
            .setDescription([
                `**Member:** ${member.user ? member.user.tag : member.id} (<@${member.id}>)`,
                `**Invited by:** ${join.inviterId ? `<@${join.inviterId}>` : 'Unknown'}`,
                join.joinedAt ? `**Joined:** <t:${Math.floor(new Date(join.joinedAt).getTime() / 1000)}:R>` : null,
            ].filter(Boolean).join('\n'))
            .setFooter({ text: `Invite Tracking • ${config.version}` })
            .setTimestamp();
    }

    // ── Queries used by commands / dashboard ────────────────────────────────
    async getStats(guildId, userId) {
        const stat = await repo.getInviteStat(guildId, userId);
        const active = await repo.getActiveInviteCounts(guildId);
        const mine = active.find(a => String(a.inviterId) === String(userId));
        return { ...stat, activeInvites: mine ? mine.active : 0, activeCodes: mine ? mine.codes : 0 };
    }

    async getLeaderboard(guildId, opts) { return repo.getLeaderboard(guildId, opts); }
    async getTotals(guildId) { return repo.getGuildInviteTotals(guildId); }
}

module.exports = { InviteTracker };
