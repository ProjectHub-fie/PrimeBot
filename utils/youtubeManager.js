/**
 * YouTube Notifications — monitoring manager.
 *
 * Runs on each shard node but only ONE node polls at a time: the polling loop
 * first acquires a database-backed lease (server/youtubeDb.js
 * `acquirePollLease`) and does nothing while another node holds a live lease.
 * A crashed node's lease expires automatically after its TTL, so a standby
 * picks up the work without operator action.
 *
 * Correctness guarantees:
 *   • Only the lease holder checks feeds — nodes never double-poll.
 *   • Every announcement is claimed atomically via the UNIQUE
 *     (guild_id, youtube_channel_id, video_id) index BEFORE the Discord send,
 *     so two nodes (or a retry) can never post the same video twice.
 *   • A subscription's first check stores the current newest video as a
 *     baseline and announces nothing — old videos are never spammed.
 *   • Multiple new videos are processed oldest-first.
 *   • Failures are per-subscription: one broken feed never stops the others.
 *   • Errors use exponential backoff (next_check_at) and self-heal.
 *
 * Configured ONLY from the dashboard; the bot never writes subscriptions.
 */

const { EmbedBuilder } = require('discord.js');
const { youtubePool, acquirePollLease, releasePollLease, claimAnnouncement, markAnnouncementSent, markAnnouncementFailed } = require('../server/youtubeDb');
const youtubeFeed = require('./youtubeFeed');
const { fetchChannelFeed, YouTubeFetchError } = youtubeFeed;
const { normalizeTemplate, DEFAULT_TEMPLATE } = require('../shared/youtubeConstants');
const { buildAnnouncementPayload } = require('../shared/youtubeAnnouncement');
const { touch } = require('./activityGate');

const POLL_INTERVAL_MS = Math.max(30000, parseInt(process.env.YOUTUBE_POLL_INTERVAL_MS, 10) || 3 * 60 * 1000); // default 3 min
const LEASE_TTL_SECONDS = Math.max(30, parseInt(process.env.YOUTUBE_LEASE_TTL_SECONDS, 10) || 90);
const BATCH_SIZE = Math.max(1, parseInt(process.env.YOUTUBE_BATCH_SIZE, 10) || 8);
const CONCURRENCY = Math.max(1, Math.min(8, parseInt(process.env.YOUTUBE_CONCURRENCY, 10) || 3));
const MAX_BACKOFF_MS = 60 * 60 * 1000; // cap retry backoff at 1 hour
const BASE_BACKOFF_MS = 2 * 60 * 1000; // first retry after 2 minutes
const MAX_PER_CHECK = 5;               // announce at most N new videos per subscription per check

function newHolderId() {
    return `${process.env.FAILOVER_NODE || process.env.NODE_ROLE || 'node'}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
}

class YouTubeManager {
    constructor(client) {
        this.client = client;
        this.holderId = newHolderId();
        this._timer = null;
        this._running = false;
        this._stopped = false;
        this._initPromise = null;
        this.status = {
            holderId: this.holderId,
            active: false,          // are we the lease holder?
            lastRunAt: null,
            lastRunCount: 0,
            lastError: null,
            consecutiveErrors: 0,
        };
    }

    /** Await boot so a command path never races initialization. */
    waitForReady() {
        if (!this._initPromise) this._initPromise = this.start();
        return this._initPromise;
    }

    async start() {
        if (this._timer || this._stopped) return;
        // Stagger the first run so all three nodes don't hit the lease at once.
        const jitter = Math.floor(Math.random() * 15000);
        this._timer = setTimeout(() => this._loop(), 5000 + jitter);
        if (this._timer.unref) this._timer.unref();
        console.log(`[YOUTUBE] Monitoring started (holder ${this.holderId}, interval ${POLL_INTERVAL_MS}ms).`);
    }

    stop() {
        this._stopped = true;
        if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    }

    _schedule(ms = POLL_INTERVAL_MS) {
        if (this._stopped) return;
        if (this._timer) clearTimeout(this._timer);
        this._timer = setTimeout(() => this._loop(), ms);
        if (this._timer.unref) this._timer.unref();
    }

    async _loop() {
        if (this._running) { this._schedule(); return; }
        this._running = true;
        try {
            const owned = await acquirePollLease(this.holderId, LEASE_TTL_SECONDS);
            this.status.active = owned;
            if (owned) {
                await this._runDueChecks();
                this.status.consecutiveErrors = 0;
                this.status.lastError = null;
            } else {
                // Not the lease holder — stay quiet and let the owner work.
                this.status.lastRunAt = this.status.lastRunAt || null;
            }
        } catch (err) {
            this.status.consecutiveErrors++;
            this.status.lastError = err.message;
            console.error('[YOUTUBE] Poll loop error:', err.message);
        } finally {
            this._running = false;
            this._schedule();
        }
    }

    /**
     * Check every due, enabled subscription. Bounded concurrency keeps the
     * outbound request rate polite; a per-subscription failure is isolated.
     */
    async _runDueChecks() {
        const subs = await this._dueSubscriptions(BATCH_SIZE);
        if (subs.length === 0) return;
        touch();
        this.status.lastRunAt = new Date();
        this.status.lastRunCount = subs.length;

        for (let i = 0; i < subs.length; i += CONCURRENCY) {
            const slice = subs.slice(i, i + CONCURRENCY);
            await Promise.all(slice.map((sub) => this._checkSubscription(sub).catch((err) => {
                console.error(`[YOUTUBE] check failed for sub ${sub.id}:`, err.message);
            })));
        }
    }

    /** Enabled subscriptions whose next_check_at is due (or null), oldest first. */
    async _dueSubscriptions(limit) {
        const res = await youtubePool.query(`
            SELECT id, guild_id, youtube_channel_id, channel_name, channel_url, channel_handle,
                   avatar_url, discord_channel_id, enabled, paused, template, last_video_id,
                   baseline_done, error_count
            FROM youtube_subscriptions
            WHERE enabled = true
              AND paused = false
              AND discord_channel_id IS NOT NULL
              AND (next_check_at IS NULL OR next_check_at <= NOW())
            ORDER BY COALESCE(next_check_at, 'epoch'::timestamp) ASC, id ASC
            LIMIT $1
        `, [limit]);
        return res.rows;
    }

    /**
     * Check one subscription: fetch its feed, diff against the baseline/last
     * seen video, and announce any new uploads oldest-first. Every DB write
     * (last_video_id, next_check_at, error info) happens even when a send fails
     * so monitoring stays healthy and the same failure isn't retried forever.
     */
    async _checkSubscription(sub) {
        const now = new Date();
        let feed;
        try {
            feed = await youtubeFeed.fetchChannelFeed(sub.youtube_channel_id);
        } catch (err) {
            return this._recordCheckError(sub, err, now);
        }

        // Keep the channel display metadata fresh when the feed provides it.
        await this._refreshMetadata(sub, feed).catch(() => {});

        const entries = (feed.entries || [])
            .filter((e) => e.videoId)
            .sort((a, b) => {
                const ta = a.publishedAt ? a.publishedAt.getTime() : 0;
                const tb = b.publishedAt ? b.publishedAt.getTime() : 0;
                return ta - tb; // oldest first
            });

        // First successful check for this subscription: store the newest video
        // as the baseline and announce nothing (never spam old uploads).
        if (!sub.baseline_done) {
            const newest = entries[entries.length - 1] || null;
            await youtubePool.query(
                `UPDATE youtube_subscriptions
                 SET baseline_done = true, last_video_id = $2, last_checked_at = NOW(),
                     last_success_at = NOW(), last_error = NULL, error_count = 0, next_check_at = NULL,
                     channel_name = COALESCE($3, channel_name), channel_url = COALESCE($4, channel_url)
                 WHERE id = $1`,
                [sub.id, newest ? newest.videoId : null, feed.channelName || null, feed.channelUrl || null]
            );
            return { baseline: true, announced: 0 };
        }

        const lastSeen = sub.last_video_id;
        const lastIdx = lastSeen ? entries.findIndex((e) => e.videoId === lastSeen) : -1;
        // New videos are those published after the last one we saw. When the
        // last-seen video is absent from the feed (scrolled off / deleted) we
        // conservatively announce only the newest entry if it is brand new —
        // this avoids re-announcing the whole feed after a long outage.
        let candidates;
        if (lastIdx >= 0) {
            candidates = entries.slice(lastIdx + 1);
        } else if (!lastSeen) {
            candidates = [];
        } else {
            candidates = entries.length ? [entries[entries.length - 1]] : [];
        }

        // Cap the per-check announcement volume to avoid a flood after downtime.
        if (candidates.length > MAX_PER_CHECK) {
            candidates = candidates.slice(candidates.length - MAX_PER_CHECK);
        }

        let announced = 0;
        let newestId = lastSeen;
        for (const entry of candidates) {
            const ok = await this._announce(sub, entry).catch((err) => {
                console.error(`[YOUTUBE] announce failed for ${sub.youtube_channel_id}/${entry.videoId}:`, err.message);
                return false;
            });
            if (ok) announced++;
            // Track the newest video id regardless of send success, so a
            // permanent failure (deleted channel) does not retry the same video
            // forever — the announcement row records the failure for history.
            if (entry.videoId) newestId = entry.videoId;
        }
        // If nothing was announced (e.g. all duplicates), still advance the
        // watermark to the newest entry so the feed's head is the new baseline.
        if (candidates.length === 0 && entries.length) {
            newestId = entries[entries.length - 1].videoId;
        }

        await youtubePool.query(
            `UPDATE youtube_subscriptions
             SET last_video_id = $2, last_checked_at = NOW(), last_success_at = NOW(),
                 last_error = NULL, error_count = 0, next_check_at = NULL,
                 channel_name = COALESCE($3, channel_name), channel_url = COALESCE($4, channel_url)
             WHERE id = $1`,
            [sub.id, newestId, feed.channelName || null, feed.channelUrl || null]
        );
        return { baseline: false, announced };
    }

    /**
     * Announce a single video to a subscription's Discord channel.
     *
     * The DB claim happens BEFORE the send, so concurrent nodes/retries can
     * never double-post. If the send fails, the row is marked failed and the
     * caller does not retry (the watermark advances) — this prevents an infinite
     * retry loop against a permanently broken destination while keeping the
     * failure visible in the announcement history.
     */
    async _announce(sub, video) {
        const claimId = await claimAnnouncement({
            guildId: sub.guild_id,
            youtubeChannelId: sub.youtube_channel_id,
            subscriptionId: sub.id,
            video,
            discordChannelId: sub.discord_channel_id,
        });
        if (!claimId) return false; // another node already claimed this video

        const payload = buildAnnouncementPayload({
            subscription: {
                channelName: sub.channel_name,
                channelUrl: sub.channel_url,
                channelHandle: sub.channel_handle,
                avatarUrl: sub.avatar_url,
                youtubeChannelId: sub.youtube_channel_id,
                discordChannelId: sub.discord_channel_id,
            },
            video,
            template: normalizeTemplate(sub.template),
        });

        let messageId = null;
        try {
            const guild = this.client.guilds.cache.get(sub.guild_id);
            if (!guild) throw new Error('Guild not cached on this node');
            const channel = await guild.channels.fetch(sub.discord_channel_id).catch(() => null);
            if (!channel) throw new Error('Destination channel missing or not visible to the bot');
            if (!channel.isTextBased || !channel.isTextBased()) throw new Error('Destination channel is not text-based');
            const sent = await channel.send(buildDiscordJsPayload(payload));
            messageId = sent.id;
            await markAnnouncementSent(claimId, messageId);
            return true;
        } catch (err) {
            await markAnnouncementFailed(claimId, err.message);
            throw err;
        }
    }

    /** Update channel name/url from a fresh feed (cheap, best-effort). */
    async _refreshMetadata(sub, feed) {
        if (!feed.channelName && !feed.channelUrl) return;
        await youtubePool.query(
            `UPDATE youtube_subscriptions
             SET channel_name = COALESCE($2, channel_name), channel_url = COALESCE($3, channel_url)
             WHERE id = $1`,
            [sub.id, feed.channelName || null, feed.channelUrl || null]
        );
    }

    /** Record a failed check with exponential backoff. */
    async _recordCheckError(sub, err, now) {
        const retryable = err instanceof YouTubeFetchError ? err.retryable !== false : true;
        const count = (sub.error_count || 0) + 1;
        const backoff = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * Math.pow(2, Math.min(count - 1, 6)));
        const next = new Date(now.getTime() + backoff);
        const message = (err && err.message) || 'Unknown error';
        try {
            await youtubePool.query(
                `UPDATE youtube_subscriptions
                 SET last_checked_at = NOW(), last_error = $2, error_count = $3, next_check_at = $4
                 WHERE id = $1`,
                [sub.id, message.slice(0, 1000), count, next]
            );
        } catch (dbErr) {
            console.error('[YOUTUBE] failed to record check error:', dbErr.message);
        }
        console.warn(`[YOUTUBE] check error for ${sub.youtube_channel_id} (${sub.guild_id}): ${message} — retry in ${Math.round(backoff / 1000)}s`);
        return { baseline: false, announced: 0, error: message, retryable };
    }

    /**
     * Build + deliver a test announcement (dashboard "Test" button). Uses a
     * synthetic video so the admin can preview without waiting for a real
     * upload. Never touches the dedup table (it is a test, not history).
     */
    async sendTestAnnouncement(sub, { channelId } = {}) {
        const targetChannelId = channelId || sub.discord_channel_id;
        if (!targetChannelId) throw new Error('No destination channel configured.');
        const payload = buildAnnouncementPayload({
            subscription: {
                channelName: sub.channel_name || 'Test Creator',
                channelUrl: sub.channel_url,
                channelHandle: sub.channel_handle,
                avatarUrl: sub.avatar_url,
                youtubeChannelId: sub.youtube_channel_id,
                discordChannelId: targetChannelId,
            },
            video: {
                videoId: 'dQw4w9WgXcQ',
                title: 'PrimeBot YouTube notifications are working!',
                url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                publishedAt: new Date(),
                thumbnail: 'https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg',
            },
            template: normalizeTemplate(sub.template),
            test: true,
        });

        const guild = this.client.guilds.cache.get(sub.guild_id);
        if (!guild) throw new Error('Guild not cached on this node.');
        const channel = await guild.channels.fetch(targetChannelId).catch(() => null);
        if (!channel) throw new Error('Destination channel missing or not visible to the bot.');
        const sent = await channel.send(buildDiscordJsPayload(payload));
        return { messageId: sent.id, channelId: targetChannelId };
    }
}

/**
 * Adapt the plain payload (shared/youtubeAnnouncement.js) into a discord.js
 * send payload (EmbedBuilder instance).
 */
function buildDiscordJsPayload(payload) {
    const out = { content: payload.content || undefined, allowedMentions: payload.allowed_mentions };
    out.embeds = (payload.embeds || []).map((e) => {
        const embed = new EmbedBuilder();
        if (e.title) embed.setTitle(e.title);
        if (e.description) embed.setDescription(e.description);
        if (e.color != null) embed.setColor(e.color);
        if (e.url) embed.setURL(e.url);
        if (e.timestamp) embed.setTimestamp(new Date(e.timestamp));
        if (e.footer) embed.setFooter({ text: e.footer.text });
        if (e.author) embed.setAuthor({ name: e.author.name, url: e.author.url, iconURL: e.author.icon_url });
        if (e.image) embed.setImage(e.image.url);
        if (e.thumbnail) embed.setThumbnail(e.thumbnail.url);
        if (Array.isArray(e.fields)) embed.addFields(e.fields.map((f) => ({ name: f.name, value: f.value, inline: !!f.inline })));
        return embed;
    });
    return out;
}

module.exports = { YouTubeManager, buildDiscordJsPayload, POLL_INTERVAL_MS };
