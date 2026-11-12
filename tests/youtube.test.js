// YouTube Notifications (Creator Hub) tests.
//
// Covers the pure helpers (channel-reference parsing, template normalization,
// announcement payload, Atom parsing), the resolver/SSRF guard, the monitoring
// manager (baseline, new-upload detection, dedup, backoff, per-subscription
// isolation) against an in-memory pool stub, and the dashboard API over real
// HTTP (auth guards + guild-channel validation).
//
// The pool stub is justified: CI has no Postgres. It understands the exact SQL
// the feature issues, so the module's real SQL handling + logic is exercised.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('node:module');

const yc = require('../shared/youtubeConstants');
const { buildAnnouncementPayload } = require('../shared/youtubeAnnouncement');
const { parseAtomFeed, parseChannelHtml, YouTubeFetchError, httpGet } = require('../utils/youtubeFeed');
const { withDeadline } = require('../utils/withDeadline');

// ─────────────────────────────────────────────────────────────────────────────
// 1. Channel reference parsing
// ─────────────────────────────────────────────────────────────────────────────

test('parseChannelReference: bare channel id', () => {
    const ref = yc.parseChannelReference('UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(ref.kind, 'channelId');
    assert.equal(ref.channelId, 'UCX6OQ3DkcsbYNE6H8uQQuVA');
});

test('parseChannelReference: bare @handle', () => {
    const ref = yc.parseChannelReference('@MrBeast');
    assert.deepEqual(ref, { kind: 'handle', handle: 'MrBeast' });
});

test('parseChannelReference: /channel/<id> URL', () => {
    const ref = yc.parseChannelReference('https://www.youtube.com/channel/UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(ref.kind, 'channelId');
});

test('parseChannelReference: /@handle URL', () => {
    const ref = yc.parseChannelReference('https://www.youtube.com/@MrBeast/videos');
    assert.deepEqual(ref, { kind: 'handle', handle: 'MrBeast' });
});

test('parseChannelReference: legacy /user and /c URLs', () => {
    assert.deepEqual(yc.parseChannelReference('https://youtube.com/user/SomeName'), { kind: 'user', username: 'SomeName' });
    assert.deepEqual(yc.parseChannelReference('https://youtube.com/c/SomeName'), { kind: 'custom', path: 'SomeName' });
});

test('parseChannelReference: a video URL is NOT a channel reference', () => {
    assert.equal(yc.parseChannelReference('https://youtu.be/dQw4w9WgXcQ').kind, 'invalid');
    assert.equal(yc.parseChannelReference('https://www.youtube.com/watch?v=dQw4w9WgXcQ').kind, 'url'); // classified as generic url (resolver rejects)
});

test('parseChannelReference: rejects untrusted hosts (SSRF guard)', () => {
    const ref = yc.parseChannelReference('https://evil.example.com/channel/UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(ref.kind, 'invalid');
    assert.equal(ref.reason, 'untrusted_host');
});

test('parseChannelReference: empty / junk input is invalid, never throws', () => {
    assert.equal(yc.parseChannelReference('').kind, 'invalid');
    assert.equal(yc.parseChannelReference(null).kind, 'invalid');
    assert.equal(yc.parseChannelReference('   ').kind, 'invalid');
});

test('httpGet refuses a non-https or untrusted host before any request', async () => {
    await assert.rejects(() => httpGet('http://www.youtube.com/feeds/videos.xml?channel_id=UCX6OQ3DkcsbYNE6H8uQQuVA'),
        (e) => e instanceof YouTubeFetchError && e.code === 'bad_protocol');
    await assert.rejects(() => httpGet('https://evil.example.com/'),
        (e) => e instanceof YouTubeFetchError && e.code === 'untrusted_host');
});

test('isValidChannelId / isValidVideoId', () => {
    assert.ok(yc.isValidChannelId('UCX6OQ3DkcsbYNE6H8uQQuVA'));
    assert.ok(!yc.isValidChannelId('UC123'));       // too short
    assert.ok(!yc.isValidChannelId('XX' + 'a'.repeat(22))); // wrong prefix
    assert.ok(yc.isValidVideoId('dQw4w9WgXcQ'));
    assert.ok(!yc.isValidVideoId('too-long-video-id'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Atom parsing
// ─────────────────────────────────────────────────────────────────────────────

const SAMPLE_FEED = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns:yt="http://www.youtube.com/xml/schemas/2015" xmlns:media="http://search.yahoo.com/mrss/" xmlns="http://www.w3.org/2005/Atom">
  <link rel="alternate" href="https://www.youtube.com/channel/UCX6OQ3DkcsbYNE6H8uQQuVA"/>
  <id>yt:channel:UCX6OQ3DkcsbYNE6H8uQQuVA</id>
  <yt:channelId>UCX6OQ3DkcsbYNE6H8uQQuVA</yt:channelId>
  <title>Test Channel</title>
  <author><name>Test Channel</name></author>
  <entry>
    <id>yt:video:AAA11111111</id>
    <yt:videoId>AAA11111111</yt:videoId>
    <title>Newest video &amp; title</title>
    <link rel="alternate" href="https://www.youtube.com/watch?v=AAA11111111"/>
    <published>2026-01-02T03:04:05+00:00</published>
    <media:thumbnail url="https://i.ytimg.com/vi/AAA11111111/hqdefault.jpg"/>
  </entry>
  <entry>
    <id>yt:video:BBB22222222</id>
    <yt:videoId>BBB22222222</yt:videoId>
    <title>Older video</title>
    <link rel="alternate" href="https://www.youtube.com/watch?v=BBB22222222"/>
    <published>2025-12-01T00:00:00+00:00</published>
    <media:thumbnail url="https://i.ytimg.com/vi/BBB22222222/hqdefault.jpg"/>
  </entry>
</feed>`;

test('parseAtomFeed extracts channel + entries with all fields', () => {
    const feed = parseAtomFeed(SAMPLE_FEED);
    assert.equal(feed.channelId, 'UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(feed.channelName, 'Test Channel');
    assert.equal(feed.entries.length, 2);
    assert.equal(feed.entries[0].videoId, 'AAA11111111');
    assert.equal(feed.entries[0].title, 'Newest video & title'); // entity decoded
    assert.equal(feed.entries[0].url, 'https://www.youtube.com/watch?v=AAA11111111');
    assert.ok(feed.entries[0].publishedAt instanceof Date);
    assert.match(feed.entries[0].thumbnail, /hqdefault/);
});

test('parseAtomFeed tolerates a channel with zero entries (new channel)', () => {
    const empty = SAMPLE_FEED.replace(/<entry>[\s\S]*?<\/entry>/g, '');
    const feed = parseAtomFeed(empty, 'UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(feed.entries.length, 0);
    assert.equal(feed.channelName, 'Test Channel');
});

test('parseAtomFeed rejects a non-feed / empty body with malformed_feed', () => {
    assert.throws(() => parseAtomFeed('not xml at all'), (e) => e.code === 'malformed_feed');
    assert.throws(() => parseAtomFeed(''), (e) => e.code === 'malformed_feed');
    assert.throws(() => parseAtomFeed('<html><body>nope</body></html>'), (e) => e.code === 'malformed_feed');
});

test('parseAtomFeed skips entries without a valid video id', () => {
    const feed = parseAtomFeed(SAMPLE_FEED
        .replace('<yt:videoId>AAA11111111</yt:videoId>', '')
        .replace('<id>yt:video:AAA11111111</id>', ''));
    assert.equal(feed.entries.length, 1);
    assert.equal(feed.entries[0].videoId, 'BBB22222222');
});

test('parseChannelHtml extracts channel id, name and avatar', () => {
    const html = `<html><head><meta property="og:title" content="Some Channel"><meta property="og:image" content="https://yt3.ggpht.com/avatar.jpg"></head><body>"channelId":"UCX6OQ3DkcsbYNE6H8uQQuVA"</body></html>`;
    const parsed = parseChannelHtml(html);
    assert.equal(parsed.channelId, 'UCX6OQ3DkcsbYNE6H8uQQuVA');
    assert.equal(parsed.name, 'Some Channel');
    assert.equal(parsed.avatarUrl, 'https://yt3.ggpht.com/avatar.jpg');
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Template normalization + announcement payload
// ─────────────────────────────────────────────────────────────────────────────

test('normalizeTemplate fills defaults and clamps + validates color', () => {
    const t = yc.normalizeTemplate({ color: 'red', title: 'x'.repeat(500) });
    assert.equal(t.color, yc.DEFAULT_COLOR); // invalid color → default
    assert.equal(t.title.length, 256);       // clamped
    assert.equal(t.showCreator, true);       // default on
    assert.equal(t.mentionRoleId, null);
    assert.equal(t.contentMentions, false);  // @everyone off by default
});

test('normalizeTemplate accepts a valid hex color and preserves booleans', () => {
    const t = yc.normalizeTemplate({ color: '#123abc', showThumbnail: false, contentMentions: true });
    assert.equal(t.color, '#123abc');
    assert.equal(t.showThumbnail, false);
    assert.equal(t.contentMentions, true);
});

test('buildAllowedMentions never allows @everyone unless opted in, and only the configured role', () => {
    assert.deepEqual(yc.buildAllowedMentions({}), { parse: [] });
    assert.deepEqual(yc.buildAllowedMentions({ mentionRoleId: '123' }), { parse: [], roles: ['123'] });
    assert.deepEqual(yc.buildAllowedMentions({ contentMentions: true }), { parse: ['everyone'] });
});

test('buildAnnouncementPayload produces a complete default embed', () => {
    const p = buildAnnouncementPayload({
        subscription: { channelName: 'Creator X', channelUrl: 'https://youtube.com/channel/UCx' },
        video: { videoId: 'AAA11111111', title: 'My New Video', url: 'https://youtu.be/AAA11111111' },
    });
    assert.equal(p.embeds.length, 1);
    const e = p.embeds[0];
    assert.match(e.title, /Creator X/);
    assert.equal(e.description, 'My New Video');
    assert.equal(e.color, 0xFF0000);
    assert.equal(e.author.name, 'Creator X');
    assert.match(e.image.url, /hqdefault/);
    assert.ok(Array.isArray(e.fields));
    assert.equal(e.footer.text, 'PrimeBot • YouTube Notifications');
    assert.deepEqual(p.allowed_mentions, { parse: [] });
    assert.equal(p.content, '');
});

test('buildAnnouncementPayload renders placeholders + role mention content', () => {
    const p = buildAnnouncementPayload({
        subscription: { channelName: 'Creator X' },
        video: { videoId: 'AAA11111111', title: 'Video', url: 'https://youtu.be/AAA11111111' },
        template: { title: 'New from {creator}', description: '{videoTitle}', mentionRoleId: '999', contentMentions: false },
    });
    assert.equal(p.embeds[0].title, 'New from Creator X');
    assert.equal(p.embeds[0].description, 'Video');
    assert.equal(p.content, '<@&999>');
    assert.deepEqual(p.allowed_mentions, { parse: [], roles: ['999'] });
});

test('buildAnnouncementPayload test mode prefixes [Test]', () => {
    const p = buildAnnouncementPayload({ subscription: {}, video: {}, test: true });
    assert.match(p.embeds[0].title, /^\[Test\]/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Monitoring manager (in-memory pool stub)
// ─────────────────────────────────────────────────────────────────────────────

const youtubeDb = require('../server/youtubeDb');

// In-memory store + a query stub that understands the feature's SQL. Models the
// UNIQUE (guild, youtube_channel, video) announcement constraint so dedup is
// tested for real.
function makeInMemoryPool() {
    const state = { subs: [], announcements: [], lease: null, nextSubId: 1, nextAnnId: 1 };
    youtubeDb.youtubePool.query = async (sql, params = []) => {
        const s = sql.replace(/\s+/g, ' ').trim();
        if (/^CREATE TABLE|^ALTER TABLE|^CREATE UNIQUE INDEX|^CREATE INDEX/i.test(s)) return { rows: [], rowCount: 0 };

        if (/FROM youtube_subscriptions WHERE enabled = true/i.test(s)) {
            const due = state.subs.filter(x => x.enabled && !x.paused && x.discord_channel_id
                && (!x.next_check_at || new Date(x.next_check_at) <= new Date()));
            due.sort((a, b) => new Date(a.next_check_at || 0) - new Date(b.next_check_at || 0));
            return { rows: due.slice(0, params[0]).map(r => ({ ...r })) };
        }
        if (/UPDATE youtube_subscriptions SET baseline_done = true/i.test(s)) {
            const sub = state.subs.find(x => x.id === params[0]);
            if (sub) { sub.baseline_done = true; sub.last_video_id = params[1]; sub.last_error = null; sub.error_count = 0; sub.next_check_at = null; }
            return { rows: [], rowCount: 1 };
        }
        if (/UPDATE youtube_subscriptions SET last_video_id = \$2, last_checked_at/i.test(s)) {
            const sub = state.subs.find(x => x.id === params[0]);
            if (sub) { sub.last_video_id = params[1]; sub.last_checked_at = new Date(); sub.last_success_at = new Date(); sub.last_error = null; sub.error_count = 0; sub.next_check_at = null; }
            return { rows: [], rowCount: 1 };
        }
        if (/UPDATE youtube_subscriptions SET last_checked_at = NOW\(\), last_error/i.test(s)) {
            const sub = state.subs.find(x => x.id === params[0]);
            if (sub) { sub.last_error = params[1]; sub.error_count = params[2]; sub.next_check_at = params[3]; }
            return { rows: [], rowCount: 1 };
        }
        if (/UPDATE youtube_subscriptions SET channel_name = COALESCE/i.test(s)) {
            const sub = state.subs.find(x => x.id === params[0]);
            if (sub) { if (params[1]) sub.channel_name = params[1]; if (params[2]) sub.channel_url = params[2]; }
            return { rows: [], rowCount: 1 };
        }
        if (/INSERT INTO youtube_announcements/i.test(s)) {
            const [guildId, ytId, subId, videoId] = params;
            const dup = state.announcements.find(a => a.guild_id === guildId && a.youtube_channel_id === ytId && a.video_id === videoId);
            if (dup) return { rows: [], rowCount: 0 }; // ON CONFLICT DO NOTHING
            const row = { id: state.nextAnnId++, guild_id: guildId, youtube_channel_id: ytId, subscription_id: subId, video_id: videoId, status: 'pending' };
            state.announcements.push(row);
            return { rows: [{ id: row.id }], rowCount: 1 };
        }
        if (/UPDATE youtube_announcements SET status = 'sent'/i.test(s)) {
            const a = state.announcements.find(x => x.id === params[0]);
            if (a) { a.status = 'sent'; a.discord_message_id = params[1]; }
            return { rows: [], rowCount: 1 };
        }
        if (/UPDATE youtube_announcements SET status = 'failed'/i.test(s)) {
            const a = state.announcements.find(x => x.id === params[0]);
            if (a) { a.status = 'failed'; a.error = params[1]; }
            return { rows: [], rowCount: 1 };
        }
        if (/INSERT INTO youtube_poll_lease/i.test(s)) {
            const [id, holder, ttl] = params;
            const now = Date.now();
            if (state.lease && new Date(state.lease.expires_at).getTime() > now && state.lease.holder !== holder) {
                return { rows: [], rowCount: 0 };
            }
            state.lease = { id, holder, expires_at: new Date(now + Number(ttl) * 1000) };
            return { rows: [{ holder }], rowCount: 1 };
        }
        if (/DELETE FROM youtube_poll_lease/i.test(s)) {
            if (state.lease && state.lease.holder === params[1]) { state.lease = null; return { rows: [], rowCount: 1 }; }
            return { rows: [], rowCount: 0 };
        }
        if (/SELECT holder, expires_at, updated_at FROM youtube_poll_lease/i.test(s)) {
            return { rows: state.lease ? [state.lease] : [] };
        }
        throw new Error('Unexpected SQL: ' + s.slice(0, 80));
    };
    return state;
}

const state = makeInMemoryPool();
const { YouTubeManager } = require('../utils/youtubeManager');
const feedModule = require('../utils/youtubeFeed');

function addSub(overrides = {}) {
    const sub = {
        id: state.nextSubId++, guild_id: '100000000000000001', youtube_channel_id: 'UCX6OQ3DkcsbYNE6H8uQQuVA',
        channel_name: 'Test Channel', channel_url: null, channel_handle: null, avatar_url: null,
        discord_channel_id: '200000000000000001', enabled: true, paused: false, template: {},
        last_video_id: null, baseline_done: false, last_checked_at: null, last_success_at: null,
        last_error: null, error_count: 0, next_check_at: null, ...overrides,
    };
    state.subs.push(sub);
    return sub;
}

// A fake discord.js client whose channels resolve to a capturing channel.
function makeClient({ channelExists = true, sendImpl } = {}) {
    const sent = [];
    const channel = {
        isTextBased: () => true,
        send: async (payload) => {
            if (sendImpl) return sendImpl(payload);
            sent.push(payload);
            return { id: `msg-${sent.length}` };
        },
    };
    return {
        sent,
        guilds: { cache: { get: (id) => (channelExists ? { channels: { fetch: async () => channel } } : undefined) } },
    };
}

function feedWith(videoIds) {
    // Real YouTube feeds list newest first — assign descending timestamps so
    // index 0 is the newest entry (the manager sorts ascending internally).
    const entries = videoIds.map((id, i) => ({
        videoId: id, title: `Video ${id}`, url: `https://youtu.be/${id}`,
        publishedAt: new Date(2026, 0, 28 - i), thumbnail: `https://i.ytimg.com/vi/${id}/hqdefault.jpg`,
        channelId: 'UCX6OQ3DkcsbYNE6H8uQQuVA', authorName: 'Test Channel',
    }));
    return { channelId: 'UCX6OQ3DkcsbYNE6H8uQQuVA', channelName: 'Test Channel', channelUrl: null, entries };
}

test('baseline: the first check stores the newest video and announces nothing', async () => {
    state.subs.length = 0; state.announcements.length = 0;
    addSub();
    feedModule.fetchChannelFeed = async () => feedWith(['NEWESTVID01', 'OLD2OLD2OLD']);
    const client = makeClient();
    const mgr = new YouTubeManager(client);
    const res = await mgr._checkSubscription(state.subs[0]);
    assert.equal(res.baseline, true);
    assert.equal(res.announced, 0);
    assert.equal(state.subs[0].last_video_id, 'NEWESTVID01'); // newest (first in feed order)
    assert.equal(state.subs[0].baseline_done, true);
    assert.equal(client.sent.length, 0, 'no announcements on baseline');
});

test('new upload detection: only videos after the last-seen id are announced, oldest first', async () => {
    state.subs.length = 0; state.announcements.length = 0;
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });
    // Feed lists newest first (real YouTube order).
    feedModule.fetchChannelFeed = async () => feedWith(['VID0000003', 'VID0000002', 'VID0000001']);
    const client = makeClient();
    const mgr = new YouTubeManager(client);
    const res = await mgr._checkSubscription(state.subs[0]);
    assert.equal(res.announced, 2);
    // Announced in chronological order: 0000002 then 0000003.
    assert.match(client.sent[0].embeds[0].data.description, /VID0000002/);
    assert.match(client.sent[1].embeds[0].data.description, /VID0000003/);
    assert.equal(state.subs[0].last_video_id, 'VID0000003');
});

test('duplicate video is never announced twice (DB claim is authoritative)', async () => {
    state.subs.length = 0; state.announcements.length = 0;
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });
    feedModule.fetchChannelFeed = async () => feedWith(['VID0000002', 'VID0000001']);
    const client = makeClient();
    const mgr = new YouTubeManager(client);
    await mgr._checkSubscription(state.subs[0]);
    assert.equal(client.sent.length, 1);
    // A second node re-checks the same feed before the watermark moved (or a
    // retry replays it): the claim collides, so no second send.
    const mgr2 = new YouTubeManager(makeClient());
    state.subs[0].last_video_id = 'VID0000001'; // simulate a stale watermark
    const res2 = await mgr2._checkSubscription(state.subs[0]);
    assert.equal(res2.announced, 0, 'the unique constraint blocks the duplicate');
});

test('a failed Discord send is recorded and does not retry forever', async () => {
    state.subs.length = 0; state.announcements.length = 0;
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });
    feedModule.fetchChannelFeed = async () => feedWith(['VID0000002', 'VID0000001']);
    const client = makeClient({ sendImpl: async () => { throw new Error('Missing Permissions'); } });
    const mgr = new YouTubeManager(client);
    const res = await mgr._checkSubscription(state.subs[0]);
    assert.equal(res.announced, 0);
    assert.equal(state.announcements[0].status, 'failed');
    // The watermark still advanced so the same failure is not retried forever.
    assert.equal(state.subs[0].last_video_id, 'VID0000002');
});

test('a feed error backs off and records last_error (isolated per subscription)', async () => {
    state.subs.length = 0;
    addSub();
    feedModule.fetchChannelFeed = async () => { throw new YouTubeFetchError('timeout', { code: 'timeout' }); };
    const mgr = new YouTubeManager(makeClient());
    const res = await mgr._checkSubscription(state.subs[0]);
    assert.equal(res.error, 'timeout');
    assert.equal(state.subs[0].error_count, 1);
    assert.ok(state.subs[0].next_check_at, 'a retry is scheduled');
});

test('one broken subscription does not stop the others', async () => {
    state.subs.length = 0; state.announcements.length = 0;
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });        // will fail
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });        // will succeed
    let call = 0;
    feedModule.fetchChannelFeed = async () => {
        call++;
        if (call === 1) throw new YouTubeFetchError('boom', { code: 'network' });
        return feedWith(['VID0000002', 'VID0000001']);
    };
    const client = makeClient();
    const mgr = new YouTubeManager(client);
    await mgr._runDueChecks();
    assert.equal(client.sent.length, 1, 'the healthy subscription still announced');
});

test('the polling lease allows only one holder; expiry recovers it', async () => {
    state.lease = null;
    assert.equal(await youtubeDb.acquirePollLease('nodeA', 90), true);
    assert.equal(await youtubeDb.acquirePollLease('nodeB', 90), false, 'nodeB cannot steal a live lease');
    // Simulate nodeA crashing: its lease expires.
    state.lease.expires_at = new Date(Date.now() - 1000);
    assert.equal(await youtubeDb.acquirePollLease('nodeB', 90), true, 'expired lease is recoverable');
    assert.equal(state.lease.holder, 'nodeB');
    // The holder can renew its own lease.
    assert.equal(await youtubeDb.acquirePollLease('nodeB', 90), true);
});

test('the lease holder is the only one that polls', async () => {
    state.lease = null; state.subs.length = 0; state.announcements.length = 0;
    addSub({ baseline_done: true, last_video_id: 'VID0000001' });
    feedModule.fetchChannelFeed = async () => feedWith(['VID0000002', 'VID0000001']);
    const a = new YouTubeManager(makeClient());
    const b = new YouTubeManager(makeClient());
    // a takes the lease and polls; b must not.
    await a._loop();
    await b._loop();
    assert.equal(a.status.active, true);
    assert.equal(b.status.active, false);
    assert.equal(a.client.sent.length, 1);
    assert.equal(b.client.sent.length, 0, 'the non-holder never announced');
});

test('test announcement builds a [Test] payload and needs a destination', async () => {
    const mgr = new YouTubeManager(makeClient());
    await assert.rejects(() => mgr.sendTestAnnouncement({ guild_id: '1', discord_channel_id: null }), /No destination channel/);
    const client = makeClient();
    const mgr2 = new YouTubeManager(client);
    const r = await mgr2.sendTestAnnouncement({ guild_id: '100000000000000001', discord_channel_id: '200000000000000001', channel_name: 'C' });
    assert.ok(r.messageId);
    assert.match(client.sent[0].embeds[0].data.title, /^\[Test\]/);
});

test('sendTestAnnouncement surfaces a missing guild/channel clearly', async () => {
    const mgr = new YouTubeManager(makeClient({ channelExists: false }));
    await assert.rejects(() => mgr.sendTestAnnouncement({ guild_id: '999', discord_channel_id: '1' }), /Guild not cached/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Dashboard API over real HTTP
// ─────────────────────────────────────────────────────────────────────────────

const SESSION_SECRET = 'test-secret';
const DASH = path.join(__dirname, '..', 'dashboard');

function bootApp() {
    const savedDbUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = SESSION_SECRET;
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    const mockDb = {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] }),
        getServerSettings: async () => ({}), upsertServerSettings: async (g, p) => p,
        getYoutubeSubscriptions: async () => [], getYoutubeAnnouncements: async () => [],
        getYoutubeStats: async () => ({}), getYoutubeGroups: async () => [],
        getYoutubeSubscription: async () => null, getYoutubeSubscriptionByChannel: async () => null, upsertYoutubeSubscription: async () => ({}),
        updateYoutubeSubscription: async () => ({}), deleteYoutubeSubscription: async () => true,
        addWebsiteLog: async () => {},
    };
    const mockDiscord = {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async (id) => ({ id, name: 'Test', approximate_member_count: 1 }),
        getGuildChannels: async () => [{ id: '111111111111111111', name: 'general' }],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({}), getCurrentUser: async () => ({ id: '1', username: 't' }),
        getUserGuilds: async () => [], canManageGuild: () => true,
        sendChannelMessage: async () => ({ id: 'msg1' }),
    };

    const origLoad = Module._load;
    Module._load = function (request, parent) {
        const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
        if (fromDash && request === './db') return mockDb;
        if (fromDash && request === './discord') return mockDiscord;
        if (fromDash && request === '../server/seasonDb') throw new Error('mock: no season pool');
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/server')];
        return require('../dashboard/server');
    } finally {
        Module._load = origLoad;
        if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
    }
}

function fetchOnce(server, urlPath, opts = {}) {
    const { method = 'GET', headers = {}, body } = opts;
    return new Promise((resolve, reject) => {
        const req = http.request({ port: server.address().port, path: urlPath, method, headers: { ...headers } },
            (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d })); });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

test('HTTP: youtube routes are 401 unauthenticated and the page redirects to /login', async () => {
    const app = bootApp();
    const server = await new Promise(r => { const s = app.listen(0, () => r(s)); });
    const json = { Accept: 'application/json' };
    try {
        for (const [m, p] of [['GET', '/api/guilds/123456789012345678/youtube'], ['POST', '/api/guilds/123456789012345678/youtube'],
            ['PATCH', '/api/guilds/123456789012345678/youtube/1'], ['DELETE', '/api/guilds/123456789012345678/youtube/1'],
            ['POST', '/api/guilds/123456789012345678/youtube/1/test']]) {
            const res = await fetchOnce(server, p, { method: m, headers: json });
            assert.equal(res.status, 401, `${m} ${p} should be 401`);
        }
        // The page route redirects an unauthenticated browser to /login.
        const page = await fetchOnce(server, '/guild/123456789012345678/youtube', { headers: { Accept: 'text/html' } });
        assert.equal(page.status, 302);
        assert.match(page.headers.location || '', /\/login/);
    } finally { server.close(); }
});

test('HTTP: the youtube API is guarded (no unauthenticated write reaches the DB)', async () => {
    const app = bootApp();
    const server = await new Promise(r => { const s = app.listen(0, () => r(s)); });
    try {
        const res = await fetchOnce(server, '/api/guilds/123456789012345678/youtube', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ reference: 'https://www.youtube.com/@SomeHandle', channelId: '111111111111111111' }),
        });
        assert.equal(res.status, 401);
        const body = JSON.parse(res.body);
        assert.match(body.error, /Not authenticated/i);
    } finally { server.close(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Serverless 504 hardening (YouTube resolve deadline)
// ─────────────────────────────────────────────────────────────────────────────

test('withDeadline resolves when the promise beats the deadline', async () => {
    const value = await withDeadline(Promise.resolve(42), 5000);
    assert.equal(value, 42);
});

test('withDeadline rejects with status 504 when the promise never settles', async () => {
    const never = () => new Promise(() => {});
    const err = await withDeadline(never(), 30).then(
        () => { throw new Error('should have timed out'); },
        (e) => e
    );
    assert.equal(err.status, 504);
    assert.match(err.message, /timed out/i);
});


