/**
 * YouTube feed fetching + parsing (public RSS/Atom — no API key, no login).
 *
 * Responsibilities:
 *   • `resolveChannelReference(ref)` — turn a URL / @handle / channel id into a
 *     stable channel id (+ display name / avatar where available). A channel id
 *     is verified by fetching its feed; handles/legacy URLs are resolved from
 *     the public channel HTML.
 *   • `fetchChannelFeed(channelId)` — fetch + parse the Atom feed into a list of
 *     uploads (video id, title, url, published time, thumbnail).
 *
 * Safety:
 *   • Only https, only hosts in shared/youtubeConstants ALLOWED_HOSTS — a
 *     user-supplied URL can never make the bot fetch an arbitrary host (SSRF).
 *   • Bounded timeout, bounded redirects, bounded response size.
 *   • No video bytes are ever downloaded — only the small feed/HTML documents.
 *
 * This module is pure I/O; the manager owns scheduling/leasing/dedup.
 */

const https = require('https');
const {
    ALLOWED_HOSTS,
    feedUrl,
    channelUrl,
    isValidChannelId,
    isValidVideoId,
    parseChannelReference,
} = require('../shared/youtubeConstants');

const DEFAULT_TIMEOUT_MS = parseInt(process.env.YOUTUBE_REQUEST_TIMEOUT_MS, 10) || 10000;
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB — feeds/HTML are far smaller.
const MAX_REDIRECTS = 4;
const USER_AGENT = 'Mozilla/5.0 (compatible; PrimeBot/1.0; +https://cpanel-primebot.vercel.app)';

class YouTubeFetchError extends Error {
    constructor(message, { code = 'fetch_error', status = null, retryable = true } = {}) {
        super(message);
        this.name = 'YouTubeFetchError';
        this.code = code;
        this.status = status;
        this.retryable = retryable;
    }
}

function assertAllowed(url) {
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new YouTubeFetchError('Invalid URL', { code: 'bad_url', retryable: false });
    }
    if (parsed.protocol !== 'https:') {
        throw new YouTubeFetchError('Only https is allowed', { code: 'bad_protocol', retryable: false });
    }
    if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
        throw new YouTubeFetchError(`Host not allowed: ${parsed.hostname}`, { code: 'untrusted_host', retryable: false });
    }
    return parsed;
}

/** Minimal https GET with timeout + redirects + size cap. Returns { status, body }. */
async function httpGet(url, { timeoutMs = DEFAULT_TIMEOUT_MS, redirects = 0 } = {}) {
    assertAllowed(url);
    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'application/atom+xml, application/xml, text/html;q=0.9, */*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
            timeout: timeoutMs,
        }, (res) => {
            const status = res.statusCode || 0;
            // Redirect handling (YouTube serves a 30x for some canonical forms).
            if (status >= 300 && status < 400 && res.headers.location) {
                res.resume();
                if (redirects >= MAX_REDIRECTS) {
                    reject(new YouTubeFetchError('Too many redirects', { code: 'too_many_redirects' }));
                    return;
                }
                let next;
                try { next = new URL(res.headers.location, url).toString(); } catch {
                    reject(new YouTubeFetchError('Bad redirect target', { code: 'bad_redirect' }));
                    return;
                }
                httpGet(next, { timeoutMs, redirects: redirects + 1 }).then(resolve, reject);
                return;
            }
            if (status === 429) {
                res.resume();
                reject(new YouTubeFetchError('Rate limited by YouTube', { code: 'rate_limited', status, retryable: true }));
                return;
            }
            if (status >= 400) {
                res.resume();
                reject(new YouTubeFetchError(`YouTube returned HTTP ${status}`, {
                    code: status === 404 ? 'not_found' : 'http_error',
                    status,
                    retryable: status >= 500,
                }));
                return;
            }
            let size = 0;
            const chunks = [];
            res.on('data', (chunk) => {
                size += chunk.length;
                if (size > MAX_BODY_BYTES) {
                    req.destroy();
                    reject(new YouTubeFetchError('Response too large', { code: 'too_large', retryable: false }));
                    return;
                }
                chunks.push(chunk);
            });
            res.on('end', () => resolve({ status, body: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('timeout', () => {
            req.destroy();
            reject(new YouTubeFetchError('Request timed out', { code: 'timeout', retryable: true }));
        });
        req.on('error', (err) => {
            reject(new YouTubeFetchError(`Network error: ${err.message}`, { code: 'network', retryable: true }));
        });
    });
}

// ── Atom parsing ────────────────────────────────────────────────────────────

function decodeEntities(str) {
    if (!str) return '';
    return String(str)
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, '&')
        .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(parseInt(n, 10)));
}

function firstMatch(str, re) {
    const m = str.match(re);
    return m ? decodeEntities(m[1].trim()) : null;
}

/**
 * Parse a YouTube Atom feed. Throws YouTubeFetchError('malformed_feed') when the
 * document is not a feed at all; tolerates feeds with zero entries (a brand-new
 * channel). Returns { channelId, channelName, channelUrl, entries: [...] }.
 */
function parseAtomFeed(xml, fallbackChannelId = null) {
    if (typeof xml !== 'string' || !xml.trim()) {
        throw new YouTubeFetchError('Empty feed body', { code: 'malformed_feed', retryable: true });
    }
    if (!/<feed[\s>]/i.test(xml)) {
        throw new YouTubeFetchError('Response is not an Atom feed', { code: 'malformed_feed', retryable: true });
    }

    // Everything up to the first <entry> is the channel-level metadata.
    const firstEntryIdx = xml.search(/<entry[\s>]/i);
    const head = firstEntryIdx === -1 ? xml : xml.slice(0, firstEntryIdx);

    const channelId = firstMatch(head, /<yt:channelId>\s*([^<\s]+)\s*<\/yt:channelId>/i)
        || firstMatch(xml, /<id>\s*yt:channel:([0-9A-Za-z_-]+)\s*<\/id>/i)
        || fallbackChannelId;
    // The channel title is the first <title> in the document (entries follow).
    const channelName = firstMatch(head, /<title[^>]*>([\s\S]*?)<\/title>/i)
        || firstMatch(head, /<author>[\s\S]*?<name>([\s\S]*?)<\/name>/i);
    const channelLink = firstMatch(head, /<link[^>]*rel="alternate"[^>]*href="([^"]+)"/i);

    const entries = [];
    const entryRe = /<entry[\s>][\s\S]*?<\/entry>/gi;
    let m;
    while ((m = entryRe.exec(xml)) !== null) {
        const entryXml = m[0];
        const videoId = firstMatch(entryXml, /<yt:videoId>\s*([^<\s]+)\s*<\/yt:videoId>/i)
            || (() => {
                const id = firstMatch(entryXml, /<id>\s*yt:video:([0-9A-Za-z_-]+)\s*<\/id>/i);
                return id;
            })();
        if (!videoId || !isValidVideoId(videoId)) continue;

        const title = firstMatch(entryXml, /<title[^>]*>([\s\S]*?)<\/title>/i) || 'Untitled video';
        const published = firstMatch(entryXml, /<published>([\s\S]*?)<\/published>/i)
            || firstMatch(entryXml, /<updated>([\s\S]*?)<\/updated>/i);
        const link = firstMatch(entryXml, /<link[^>]*rel="alternate"[^>]*href="([^"]+)"/i)
            || `https://www.youtube.com/watch?v=${videoId}`;
        const thumbnail = firstMatch(entryXml, /<media:thumbnail[^>]*url="([^"]+)"/i)
            || `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`;
        const entryChannelId = firstMatch(entryXml, /<yt:channelId>\s*([^<\s]+)\s*<\/yt:channelId>/i) || channelId;
        const authorName = firstMatch(entryXml, /<author>[\s\S]*?<name>([\s\S]*?)<\/name>/i);

        entries.push({
            videoId,
            title,
            url: link,
            publishedAt: published ? new Date(published) : null,
            publishedAtRaw: published || null,
            thumbnail,
            channelId: entryChannelId,
            authorName: authorName || channelName || null,
        });
    }

    return {
        channelId,
        channelName: channelName || null,
        channelUrl: channelLink || (channelId ? channelUrl(channelId) : null),
        entries,
    };
}

/**
 * Fetch + parse a channel's upload feed. The newest entries come first in the
 * YouTube feed, so callers can diff the head against the last-seen video id.
 */
async function fetchChannelFeed(channelId, opts = {}) {
    if (!isValidChannelId(channelId)) {
        throw new YouTubeFetchError('Invalid channel id', { code: 'bad_channel_id', retryable: false });
    }
    const { body } = await httpGet(feedUrl(channelId), opts);
    return parseAtomFeed(body, channelId);
}

// ── Channel resolution ──────────────────────────────────────────────────────

/** Extract a channel id / name / avatar from a YouTube channel HTML page. */
function parseChannelHtml(html) {
    const channelId = firstMatch(html, /"channelId":"(UC[0-9A-Za-z_-]{22})"/)
        || firstMatch(html, /<link[^>]*rel="canonical"[^>]*href="https:\/\/www\.youtube\.com\/channel\/(UC[0-9A-Za-z_-]{22})"/i)
        || firstMatch(html, /channel_id=(UC[0-9A-Za-z_-]{22})/);
    const name = firstMatch(html, /<meta[^>]*property="og:title"[^>]*content="([^"]*)"/i)
        || firstMatch(html, /<title[^>]*>([\s\S]*?)<\/title>/i);
    const avatarUrl = firstMatch(html, /<meta[^>]*property="og:image"[^>]*content="([^"]*)"/i)
        || firstMatch(html, /"avatar":\{"thumbnails":\[\{"url":"([^"]+)"/);
    return { channelId, name, avatarUrl };
}

/**
 * Resolve any accepted reference (channel id, @handle, legacy /user or /c URL,
 * or a full channel URL) into a stable descriptor:
 *   { channelId, name, handle, avatarUrl, url }
 *
 * Throws YouTubeFetchError with a clear code on failure. NEVER assumes a URL
 * contains a channel id — handles/legacy URLs are resolved from the HTML.
 */
async function resolveChannelReference(raw, opts = {}) {
    const ref = parseChannelReference(raw);
    switch (ref.kind) {
        case 'invalid':
            throw new YouTubeFetchError(`Could not read a YouTube channel from "${raw}" (${ref.reason}).`, {
                code: `invalid_reference_${ref.reason}`,
                retryable: false,
            });
        case 'channelId':
            return verifyChannelId(ref.channelId, opts);
        case 'handle':
            return resolveFromHtml(`https://www.youtube.com/@${encodeURIComponent(ref.handle)}`, { handle: ref.handle }, opts);
        case 'user':
            return resolveFromHtml(`https://www.youtube.com/user/${encodeURIComponent(ref.username)}`, {}, opts);
        case 'custom':
            return resolveFromHtml(`https://www.youtube.com/c/${encodeURIComponent(ref.path)}`, {}, opts);
        case 'url':
            return resolveFromHtml(ref.url, {}, opts);
        default:
            throw new YouTubeFetchError('Unsupported reference', { code: 'unsupported_reference', retryable: false });
    }
}

/**
 * Verify a channel id by fetching its feed (this also yields the display name
 * and confirms the channel exists + is public). Falls back to the channel HTML
 * for the avatar when the feed lacks one.
 */
async function verifyChannelId(channelId, opts = {}) {
    let feed;
    try {
        feed = await fetchChannelFeed(channelId, opts);
    } catch (err) {
        if (err instanceof YouTubeFetchError && (err.code === 'not_found' || err.code === 'malformed_feed')) {
            throw new YouTubeFetchError(`No public YouTube channel with id ${channelId}.`, { code: 'channel_not_found', retryable: false });
        }
        throw err;
    }
    let avatarUrl = null;
    try {
        const { body } = await httpGet(channelUrl(channelId), opts);
        avatarUrl = parseChannelHtml(body).avatarUrl || null;
    } catch { /* avatar is best-effort — never block resolution on it */ }
    return {
        channelId,
        name: feed.channelName || null,
        handle: null,
        avatarUrl,
        url: channelUrl(channelId),
    };
}

/** Resolve a non-id reference by fetching the channel HTML page. */
async function resolveFromHtml(url, extra = {}, opts = {}) {
    const { body } = await httpGet(url, opts);
    const parsed = parseChannelHtml(body);
    if (!parsed.channelId || !isValidChannelId(parsed.channelId)) {
        throw new YouTubeFetchError(
            'Could not resolve that YouTube URL to a channel id. Use the channel page URL (…/channel/UC…, …/@handle) or paste the channel id directly.',
            { code: 'channel_unresolved', retryable: false }
        );
    }
    return {
        channelId: parsed.channelId,
        name: parsed.name || null,
        handle: extra.handle || null,
        avatarUrl: parsed.avatarUrl || null,
        url: channelUrl(parsed.channelId),
    };
}

module.exports = {
    YouTubeFetchError,
    httpGet,
    parseAtomFeed,
    parseChannelHtml,
    fetchChannelFeed,
    resolveChannelReference,
    verifyChannelId,
    resolveFromHtml,
};
