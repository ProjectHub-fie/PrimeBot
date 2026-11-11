/**
 * YouTube Notifications — shared constants + pure helpers.
 *
 * Single source of truth for the bot (`utils/youtubeManager.js`,
 * `utils/youtubeFeed.js`) and the dashboard (`dashboard/db.js`,
 * `dashboard/render/youtube-page.js`). Keeping the catalog + normalizers here
 * means the two sides can never drift on what a valid setting looks like.
 *
 * Nothing in this file performs network or database I/O — it is pure and
 * therefore trivially unit-testable.
 */

// ── YouTube URL / ID handling ───────────────────────────────────────────────
//
// A YouTube channel id is a stable, opaque 24-character string beginning with
// "UC" (e.g. UCXuqSBlHAE6Xw-yeJA0Tunw). We accept the shapes a user is likely
// to paste and resolve the rest (handles/legacy URLs) over the network.
const CHANNEL_ID_RE = /^UC[0-9A-Za-z_-]{22}$/;
// A video id is an 11-character token (letters, digits, "-", "_").
const VIDEO_ID_RE = /^[0-9A-Za-z_-]{11}$/;

// Hosts we will ever fetch from. Anything else is refused (SSRF guard) — the
// feature only talks to YouTube's public RSS + HTML endpoints.
const ALLOWED_HOSTS = new Set([
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'music.youtube.com',
    'youtu.be',
    'www.youtu.be',
]);

// The RSS/Atom endpoint for a channel's uploads. Public, no API key required.
function feedUrl(channelId) {
    return `https://www.youtube.com/feeds/videos.xml?channel_id=${encodeURIComponent(channelId)}`;
}

function isValidChannelId(value) {
    return typeof value === 'string' && CHANNEL_ID_RE.test(value.trim());
}

function isValidVideoId(value) {
    return typeof value === 'string' && VIDEO_ID_RE.test(value.trim());
}

/**
 * Parse a user-supplied YouTube reference into a descriptor.
 *
 * Returns one of:
 *   { kind: 'channelId', channelId }        — a stable id was present
 *   { kind: 'handle',    handle }           — an @handle (needs resolution)
 *   { kind: 'user',      username }         — legacy /user/<name> (needs resolution)
 *   { kind: 'custom',    path }             — legacy /c/<name> (needs resolution)
 *   { kind: 'url',       url }              — a bare youtube.com URL (needs resolution)
 *   { kind: 'invalid',   reason }           — cannot be interpreted
 *
 * This function NEVER assumes every URL contains a channel id — callers must
 * handle the non-`channelId` kinds by resolving them (see utils/youtubeFeed.js).
 */
function parseChannelReference(raw) {
    if (raw == null) return { kind: 'invalid', reason: 'empty' };
    let input = String(raw).trim();
    if (!input) return { kind: 'invalid', reason: 'empty' };

    // A bare channel id.
    if (isValidChannelId(input)) return { kind: 'channelId', channelId: input };

    // A bare @handle (no URL).
    if (/^@[A-Za-z0-9._-]{1,60}$/.test(input)) {
        return { kind: 'handle', handle: input.slice(1) };
    }

    // Anything else must be a URL we recognise.
    let url;
    try {
        url = new URL(input.startsWith('http') ? input : `https://${input}`);
    } catch {
        return { kind: 'invalid', reason: 'unparseable' };
    }

    const host = url.hostname.toLowerCase();
    if (!ALLOWED_HOSTS.has(host)) {
        return { kind: 'invalid', reason: 'untrusted_host', host };
    }

    const segments = url.pathname.split('/').filter(Boolean);

    // youtu.be/<videoId> — a video link; not a channel reference.
    if (host.endsWith('youtu.be')) {
        if (isValidVideoId(segments[0])) return { kind: 'invalid', reason: 'video_url' };
        return { kind: 'invalid', reason: 'not_a_channel' };
    }

    // /channel/<id>
    if (segments[0] === 'channel' && segments[1]) {
        const id = segments[1];
        if (isValidChannelId(id)) return { kind: 'channelId', channelId: id };
        return { kind: 'invalid', reason: 'bad_channel_id' };
    }

    // /@handle (or /@handle/videos)
    if (segments[0] && segments[0].startsWith('@')) {
        const handle = segments[0].slice(1);
        if (/^[A-Za-z0-9._-]{1,60}$/.test(handle)) return { kind: 'handle', handle };
        return { kind: 'invalid', reason: 'bad_handle' };
    }

    // /user/<name> (legacy)
    if (segments[0] === 'user' && segments[1]) {
        return { kind: 'user', username: segments[1] };
    }

    // /c/<name> (legacy custom URL)
    if (segments[0] === 'c' && segments[1]) {
        return { kind: 'custom', path: segments[1] };
    }

    // A bare youtube.com/... we could not classify — let the resolver try.
    if (segments.length === 0) return { kind: 'invalid', reason: 'root_url' };
    return { kind: 'url', url: url.toString() };
}

/** The canonical public channel URL for a resolved channel id. */
function channelUrl(channelId) {
    return `https://www.youtube.com/channel/${channelId}`;
}

// ── Announcement defaults + normalizers ─────────────────────────────────────

const DEFAULT_COLOR = '#FF0000'; // YouTube red

// The built-in professional embed used when a guild has not customized
// anything. Kept as data (not code) so the dashboard can preview it verbatim.
const DEFAULT_TEMPLATE = {
    title: '{creator} just uploaded a new video!',
    message: '',
    description: '{videoTitle}',
    footer: 'PrimeBot • YouTube Notifications',
    color: DEFAULT_COLOR,
    showCreator: true,
    showThumbnail: true,
    showTimestamp: true,
    showVideoUrl: true,
    mentionRoleId: null,
    contentMentions: false, // @everyone / @here are never enabled implicitly
};

// Hard caps mirrored from Discord's embed limits so we never build an invalid
// payload (Discord rejects it wholesale if any single field overflows).
const LIMITS = {
    title: 256,
    description: 4096,
    footer: 2048,
    message: 2000,
    authorName: 256,
};

function clampText(value, max) {
    if (value == null) return '';
    return String(value).slice(0, max);
}

/**
 * Normalize an announcement template (from the dashboard or the DB) into the
 * exact shape the manager renders. Unknown fields are dropped; every string is
 * clamped to Discord's limits; the color is validated as a 6-digit hex.
 */
function normalizeTemplate(raw) {
    const src = (raw && typeof raw === 'object') ? raw : {};
    const pick = (key) => (src[key] == null ? DEFAULT_TEMPLATE[key] : src[key]);
    let color = String(pick('color') || DEFAULT_COLOR).trim();
    if (!/^#[0-9a-fA-F]{6}$/.test(color)) color = DEFAULT_COLOR;
    return {
        title: clampText(pick('title'), LIMITS.title),
        message: clampText(pick('message'), LIMITS.message),
        description: clampText(pick('description'), LIMITS.description),
        footer: clampText(pick('footer'), LIMITS.footer),
        color,
        showCreator: src.showCreator !== false,
        showThumbnail: src.showThumbnail !== false,
        showTimestamp: src.showTimestamp !== false,
        showVideoUrl: src.showVideoUrl !== false,
        mentionRoleId: src.mentionRoleId ? String(src.mentionRoleId) : null,
        contentMentions: src.contentMentions === true,
    };
}

/**
 * Render a template string, substituting the supported placeholders. Unknown
 * placeholders are left as-is (so a typo is visible, not silently blank).
 */
function renderTemplate(template, vars) {
    if (!template) return '';
    return String(template).replace(/\{(\w+)\}/g, (match, key) =>
        Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : match);
}

/**
 * The `allowed_mentions` policy for an announcement. @everyone/@here are only
 * permitted when the admin explicitly opted in (contentMentions) AND the role
 * mention is limited to the configured role id — never "parse: ['roles']",
 * which would allow any role the author happens to write.
 */
function buildAllowedMentions({ mentionRoleId = null, contentMentions = false } = {}) {
    const allowed = { parse: [] };
    if (contentMentions) allowed.parse.push('everyone');
    if (mentionRoleId) allowed.roles = [String(mentionRoleId)];
    return allowed;
}

/** The content line for an announcement (role ping / @everyone), or ''. */
function buildAnnouncementContent(template) {
    const t = template || DEFAULT_TEMPLATE;
    if (t.contentMentions) return '@everyone';
    if (t.mentionRoleId) return `<@&${t.mentionRoleId}>`;
    return '';
}

module.exports = {
    CHANNEL_ID_RE,
    VIDEO_ID_RE,
    ALLOWED_HOSTS,
    DEFAULT_COLOR,
    DEFAULT_TEMPLATE,
    LIMITS,
    feedUrl,
    channelUrl,
    isValidChannelId,
    isValidVideoId,
    parseChannelReference,
    normalizeTemplate,
    renderTemplate,
    buildAllowedMentions,
    buildAnnouncementContent,
    clampText,
};
