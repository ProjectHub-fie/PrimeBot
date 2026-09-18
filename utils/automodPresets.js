/**
 * Automod presets — professional, ready-made protection profiles.
 *
 * A preset is a *partial* guild Automod configuration. Applying one merges it
 * over the guild's current settings (it never wipes unrelated options such as
 * the log channel), and the dashboard always asks for confirmation first
 * because a preset replaces the rules list.
 *
 * Presets are pure data + a pure merge helper so both the dashboard and tests
 * can use them without touching the database. Shared by the dashboard
 * (dashboard/render/guild-pages.js + the API) and the bot's manager.
 */

const { normalizeRules, normalizeWarnActions } = require('./automodRules');

const PRESETS = [
    {
        key: 'community',
        label: 'Community',
        iconName: 'users',
        description: 'Sensible defaults for a normal community server. Blocks invites, phishing links, NSFW and unsafe files, and warns on message flooding.',
        rules: [
            { type: 'invites', enabled: true, actions: ['delete'] },
            { type: 'badLinks', enabled: true, actions: ['delete', 'warn'] },
            { type: 'nsfw', enabled: true, actions: ['delete', 'warn'] },
            { type: 'attachments', enabled: true, actions: ['delete'], safeExtensions: [], maxSizeMb: 50 },
            { type: 'spam', enabled: true, actions: ['warn'], threshold: 6, seconds: 10 },
            { type: 'duplicateMessages', enabled: true, actions: ['warn'], threshold: 3, seconds: 20, similarity: 90 },
            { type: 'mentions', enabled: true, actions: ['warn'], threshold: 8 },
            { type: 'massMention', enabled: true, actions: ['delete', 'warn'], threshold: 5 },
            { type: 'caps', enabled: true, actions: ['delete'], threshold: 80, minLength: 12 },
            { type: 'newAccount', enabled: false, actions: ['warn'], threshold: 3 },
        ],
        warnThreshold: 3,
        warnActions: ['timeout'],
    },
    {
        key: 'balanced',
        label: 'Balanced',
        iconName: 'sliders',
        description: 'Moderate protection that catches the common cases without being aggressive. A good starting point for most servers.',
        rules: [
            { type: 'invites', enabled: true, actions: ['delete'] },
            { type: 'badLinks', enabled: true, actions: ['delete'] },
            { type: 'links', enabled: false, actions: ['delete'], allowedDomains: ['youtube.com', 'github.com', 'tenor.com'] },
            { type: 'nsfw', enabled: true, actions: ['delete', 'warn'] },
            { type: 'spam', enabled: true, actions: ['timeout'], threshold: 5, seconds: 10 },
            { type: 'duplicateMessages', enabled: true, actions: ['delete'], threshold: 3, seconds: 15, similarity: 85 },
            { type: 'mentions', enabled: true, actions: ['warn'], threshold: 8 },
            { type: 'massMention', enabled: true, actions: ['delete', 'timeout'], threshold: 5 },
            { type: 'caps', enabled: true, actions: ['delete'], threshold: 80, minLength: 10 },
            { type: 'emojiSpam', enabled: true, actions: ['delete'], threshold: 12 },
            { type: 'newlines', enabled: true, actions: ['delete'], threshold: 12 },
            { type: 'zalgo', enabled: true, actions: ['delete'] },
            { type: 'repeatedChars', enabled: true, actions: ['delete'], threshold: 15 },
        ],
        warnThreshold: 3,
        warnActions: ['timeout'],
    },
    {
        key: 'strict',
        label: 'Strict',
        iconName: 'shieldAlert',
        description: 'Aggressive spam and link protection. Blocks all links except an allowlist, escalates flooding to timeouts and kicks on repeat warnings.',
        rules: [
            { type: 'invites', enabled: true, actions: ['delete', 'warn'] },
            { type: 'badLinks', enabled: true, actions: ['delete', 'ban'] },
            { type: 'links', enabled: true, actions: ['delete'], allowedDomains: ['youtube.com', 'github.com'], allowDiscordLinks: true },
            { type: 'nsfw', enabled: true, actions: ['delete', 'timeout'] },
            { type: 'attachments', enabled: true, actions: ['delete', 'warn'], safeExtensions: [], maxSizeMb: 10 },
            { type: 'spam', enabled: true, actions: ['timeout'], threshold: 4, seconds: 8 },
            { type: 'duplicateMessages', enabled: true, actions: ['timeout'], threshold: 3, seconds: 15, similarity: 80 },
            { type: 'mentions', enabled: true, actions: ['timeout'], threshold: 5 },
            { type: 'massMention', enabled: true, actions: ['delete', 'timeout'], threshold: 3 },
            { type: 'caps', enabled: true, actions: ['delete'], threshold: 70, minLength: 8 },
            { type: 'emojiSpam', enabled: true, actions: ['delete'], threshold: 8 },
            { type: 'newlines', enabled: true, actions: ['delete'], threshold: 8 },
            { type: 'zalgo', enabled: true, actions: ['delete'] },
            { type: 'repeatedChars', enabled: true, actions: ['delete'], threshold: 10 },
            { type: 'newAccount', enabled: true, actions: ['warn'], threshold: 1 },
        ],
        warnThreshold: 2,
        warnActions: ['timeout', 'kick'],
    },
    {
        key: 'gaming',
        label: 'Gaming',
        iconName: 'trophy',
        description: 'Tuned for busy gaming servers: tolerant of caps, emoji and memes, but hard on flooding, invites and phishing.',
        rules: [
            { type: 'invites', enabled: true, actions: ['delete'] },
            { type: 'badLinks', enabled: true, actions: ['delete', 'ban'] },
            { type: 'links', enabled: false, actions: ['delete'], allowedDomains: ['youtube.com', 'twitch.tv', 'steamcommunity.com', 'github.com'] },
            { type: 'spam', enabled: true, actions: ['timeout'], threshold: 8, seconds: 10 },
            { type: 'duplicateMessages', enabled: true, actions: ['timeout'], threshold: 4, seconds: 20, similarity: 90 },
            { type: 'mentions', enabled: true, actions: ['warn'], threshold: 10 },
            { type: 'massMention', enabled: true, actions: ['delete', 'timeout'], threshold: 5 },
            { type: 'caps', enabled: false, actions: ['delete'], threshold: 90, minLength: 15 },
            { type: 'emojiSpam', enabled: false, actions: ['delete'], threshold: 20 },
            { type: 'newlines', enabled: true, actions: ['delete'], threshold: 15 },
            { type: 'zalgo', enabled: true, actions: ['delete'] },
            { type: 'repeatedChars', enabled: true, actions: ['delete'], threshold: 20 },
        ],
        warnThreshold: 4,
        warnActions: ['timeout'],
    },
    {
        key: 'highSecurity',
        label: 'High Security',
        iconName: 'shield',
        description: 'Maximum protection with raid defences: everything in Strict plus join-burst detection, similar-name raids and an aggressive warning ladder.',
        rules: [
            { type: 'invites', enabled: true, actions: ['delete', 'warn'] },
            { type: 'badLinks', enabled: true, actions: ['delete', 'ban'] },
            { type: 'links', enabled: true, actions: ['delete'], allowedDomains: ['youtube.com'], allowDiscordLinks: true },
            { type: 'nsfw', enabled: true, actions: ['delete', 'ban'] },
            { type: 'attachments', enabled: true, actions: ['delete', 'warn'], safeExtensions: [], maxSizeMb: 5 },
            { type: 'spam', enabled: true, actions: ['timeout', 'kick'], threshold: 3, seconds: 8 },
            { type: 'duplicateMessages', enabled: true, actions: ['timeout'], threshold: 3, seconds: 10, similarity: 80 },
            { type: 'mentions', enabled: true, actions: ['timeout'], threshold: 4 },
            { type: 'massMention', enabled: true, actions: ['delete', 'ban'], threshold: 3 },
            { type: 'caps', enabled: true, actions: ['delete'], threshold: 70, minLength: 8 },
            { type: 'emojiSpam', enabled: true, actions: ['delete'], threshold: 8 },
            { type: 'newlines', enabled: true, actions: ['delete'], threshold: 8 },
            { type: 'zalgo', enabled: true, actions: ['delete'] },
            { type: 'repeatedChars', enabled: true, actions: ['delete'], threshold: 10 },
            { type: 'newAccount', enabled: true, actions: ['timeout'], threshold: 3 },
            { type: 'raidJoin', enabled: true, actions: ['timeout'], threshold: 8, seconds: 20, minAccountAgeDays: 7 },
            { type: 'raidSimilarNames', enabled: true, actions: ['timeout'], threshold: 5, seconds: 30, similarity: 85 },
        ],
        warnThreshold: 2,
        warnActions: ['timeout', 'kick', 'ban'],
    },
];

const PRESET_BY_KEY = Object.fromEntries(PRESETS.map(p => [p.key, p]));

function metaForPreset(key) {
    return PRESET_BY_KEY[String(key || '')] || null;
}

/**
 * Merge a preset over the current settings. Only the fields a preset owns are
 * replaced (rules + the warning ladder); everything else — log channel, mute
 * role, exemptions, DM config, dry-run — is preserved. Returns a patch object
 * suitable for `updateSettings`/`upsertAutomodSettings`.
 */
function buildPresetPatch(key, current = {}) {
    const preset = metaForPreset(key);
    if (!preset) return null;
    const patch = {
        rules: normalizeRules(preset.rules),
    };
    if (preset.warnThreshold != null) patch.warnThreshold = preset.warnThreshold;
    if (preset.warnActions != null) {
        const actions = normalizeWarnActions(preset.warnActions, 'timeout');
        patch.warnActions = actions;
        patch.warnAction = actions[0];
    }
    // A preset never silently flips the master switch: an admin who applies a
    // preset to a disabled server almost certainly wants it turned on, so we
    // enable it, but we never disable it.
    if (current.enabled !== true) patch.enabled = true;
    return patch;
}

module.exports = { PRESETS, PRESET_BY_KEY, metaForPreset, buildPresetPatch };
