/**
 * Canonical Automod rule catalog.
 *
 * Single source of truth for the rule types PrimeBot Automod understands, their
 * labels, icons, categories, the parameters each rule accepts and the actions
 * they can take. Shared by the bot (utils/automodManager.js), the dashboard
 * (constants + UI) and tests so they all agree on what a rule looks like.
 *
 * Adding a new rule type is a one-line change here plus the matching logic in
 * AutomodManager.matchRule(). Everything ships free — PrimeBot's motto is
 * "premium features in free".
 */

/**
 * @typedef {Object} RuleMeta
 * @property {string} key        - Stable identifier stored in rule.type.
 * @property {string} label      - Human label shown in the dashboard.
 * @property {string} icon       - Emoji prefix for the dashboard/log embed.
 * @property {string} category   - Grouping for the dashboard UI.
 * @property {string} description
 * @property {string[]} params   - Extra fields this rule accepts beyond the
 *                                  common { enabled, action } pair.
 * @property {string[]} actions  - Action keys valid for this rule (subset of
 *                                  ACTIONS); empty = all actions allowed.
 */

const ACTIONS = [
    { key: 'delete',  label: 'Delete message',  icon: '🗑️' },
    { key: 'warn',    label: 'Warn member',     icon: '⚠️' },
    { key: 'timeout', label: 'Timeout (mute)',  icon: '🔇' },
    { key: 'kick',    label: 'Kick',            icon: '👢' },
    { key: 'ban',     label: 'Ban',             icon: '🔨' },
];
const ACTION_KEYS = ACTIONS.map(a => a.key);
const ACTION_BY_KEY = Object.fromEntries(ACTIONS.map(a => [a.key, a]));

const RULES = [
    {
        key: 'blockedWords',
        label: 'Blocked words',
        icon: '🚫',
        category: 'Content',
        description: 'Delete and act on messages containing blocked words or phrases (substring match).',
        params: ['words'],
        actions: [],
    },
    {
        key: 'invites',
        label: 'Discord invites',
        icon: '📨',
        category: 'Content',
        description: 'Detect Discord server invite links (discord.gg/, discord.com/invite/).',
        params: [],
        actions: [],
    },
    {
        key: 'links',
        label: 'All links',
        icon: '🔗',
        category: 'Content',
        description: 'Detect any URL (http/https) in messages.',
        params: [],
        actions: [],
    },
    {
        key: 'mentions',
        label: 'Mass mentions',
        icon: '@',
        category: 'Spam',
        description: 'Act when a message mentions too many users/roles. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'spam',
        label: 'Duplicate / rapid spam',
        icon: '🌀',
        category: 'Spam',
        description: 'Act when a member sends the same message (or N messages) within a short window.',
        params: ['threshold', 'seconds'],
        actions: [],
    },
    {
        key: 'caps',
        label: 'Excessive caps',
        icon: '🔠',
        category: 'Content',
        description: 'Act when a message is mostly uppercase letters. Threshold is the % of caps.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'emojiSpam',
        label: 'Emoji spam',
        icon: '🎉',
        category: 'Content',
        description: 'Act when a message contains too many emoji. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'newlines',
        label: 'Wall of text / newlines',
        icon: '↩️',
        category: 'Content',
        description: 'Act when a message has too many line breaks. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'zalgo',
        label: 'Zalgo / glitch text',
        icon: '͓z̷',
        category: 'Content',
        description: 'Detect unicode combining characters used for glitchy text spam.',
        params: [],
        actions: [],
    },
];

const RULE_KEYS = RULES.map(r => r.key);
const RULE_BY_KEY = Object.fromEntries(RULES.map(r => [r.key, r]));

/** Default rule set when automod is enabled without specifying rules. */
const DEFAULT_RULES = [
    { type: 'invites', enabled: true, action: 'delete' },
    { type: 'spam', enabled: true, action: 'warn', threshold: 5, seconds: 10 },
    { type: 'mentions', enabled: true, action: 'warn', threshold: 10 },
];

/** Normalize a raw rules array into a clean array of rule objects. */
function normalizeRules(rules) {
    if (!Array.isArray(rules)) return [];
    const seen = new Set();
    const out = [];
    for (const raw of rules) {
        if (!raw || typeof raw !== 'object') continue;
        const type = String(raw.type || '').trim();
        const meta = RULE_BY_KEY[type];
        if (!meta || seen.has(type)) continue;
        seen.add(type);

        const rule = {
            type,
            enabled: raw.enabled !== false,
            action: normalizeAction(raw.action, 'delete'),
        };
        for (const param of meta.params) {
            if (param === 'words') {
                rule.words = Array.isArray(raw.words)
                    ? raw.words.map(w => String(w || '').toLowerCase()).filter(w => w)
                    : [];
            } else {
                const num = Number(raw[param]);
                rule[param] = Number.isFinite(num) && num > 0 ? num : null;
            }
        }
        out.push(rule);
    }
    return out;
}

function normalizeAction(action, fallback = 'delete') {
    const a = String(action || '').trim();
    return ACTION_BY_KEY[a] ? a : fallback;
}

function metaFor(type) {
    return RULE_BY_KEY[type] || { key: type, label: type, icon: '🛡️', category: 'Other', description: '', params: [], actions: [] };
}

/**
 * Pure, dependency-free rule matcher. Tests a single normalized rule against a
 * message context ({ content, guildId, userId, channelId }). The `spamState`
 * argument is a Map the caller owns (keyed by `guildId|userId`); the spam rule
 * reads/writes it to track recent messages within the rule's window. Returning
 * it here keeps the matcher pure w.r.t. everything except that one Map.
 *
 * Returns { reason } on match, or null. Excludes the spam stateful rule's
 * cleanup; the caller prunes old entries periodically.
 */
function matchRule(rule, ctx, spamState = new Map()) {
    if (!rule || rule.enabled === false) return null;
    const content = ctx.content || '';
    const type = rule.type;

    switch (type) {
        case 'blockedWords': {
            if (!Array.isArray(rule.words) || rule.words.length === 0) return null;
            const lower = content.toLowerCase();
            const hit = rule.words.find(w => w && lower.includes(w));
            return hit ? { reason: `Blocked word: \`${hit}\`` } : null;
        }
        case 'invites': {
            const m = content.match(/(https?:\/\/)?(www\.)?(discord\.gg|discord(?:app)?\.com\/invite)\/[a-z0-9-]+/i);
            return m ? { reason: `Discord invite link: \`${m[0]}\`` } : null;
        }
        case 'links': {
            const m = content.match(/https?:\/\/\S+/i);
            return m ? { reason: `Link: \`${m[0]}\`` } : null;
        }
        case 'mentions': {
            const threshold = rule.threshold || 5;
            const count = (content.match(/<@!?\d+>/g) || []).length + (content.match(/<@&\d+>/g) || []).length;
            return count >= threshold ? { reason: `Mass mentions (${count}/${threshold})` } : null;
        }
        case 'spam': {
            const threshold = rule.threshold || 5;
            const seconds = rule.seconds || 10;
            const key = `${ctx.guildId}|${ctx.userId}`;
            const now = Date.now();
            let arr = spamState.get(key) || [];
            arr = arr.filter(e => now - e.ts < seconds * 1000);
            arr.push({ content, ts: now });
            if (arr.length > 50) arr = arr.slice(-50);
            spamState.set(key, arr);
            const dupes = arr.filter(e => e.content === content).length;
            if (arr.length >= threshold || dupes >= threshold) {
                return { reason: `Spam (${arr.length} messages/${seconds}s)` };
            }
            return null;
        }
        case 'caps': {
            const threshold = rule.threshold || 70;
            const letters = content.replace(/[^a-zA-Z]/g, '');
            if (letters.length < 8) return null;
            const caps = content.replace(/[^A-Z]/g, '').length;
            const pct = Math.round((caps / letters.length) * 100);
            return pct >= threshold ? { reason: `Excessive caps (${pct}%)` } : null;
        }
        case 'emojiSpam': {
            const threshold = rule.threshold || 10;
            const count = (content.match(/<a?:\w+:\d+>/g) || []).length +
                (content.match(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F02F}]/gu) || []).length;
            return count >= threshold ? { reason: `Emoji spam (${count})` } : null;
        }
        case 'newlines': {
            const threshold = rule.threshold || 10;
            const count = (content.match(/\n/g) || []).length + 1;
            return count >= threshold ? { reason: `Wall of text (${count} lines)` } : null;
        }
        case 'zalgo': {
            const count = (content.match(/[\u0300-\u036f\u1ab0-\u1aff\u20d0-\u20ff\ufe00-\ufe0f]/g) || []).length;
            return count >= 5 ? { reason: `Zalgo / glitch text (${count} combining marks)` } : null;
        }
        default:
            return null;
    }
}

module.exports = {
    ACTIONS,
    ACTION_KEYS,
    ACTION_BY_KEY,
    RULES,
    RULE_KEYS,
    RULE_BY_KEY,
    DEFAULT_RULES,
    normalizeRules,
    normalizeAction,
    metaFor,
    matchRule,
};
