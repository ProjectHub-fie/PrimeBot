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
 * @property {string} iconName   - SVG icon name (dashboard/public/js/icons.js)
 *                                 for the dashboard UI chrome. The bot ignores it.
 * @property {string} category   - Grouping for the dashboard UI.
 * @property {string} description
 * @property {string[]} params   - Extra fields this rule accepts beyond the
 *                                  common { enabled, actions } pair.
 * @property {string[]} actions  - Action keys valid for this rule (subset of
 *                                  ACTIONS); empty = all actions allowed.
 * @property {boolean} [needsAuthor] - Rule reads ctx.authorCreatedAt (newAccount).
 */

const ACTIONS = [
    { key: 'delete',  label: 'Delete message',  icon: '🗑️', iconName: 'trash' },
    { key: 'warn',    label: 'Warn member',     icon: '⚠️', iconName: 'alertTriangle' },
    { key: 'timeout', label: 'Timeout (mute)',  icon: '🔇', iconName: 'mute' },
    { key: 'kick',    label: 'Kick',            icon: '👢', iconName: 'userX' },
    { key: 'ban',     label: 'Ban',             icon: '🔨', iconName: 'ban' },
];
const ACTION_KEYS = ACTIONS.map(a => a.key);
const ACTION_BY_KEY = Object.fromEntries(ACTIONS.map(a => [a.key, a]));

const RULES = [
    {
        key: 'blockedWords',
        label: 'Blocked words',
        icon: '🚫',
        iconName: 'ban',
        category: 'Content',
        description: 'Delete and act on messages containing blocked words or phrases (substring match).',
        params: ['words'],
        actions: [],
    },
    {
        key: 'invites',
        label: 'Discord invites',
        icon: '📨',
        iconName: 'envelope',
        category: 'Content',
        description: 'Detect Discord server invite links (discord.gg/, discord.com/invite/).',
        params: [],
        actions: [],
    },
    {
        key: 'links',
        label: 'All links',
        icon: '🔗',
        iconName: 'link',
        category: 'Content',
        description: 'Detect any URL (http/https) in messages.',
        params: [],
        actions: [],
    },
    {
        key: 'badLinks',
        label: 'Bad / phishing links',
        icon: '🪝',
        iconName: 'linkOff',
        category: 'Content',
        description: 'Detect known phishing/scam URLs and impersonation domains (discord, steam, nitro gift lures). Add your own domains via the "words" field.',
        params: ['words'],
        actions: [],
    },
    {
        key: 'nsfw',
        label: 'NSFW content',
        icon: '🔞',
        iconName: 'eyeOff',
        category: 'Content',
        description: 'Detect common NSFW terms. Add your own terms via the "words" field.',
        params: ['words'],
        actions: [],
    },
    {
        key: 'repeatedChars',
        label: 'Repeated characters',
        icon: '🔁',
        iconName: 'repeat',
        category: 'Spam',
        description: 'Act when a message contains a run of the same character. Threshold is the run length.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'newAccount',
        label: 'New / alt account',
        icon: '🐣',
        iconName: 'userClock',
        category: 'Spam',
        description: 'Act when the message author\'s account is newer than the configured age (days). Useful against raid/alt raids.',
        params: ['threshold'],
        actions: [],
        needsAuthor: true,
    },
    {
        key: 'mentions',
        label: 'Mass mentions',
        icon: '@',
        iconName: 'at',
        category: 'Spam',
        description: 'Act when a message mentions too many users/roles. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'spam',
        label: 'Duplicate / rapid spam',
        icon: '🌀',
        iconName: 'activity',
        category: 'Spam',
        description: 'Act when a member sends the same message (or N messages) within a short window.',
        params: ['threshold', 'seconds'],
        actions: [],
    },
    {
        key: 'caps',
        label: 'Excessive caps',
        icon: '🔠',
        iconName: 'type',
        category: 'Content',
        description: 'Act when a message is mostly uppercase letters. Threshold is the % of caps.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'emojiSpam',
        label: 'Emoji spam',
        icon: '🎉',
        iconName: 'smile',
        category: 'Content',
        description: 'Act when a message contains too many emoji. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'newlines',
        label: 'Wall of text / newlines',
        icon: '↩️',
        iconName: 'alignLeft',
        category: 'Content',
        description: 'Act when a message has too many line breaks. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'zalgo',
        label: 'Zalgo / glitch text',
        icon: '͓z̷',
        iconName: 'flask',
        category: 'Content',
        description: 'Detect unicode combining characters used for glitchy text spam.',
        params: [],
        actions: [],
    },
];

const RULE_KEYS = RULES.map(r => r.key);
const RULE_BY_KEY = Object.fromEntries(RULES.map(r => [r.key, r]));

// Known phishing/impersonation domains & lures for the badLinks rule. Kept as a
// small, opinionated starter list; guilds extend it via the rule's `words`.
// Matched against hostnames extracted from links in the message.
const BAD_LINK_DOMAINS = [
    'steampowered', 'steamcommunity', 'steamcommunit', 'stearn', 'stearncorn',
    'discrod', 'disord', 'dicsord', 'discorcl', 'discod', 'dizcord', 'discorc',
    'discord-nitro', 'discordnitro', 'free-nitro', 'freenitro', 'nitro-generator',
    'discordgift', 'discord-gift', 'steamgift', 'freegift', 'gift-discord',
    'discrod-app', 'discordapp', 'discordclaims', 'discord-claim',
];
// Path/keyword lures commonly used in scams (matched against the full URL).
const BAD_LINK_LURES = ['nitro', 'gift', 'free', 'claim', 'generator', 'airdrop', 'promo'];
// Whitelist of safe hosts so legitimate links to the real services are not flagged.
const BAD_LINK_SAFE_HOSTS = [
    'discord.com', 'discordapp.com', 'discord.gg', 'steampowered.com',
    'steamcommunity.com', 'google.com', 'youtube.com', 'youtu.be',
    'github.com', 'twitter.com', 'x.com',
];

// Common NSFW terms for the nsfw rule. Intentionally non-exhaustive starter list;
// guilds extend it via the rule's `words`. Lowercased, word/substring matched.
const NSFW_TERMS = [
    'porn', 'porno', 'pornography', 'xxx', 'nsfw', 'hentai', 'rule34',
    'nude', 'nudes', 'naked', 'brazzers', 'onlyfans', 'camsoda', 'chaturbate',
    'camgirl', 'camsex', 'sexcam', ' hookup', 'escort', 'hooker',
    'dickpic', 'cockpic', 'boobs', 'milf', 'milfs', 'creampie',
    'furryporn', 'femboy', 'transporn', 'gayporn',
];

/** Default rule set when automod is enabled without specifying rules. */
const DEFAULT_RULES = [
    { type: 'invites', enabled: true, actions: ['delete'] },
    { type: 'badLinks', enabled: true, actions: ['delete'] },
    { type: 'spam', enabled: true, actions: ['warn'], threshold: 5, seconds: 10 },
    { type: 'mentions', enabled: true, actions: ['warn'], threshold: 10 },
];

/**
 * Default DM message templates sent to members when an action is taken against
 * them. Placeholders: {server}, {reason}, {action}, {threshold}. A guild can
 * override any of these via settings.dmMessages. DMs are only sent when
 * settings.dmEnabled is true.
 */
const DEFAULT_DM_MESSAGES = {
    delete: 'Your message in **{server}** was removed: {reason}.',
    warn: '⚠️ **Warning** in **{server}**: {reason}. Further warnings may escalate to further punishment.',
    timeout: '🔇 You were timed out in **{server}** for: {reason}.',
    kick: '👢 You were kicked from **{server}** for: {reason}.',
    ban: '🔨 You were banned from **{server}** for: {reason}.',
    escalation: '🚫 You reached the warning threshold in **{server}** and were escalated to **{action}**.',
};

/**
 * Normalize an actions value (string or array) into a de-duplicated array of
 * valid action keys. Accepts a legacy single `action` string for back-compat.
 * An empty result falls back to [fallback].
 */
function normalizeActions(actions, fallback = 'delete') {
    let arr;
    if (Array.isArray(actions)) {
        arr = actions;
    } else if (typeof actions === 'string') {
        arr = [actions];
    } else {
        arr = [];
    }
    const out = [];
    const seen = new Set();
    for (const a of arr) {
        const key = String(a || '').trim();
        if (ACTION_BY_KEY[key] && !seen.has(key)) {
            seen.add(key);
            out.push(key);
        }
    }
    return out.length ? out : [fallback];
}

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

        // Accept either `actions` (array) or legacy `action` (string).
        const actions = normalizeActions(
            Array.isArray(raw.actions) ? raw.actions : (raw.actions ?? raw.action),
            'delete'
        );
        const rule = {
            type,
            enabled: raw.enabled !== false,
            actions,
            action: actions[0],
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

/** Normalize the top-level warn escalation actions (multi-action escalation). */
function normalizeWarnActions(actions, fallback = 'timeout') {
    // Escalation excludes 'delete' (pointless) but allows warn/kick/ban/timeout.
    const allowed = ['warn', 'timeout', 'kick', 'ban'];
    let arr = Array.isArray(actions) ? actions : (typeof actions === 'string' ? [actions] : []);
    const out = [];
    const seen = new Set();
    for (const a of arr) {
        const key = String(a || '').trim();
        if (allowed.includes(key) && !seen.has(key)) {
            seen.add(key);
            out.push(key);
        }
    }
    return out.length ? out : [fallback];
}

/** Normalize the custom DM message overrides object against known action keys. */
function normalizeDmMessages(dm) {
    const out = {};
    if (dm && typeof dm === 'object' && !Array.isArray(dm)) {
        for (const [key, val] of Object.entries(dm)) {
            if (typeof val === 'string' && val.trim()) {
                out[key] = val.slice(0, 1000);
            }
        }
    }
    return out;
}

function normalizeAction(action, fallback = 'delete') {
    const a = String(action || '').trim();
    return ACTION_BY_KEY[a] ? a : fallback;
}

function metaFor(type) {
    return RULE_BY_KEY[type] || { key: type, label: type, icon: '🛡️', iconName: 'shield', category: 'Other', description: '', params: [], actions: [] };
}

/**
 * Pure, dependency-free rule matcher. Tests a single normalized rule against a
 * message context ({ content, guildId, userId, channelId, authorCreatedAt }).
 * The `spamState` argument is a Map the caller owns (keyed by `guildId|userId`);
 * the spam rule reads/writes it to track recent messages within the rule's
 * window. Returning it here keeps the matcher pure w.r.t. everything except
 * that one Map.
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
        case 'badLinks': {
            const urls = content.match(/https?:\/\/[^\s<]+/gi) || [];
            if (urls.length === 0) return null;
            const extra = Array.isArray(rule.words) ? rule.words.map(w => String(w).toLowerCase()).filter(Boolean) : [];
            for (const url of urls) {
                const u = url.toLowerCase();
                const host = (u.match(/^https?:\/\/([^/]+)/) || [])[1] || '';
                // Strip "www." and port for matching.
                const bareHost = host.replace(/^www\./, '').replace(/:\d+$/, '');
                if (BAD_LINK_SAFE_HOSTS.some(s => bareHost === s || bareHost.endsWith('.' + s))) continue;
                const hostLabel = bareHost.split('.')[0] || bareHost;
                const isImpersonation = BAD_LINK_DOMAINS.some(d => bareHost.includes(d) || hostLabel === d) ||
                    extra.some(d => bareHost.includes(d) || hostLabel === d);
                const hasLure = BAD_LINK_LURES.some(l => u.includes(l));
                if (isImpersonation) {
                    return { reason: `Suspicious/impersonation link: \`${url}\`` };
                }
                if (hasLure && /disc(o|0)rd|ste(a|4)m|nitr(o|0)|gift|free|claim/i.test(bareHost)) {
                    return { reason: `Suspicious scam link: \`${url}\`` };
                }
            }
            return null;
        }
        case 'nsfw': {
            const terms = Array.from(new Set([...NSFW_TERMS, ...(Array.isArray(rule.words) ? rule.words : [])]));
            if (terms.length === 0) return null;
            const lower = content.toLowerCase();
            const hit = terms.find(t => t && lower.includes(t));
            return hit ? { reason: `NSFW term: \`${hit.trim()}\`` } : null;
        }
        case 'repeatedChars': {
            const threshold = rule.threshold || 12;
            const m = content.match(/(.)\1+/g);
            if (!m) return null;
            const longest = m.reduce((max, run) => Math.max(max, run.length), 0);
            return longest >= threshold ? { reason: `Repeated characters (${longest}x)` } : null;
        }
        case 'newAccount': {
            const days = rule.threshold || 7;
            const created = ctx.authorCreatedAt;
            if (!created) return null;
            const ageMs = Date.now() - (created instanceof Date ? created.getTime() : new Date(created).getTime());
            const ageDays = ageMs / (1000 * 60 * 60 * 24);
            if (Number.isFinite(ageDays) && ageDays >= 0 && ageDays < days) {
                return { reason: `New account (${ageDays.toFixed(1)} days old, < ${days}d)` };
            }
            return null;
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

/**
 * Render a DM message template, substituting placeholders with the provided
 * values. Falls back to the default template for the action key if the custom
 * override is empty/missing.
 *
 * Placeholders: {server}, {reason}, {action}, {threshold}.
 */
function renderDmMessage(action, { server = '', reason = '', actionLabel = '', threshold = '' } = {}, overrides = {}) {
    const tmpl = (overrides && typeof overrides[action] === 'string' && overrides[action].trim())
        ? overrides[action]
        : (DEFAULT_DM_MESSAGES[action] || 'You were actioned in **{server}**: {reason}.');
    return String(tmpl)
        .replaceAll('{server}', server)
        .replaceAll('{reason}', reason)
        .replaceAll('{action}', actionLabel)
        .replaceAll('{threshold}', String(threshold))
        .slice(0, 2000);
}

module.exports = {
    ACTIONS,
    ACTION_KEYS,
    ACTION_BY_KEY,
    RULES,
    RULE_KEYS,
    RULE_BY_KEY,
    DEFAULT_RULES,
    DEFAULT_DM_MESSAGES,
    BAD_LINK_DOMAINS,
    BAD_LINK_LURES,
    BAD_LINK_SAFE_HOSTS,
    NSFW_TERMS,
    normalizeRules,
    normalizeAction,
    normalizeActions,
    normalizeWarnActions,
    normalizeDmMessages,
    metaFor,
    matchRule,
    renderDmMessage,
};
