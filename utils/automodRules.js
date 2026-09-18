/**
 * Canonical Automod rule catalog + detection engine.
 *
 * Single source of truth for the rule types PrimeBot Automod understands, their
 * labels, icons, categories, severity, the parameters each rule accepts and the
 * actions they can take. Shared by the bot (utils/automodManager.js), the
 * dashboard (constants + UI) and tests so they all agree on what a rule looks
 * like.
 *
 * Adding a new rule type is a one-line change here plus the matching logic in
 * matchRule(). Everything ships free — PrimeBot's motto is "premium features in
 * free".
 */

/**
 * @typedef {Object} RuleMeta
 * @property {string} key        - Stable identifier stored in rule.type.
 * @property {string} label      - Human label shown in the dashboard.
 * @property {string} icon       - Emoji prefix for the bot's Discord embeds.
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
    { key: 'delete',  label: 'Delete message',  icon: '🗑️', iconName: 'trash',         severity: 'low' },
    { key: 'warn',    label: 'Warn member',     icon: '⚠️', iconName: 'alertTriangle', severity: 'low' },
    { key: 'timeout', label: 'Timeout (mute)',  icon: '🔇', iconName: 'mute',          severity: 'medium' },
    { key: 'kick',    label: 'Kick',            icon: '👢', iconName: 'userX',         severity: 'high' },
    { key: 'ban',     label: 'Ban',             icon: '🔨', iconName: 'ban',           severity: 'critical' },
    { key: 'log',     label: 'Log incident',    icon: '📜', iconName: 'scroll',        severity: 'low' },
];
const ACTION_KEYS = ACTIONS.map(a => a.key);
const ACTION_BY_KEY = Object.fromEntries(ACTIONS.map(a => [a.key, a]));

// Severity levels. Severity is a *presentation/notification* signal — it never
// triggers a punishment on its own (that is always the configured actions).
// `color` is the integer Discord embed color; `colorHex` is the same value as a
// CSS hex string so the dashboard's charts/badges can use the exact same palette.
const SEVERITIES = [
    { key: 'low',      label: 'Low',      color: 0x57F287, colorHex: '#57F287', iconName: 'info' },
    { key: 'medium',   label: 'Medium',   color: 0xFEE75C, colorHex: '#FEE75C', iconName: 'alertTriangle' },
    { key: 'high',     label: 'High',     color: 0xED8A5C, colorHex: '#ED8A5C', iconName: 'shieldAlert' },
    { key: 'critical', label: 'Critical', color: 0xED4245, colorHex: '#ED4245', iconName: 'octagonX' },
];
const SEVERITY_KEYS = SEVERITIES.map(s => s.key);
const SEVERITY_BY_KEY = Object.fromEntries(SEVERITIES.map(s => [s.key, s]));

const RULES = [
    // ── Content ────────────────────────────────────────────────────────────
    {
        key: 'blockedWords',
        label: 'Blocked words',
        icon: '🚫',
        iconName: 'ban',
        category: 'Content Protection',
        severity: 'medium',
        description: 'Delete and act on messages containing blocked words or phrases. Matching is case-insensitive and defeats common obfuscation (b.a.d, b-a-d, b a d, b4d).',
        params: ['words', 'partial'],
        actions: [],
    },
    {
        key: 'invites',
        label: 'Discord invites',
        icon: '📨',
        iconName: 'envelope',
        category: 'Content Protection',
        severity: 'medium',
        description: 'Detect Discord server invite links (discord.gg/, discord.com/invite/). Optionally allow your own server invite or a list of permitted invite codes.',
        params: ['allowOwnInvite', 'allowedInvites'],
        actions: [],
    },
    {
        key: 'links',
        label: 'All links',
        icon: '🔗',
        iconName: 'link',
        category: 'Content Protection',
        severity: 'medium',
        description: 'Detect any URL in messages. Add allowed domains to permit trusted sites, or blocked domains to deny specific ones even when links are otherwise allowed.',
        params: ['allowedDomains', 'blockedDomains', 'allowDiscordLinks'],
        actions: [],
    },
    {
        key: 'badLinks',
        label: 'Bad / phishing links',
        icon: '🪝',
        iconName: 'linkOff',
        category: 'Content Protection',
        severity: 'critical',
        description: 'Detect known phishing/scam URLs and impersonation domains (fake discord, steam, nitro gift lures). Add your own domains via the extra-domains field.',
        params: ['words'],
        actions: [],
    },
    {
        key: 'nsfw',
        label: 'NSFW content',
        icon: '🔞',
        iconName: 'eyeOff',
        category: 'Content Protection',
        severity: 'high',
        description: 'Detect common NSFW terms. Add your own terms via the extra-terms field.',
        params: ['words'],
        actions: [],
    },
    {
        key: 'attachments',
        label: 'Unsafe attachments',
        icon: '📎',
        iconName: 'fileText',
        category: 'Content Protection',
        severity: 'high',
        description: 'Act on uploaded files by extension or size. Anything not on the safe-extension list (or above the size cap) is treated as suspicious.',
        params: ['safeExtensions', 'maxSizeMb', 'blockAll'],
        actions: [],
    },
    {
        key: 'caps',
        label: 'Excessive caps',
        icon: '🔠',
        iconName: 'type',
        category: 'Content Protection',
        severity: 'low',
        description: 'Act when a message is mostly uppercase letters. Threshold is the % of caps; messages shorter than the minimum length are ignored.',
        params: ['threshold', 'minLength'],
        actions: [],
    },
    {
        key: 'emojiSpam',
        label: 'Emoji spam',
        icon: '🎉',
        iconName: 'smile',
        category: 'Content Protection',
        severity: 'low',
        description: 'Act when a message contains too many emoji (unicode, custom and animated all count). Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'newlines',
        label: 'Wall of text / newlines',
        icon: '↩️',
        iconName: 'alignLeft',
        category: 'Content Protection',
        severity: 'low',
        description: 'Act when a message has too many line breaks. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'zalgo',
        label: 'Zalgo / glitch text',
        icon: '͓z̷',
        iconName: 'flask',
        category: 'Content Protection',
        severity: 'low',
        description: 'Detect unicode combining characters used for glitchy text spam.',
        params: [],
        actions: [],
    },

    // ── Anti-Spam ──────────────────────────────────────────────────────────
    {
        key: 'spam',
        label: 'Message flooding',
        icon: '🌀',
        iconName: 'activity',
        category: 'Anti-Spam',
        severity: 'medium',
        description: 'Act when a member sends too many messages inside a short window. Threshold is the message count, seconds is the window.',
        params: ['threshold', 'seconds'],
        actions: [],
    },
    {
        key: 'duplicateMessages',
        label: 'Duplicate messages',
        icon: '📑',
        iconName: 'copy',
        category: 'Anti-Spam',
        severity: 'medium',
        description: 'Act when a member repeats the same (or a near-identical) message. Threshold is the repetition count, seconds the window, and similarity the % match required.',
        params: ['threshold', 'seconds', 'similarity'],
        actions: [],
    },
    {
        key: 'repeatedChars',
        label: 'Character spam',
        icon: '🔁',
        iconName: 'repeat',
        category: 'Anti-Spam',
        severity: 'low',
        description: 'Act when a message contains a run of the same character. Threshold is the run length.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'mentions',
        label: 'Mention spam',
        icon: '@',
        iconName: 'at',
        category: 'Anti-Spam',
        severity: 'medium',
        description: 'Act when a message mentions too many users/roles. Threshold is the count.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'massMention',
        label: 'Mass mention / @everyone',
        icon: '📣',
        iconName: 'megaphone',
        category: 'Anti-Spam',
        severity: 'high',
        description: 'Act on @everyone / @here pings and large role mentions. Lets you punish a server-wide ping separately (and more harshly) than ordinary mention spam.',
        params: ['threshold'],
        actions: [],
    },
    {
        key: 'newAccount',
        label: 'New / alt account',
        icon: '🐣',
        iconName: 'userClock',
        category: 'Anti-Spam',
        severity: 'high',
        description: 'Act when the message author\'s account is newer than the configured age (days). Useful against raid/alt raids.',
        params: ['threshold'],
        actions: [],
        needsAuthor: true,
    },

    // ── Raid Protection ────────────────────────────────────────────────────
    {
        key: 'raidJoin',
        label: 'Join burst (raid)',
        icon: '🚨',
        iconName: 'users',
        category: 'Raid Protection',
        severity: 'critical',
        description: 'Act when more than N members join inside a short window. Combine with the minimum-account-age signal to avoid punishing a legitimate growth spurt.',
        params: ['threshold', 'seconds', 'minAccountAgeDays'],
        actions: [],
        needsJoin: true,
    },
    {
        key: 'raidSimilarNames',
        label: 'Similar join names',
        icon: '👥',
        iconName: 'users',
        category: 'Raid Protection',
        severity: 'high',
        description: 'Act when a burst of new members share a near-identical username (e.g. "user1234", "user1235"). Threshold is the number of similar names, seconds the window.',
        params: ['threshold', 'seconds', 'similarity'],
        actions: [],
        needsJoin: true,
    },
];

const RULE_KEYS = RULES.map(r => r.key);
const RULE_BY_KEY = Object.fromEntries(RULES.map(r => [r.key, r]));

/**
 * Every rule parameter the dashboard can render, as data.
 *
 * `params` on a rule lists which of these apply. Both the server-side renderer
 * (dashboard/render/automod-page.js) and the client renderer
 * (dashboard/public/js/automod.js) build their inputs from this catalog, so a
 * new rule parameter is a one-line addition here instead of three edits that
 * can silently drift apart. `type` drives the input kind, `cssClass` is the
 * selector the client reads the value back from, and `valueKey` is the field
 * name written into the rule object.
 */
const RULE_PARAMS = {
    words: {
        type: 'list', cssClass: 'am-words', valueKey: 'words',
        label: 'Words / domains', placeholder: 'comma, separated, values', lowercase: true,
    },
    partial: {
        type: 'switch', cssClass: 'am-partial', valueKey: 'partial',
        label: 'Partial matches (substring)', defaultOn: true,
    },
    allowOwnInvite: {
        type: 'switch', cssClass: 'am-allow-own-invite', valueKey: 'allowOwnInvite',
        label: "Allow this server's own invites", defaultOn: false,
    },
    allowedInvites: {
        type: 'list', cssClass: 'am-allowed-invites', valueKey: 'allowedInvites',
        label: 'Allowed invite codes', placeholder: 'abc123, def456', lowercase: true,
    },
    allowedDomains: {
        type: 'list', cssClass: 'am-allowed-domains', valueKey: 'allowedDomains',
        label: 'Allowed domains', placeholder: 'youtube.com, github.com', lowercase: true,
    },
    blockedDomains: {
        type: 'list', cssClass: 'am-blocked-domains', valueKey: 'blockedDomains',
        label: 'Blocked domains', placeholder: 'example.com', lowercase: true,
    },
    allowDiscordLinks: {
        type: 'switch', cssClass: 'am-allow-discord', valueKey: 'allowDiscordLinks',
        label: 'Always allow Discord links', defaultOn: true,
    },
    safeExtensions: {
        type: 'list', cssClass: 'am-safe-ext', valueKey: 'safeExtensions',
        label: 'Safe extensions (blank = built-in list)', placeholder: 'png, jpg, pdf',
        lowercase: true, stripDot: true,
    },
    maxSizeMb: {
        type: 'number', cssClass: 'am-max-size', valueKey: 'maxSizeMb',
        label: 'Max size (MB)', min: 1, max: 500, placeholder: '—',
    },
    blockAll: {
        type: 'switch', cssClass: 'am-block-all', valueKey: 'blockAll',
        label: 'Block all attachments', defaultOn: false,
    },
    threshold: {
        type: 'number', cssClass: 'am-threshold', valueKey: 'threshold',
        label: 'Threshold', min: 1, max: 100000, placeholder: '—',
        // A couple of rules reuse `threshold` with a domain-specific meaning.
        labelByRule: { newAccount: 'Account age (days)', caps: 'Uppercase %' },
    },
    minLength: {
        type: 'number', cssClass: 'am-min-length', valueKey: 'minLength',
        label: 'Min message length', min: 1, max: 5000, placeholder: '—',
    },
    seconds: {
        type: 'number', cssClass: 'am-seconds', valueKey: 'seconds',
        label: 'Within (seconds)', min: 1, max: 3600, placeholder: '—',
    },
    similarity: {
        type: 'number', cssClass: 'am-similarity', valueKey: 'similarity',
        label: 'Similarity %', min: 1, max: 100, placeholder: '—',
    },
    minAccountAgeDays: {
        type: 'number', cssClass: 'am-min-age', valueKey: 'minAccountAgeDays',
        label: 'Min account age (days)', min: 0, max: 3650, placeholder: '0',
    },
};

/** Param definitions (with the per-rule label override applied) for a rule. */
function ruleParamDefs(type) {
    const meta = RULE_BY_KEY[type];
    if (!meta) return [];
    return (meta.params || [])
        .map(key => {
            const def = RULE_PARAMS[key];
            if (!def) return null;
            return def.labelByRule && def.labelByRule[type]
                ? { ...def, label: def.labelByRule[type] }
                : def;
        })
        .filter(Boolean);
}

/** The value of a rule param, normalized for rendering. */
function ruleParamValue(rule, def) {
    const raw = rule ? rule[def.valueKey] : undefined;
    if (def.type === 'list') {
        const arr = Array.isArray(raw) ? raw : [];
        return arr.map(v => String(v)).join(', ');
    }
    if (def.type === 'switch') {
        return raw === undefined ? def.defaultOn === true : raw === true;
    }
    return raw === undefined || raw === null ? '' : String(raw);
}

// The subset of rules that run on the message path (everything except the two
// join-burst rules, which are driven by guildMemberAdd).
const MESSAGE_RULE_KEYS = RULES.filter(r => !r.needsJoin).map(r => r.key);
const JOIN_RULE_KEYS = RULES.filter(r => r.needsJoin).map(r => r.key);

// Dashboard section grouping (see the Automod page sidebar).
const RULE_CATEGORIES = [
    'Anti-Spam',
    'Content Protection',
    'Raid Protection',
];

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

// Extensions that are safe to upload. Anything else is treated as suspicious by
// the attachments rule (when it is enabled). Lowercased, no leading dot.
const SAFE_EXTENSIONS = [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico', 'avif',
    'mp4', 'webm', 'mov', 'mkv', 'mp3', 'wav', 'ogg', 'flac', 'm4a',
    'pdf', 'txt', 'md', 'csv', 'json', 'xml', 'yml', 'yaml',
    'zip', 'rar', '7z', 'tar', 'gz',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
];
// Extensions that are essentially always dangerous when shared in chat.
const DANGEROUS_EXTENSIONS = [
    'exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'ps1', 'psm1', 'jar', 'hta', 'cpl', 'dll', 'lnk', 'reg',
    'apk', 'app', 'dmg', 'sh', 'run', 'bin', 'iso', 'img',
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

// ── Normalization helpers ────────────────────────────────────────────────────

/** Normalize an actions value (string or array) into de-duplicated action keys. */
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

function normalizeSeverity(sev, fallback = 'medium') {
    const s = String(sev || '').trim().toLowerCase();
    return SEVERITY_BY_KEY[s] ? s : fallback;
}

/** Normalize a list of strings (words / domains / extensions). */
function normalizeStringList(v, { lower = true, stripDot = false } = {}) {
    if (!Array.isArray(v)) {
        if (typeof v === 'string') {
            v = v.split(',');
        } else {
            return [];
        }
    }
    const out = [];
    const seen = new Set();
    for (const raw of v) {
        let s = String(raw == null ? '' : raw).trim();
        if (stripDot) s = s.replace(/^\.+/, '');
        if (lower) s = s.toLowerCase();
        if (!s || seen.has(s)) continue;
        seen.add(s);
        out.push(s);
        if (out.length >= 200) break; // hard cap — keeps the hot path bounded
    }
    return out;
}

function normalizePositiveInt(v, fallback = null, { min = 1, max = 100000 } = {}) {
    const n = Number(v);
    if (!Number.isFinite(n)) return fallback;
    const i = Math.floor(n);
    if (i < min || i > max) return fallback;
    return i;
}

/**
 * Normalize a raw rules array into a clean array of rule objects.
 *
 * Accepts both the current multi-action shape ({ type, enabled, actions, … })
 * and the legacy single-action shape ({ type, action }). Unknown rule types are
 * dropped; duplicate types keep the first occurrence.
 */
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
            severity: normalizeSeverity(raw.severity, meta.severity || 'medium'),
            // Per-rule exemptions (in addition to the guild-wide lists).
            exemptRoleIds: normalizeStringList(raw.exemptRoleIds),
            exemptChannelIds: normalizeStringList(raw.exemptChannelIds),
            exemptUserIds: normalizeStringList(raw.exemptUserIds),
            // Per-rule cooldown (seconds) between enforcement for one member.
            cooldown: normalizePositiveInt(raw.cooldown, 0, { min: 0, max: 86400 }) || 0,
        };
        for (const param of meta.params) {
            switch (param) {
                case 'words':
                    rule.words = normalizeStringList(raw.words);
                    break;
                case 'allowedDomains':
                case 'blockedDomains':
                    rule[param] = normalizeStringList(raw[param], { stripDot: true });
                    break;
                case 'safeExtensions':
                    rule[param] = normalizeStringList(raw[param], { stripDot: true });
                    break;
                case 'allowedInvites':
                    rule[param] = normalizeStringList(raw[param]);
                    break;
                case 'similarity':
                    rule[param] = normalizePositiveInt(raw[param], 80, { min: 40, max: 100 });
                    break;
                case 'minLength':
                    rule[param] = normalizePositiveInt(raw[param], 8, { min: 1, max: 2000 });
                    break;
                case 'maxSizeMb':
                    rule[param] = normalizePositiveInt(raw[param], 25, { min: 1, max: 500 });
                    break;
                case 'minAccountAgeDays':
                    rule[param] = normalizePositiveInt(raw[param], 0, { min: 0, max: 3650 }) ?? 0;
                    break;
                case 'partial':
                case 'allowOwnInvite':
                case 'allowDiscordLinks':
                case 'blockAll':
                    rule[param] = raw[param] !== false;
                    break;
                default: {
                    const num = Number(raw[param]);
                    rule[param] = Number.isFinite(num) && num > 0 ? num : null;
                }
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
    // A `null` fallback means "no default": callers that only want valid actions
    // get an empty array rather than a bogus `[null]` entry (which would look
    // like a configured step with no real action).
    if (out.length) return out;
    return fallback ? [fallback] : [];
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

/**
 * Normalize the warning-escalation ladder. Accepts either the modern ladder
 * shape ([{ count, actions }]) or the legacy flat (warnThreshold + warnActions)
 * pair, and always returns a sorted, de-duplicated, bounded ladder.
 */
function normalizeWarnLadder(ladder, { threshold = 3, warnActions = ['timeout'] } = {}) {
    const out = [];
    const seen = new Set();
    if (Array.isArray(ladder)) {
        for (const step of ladder) {
            if (!step || typeof step !== 'object') continue;
            const count = normalizePositiveInt(step.count, null, { min: 1, max: 100 });
            if (!count || seen.has(count)) continue;
            const actions = normalizeWarnActions(step.actions, null) || [];
            if (actions.length === 0) continue;
            seen.add(count);
            out.push({ count, actions });
        }
    }
    if (out.length === 0) {
        out.push({ count: normalizePositiveInt(threshold, 3, { min: 1, max: 100 }), actions: normalizeWarnActions(warnActions, 'timeout') });
    }
    return out.sort((a, b) => a.count - b.count).slice(0, 20);
}

function normalizeAction(action, fallback = 'delete') {
    const a = String(action || '').trim();
    return ACTION_BY_KEY[a] ? a : fallback;
}

function metaFor(type) {
    return RULE_BY_KEY[type] || {
        key: type, label: type, icon: '🛡️', iconName: 'shield', category: 'Other',
        severity: 'medium', description: '', params: [], actions: [],
    };
}

function severityMeta(sev) {
    return SEVERITY_BY_KEY[normalizeSeverity(sev)] || SEVERITY_BY_KEY.medium;
}

// ── Smart detection (safe, bounded text normalization) ───────────────────────
//
// AutoMod must defeat trivial obfuscation ("b.a.d.w.o.r.d", "b-a-d-w-o-r-d",
// "b a d w o r d", "b4d", full-width characters) without generating false
// positives. We therefore build ONE normalized "folded" variant of the message
// per scan and test word lists against both the raw lowercased text and the
// folded text. The fold is deliberately conservative:
//
//   • NFKC unicode normalization (full-width → ASCII, ligatures, …)
//   • lowercase
//   • strip zero-width / combining marks
//   • collapse leetspeak digits used as letters (0→o, 1→i, 3→e, 4→a, 5→s, 7→t)
//   • remove separators between single characters (dots, dashes, spaces, …)
//
// The fold is only ever used for *matching*, never stored or echoed back, so a
// false positive is at worst one deleted message rather than a corrupted record.
// Callers can disable it per rule (the `partial` toggle is unrelated — it
// controls substring vs whole-word matching).

const ZERO_WIDTH_RE = /[\u200b-\u200f\u2028-\u202f\u2060\ufeff]/g;
const COMBINING_RE = /[\u0300-\u036f\u1ab0-\u1aff\u20d0-\u20ff\ufe00-\ufe0f]/g;

/** Lowercase + unicode-fold a string, without separator stripping. */
function foldText(input) {
    let s = String(input || '');
    try {
        s = s.normalize('NFKC');
    } catch { /* older runtimes — keep the raw string */ }
    s = s.replace(ZERO_WIDTH_RE, '').replace(COMBINING_RE, '');
    s = s.toLowerCase();
    // Leetspeak → letters. Applied after lowercasing so 'B4D' and 'b4d' agree.
    s = s.replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
         .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
         .replace(/8/g, 'b').replace(/9/g, 'g').replace(/@/g, 'a').replace(/\$/g, 's');
    return s;
}

/**
 * Fold a string AND strip the separators used to break up words. Only chains of
 * SINGLE characters separated by a SINGLE separator are joined
 * ("b.a.d.w.o.r.d" → "badword", "b-a-d" → "bad"), so ordinary prose
 * ("hello, world") and multi-letter words ("well-known") are left intact.
 */
function foldAndSqueeze(input) {
    const folded = foldText(input);
    const tokens = folded.match(/[a-z0-9]+|[^a-z0-9]/g);
    if (!tokens) return '';
    const out = [];
    let i = 0;
    while (i < tokens.length) {
        if (/^[a-z0-9]$/.test(tokens[i])) {
            // Consume a chain of single alnum chars joined by single separators.
            let chain = tokens[i];
            let k = i + 1;
            while (k + 1 < tokens.length
                && /^[^a-z0-9]$/.test(tokens[k])
                && /^[a-z0-9]$/.test(tokens[k + 1])) {
                chain += tokens[k + 1];
                k += 2;
            }
            out.push(chain);
            i = k;
            continue;
        }
        out.push(tokens[i]);
        i++;
    }
    return out.join('');
}

/**
 * Build the detection context for a message body: the raw lowercased text, the
 * folded text and the separator-squeezed fold. Exported so tests can assert the
 * normalization without constructing a manager.
 */
function buildDetectionTexts(content) {
    const raw = String(content || '');
    const lower = raw.toLowerCase();
    const folded = foldText(raw);
    const squeezed = foldAndSqueeze(raw);
    return { raw, lower, folded, squeezed };
}

/** Extract hostnames from a message body. */
function extractHosts(content) {
    const urls = String(content || '').match(/https?:\/\/[^\s<>"']+/gi) || [];
    const hosts = [];
    for (const url of urls) {
        const m = url.match(/^https?:\/\/([^/?#]+)/i);
        if (!m) continue;
        const bare = m[1].toLowerCase().replace(/^www\./, '').replace(/:\d+$/, '');
        if (bare) hosts.push(bare);
    }
    // Also catch bare "example.com/path" mentions without a scheme.
    const bare = String(content || '').match(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\/[^\s<>"']*/gi) || [];
    for (const b of bare) {
        const host = b.split('/')[0].toLowerCase().replace(/^www\./, '');
        if (host.includes('.') && !hosts.includes(host)) hosts.push(host);
    }
    return hosts;
}

/** Does `host` equal, or sit under, any of `domains`? */
function hostMatchesAny(host, domains) {
    if (!host || !Array.isArray(domains)) return false;
    return domains.some(d => d && (host === d || host.endsWith('.' + d)));
}

/** Similarity (0-100) between two strings, based on a bounded Levenshtein ratio. */
function similarity(a, b) {
    const s1 = String(a || '');
    const s2 = String(b || '');
    if (!s1 && !s2) return 100;
    if (!s1 || !s2) return 0;
    const max = Math.max(s1.length, s2.length);
    if (max > 512) return s1 === s2 ? 100 : 0; // bounded: never O(n²) on huge inputs
    const prev = new Array(s2.length + 1);
    const cur = new Array(s2.length + 1);
    for (let j = 0; j <= s2.length; j++) prev[j] = j;
    for (let i = 1; i <= s1.length; i++) {
        cur[0] = i;
        for (let j = 1; j <= s2.length; j++) {
            const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
            cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        }
        for (let j = 0; j <= s2.length; j++) prev[j] = cur[j];
    }
    const dist = prev[s2.length];
    return Math.round(((max - dist) / max) * 100);
}

// ── Stateful detection (in-memory, never persisted) ──────────────────────────
//
// Every rule that needs history (flood, duplicate, join burst, similar names,
// per-rule cooldown) keeps it in a Map the CALLER owns and passes in. The
// manager holds those Maps for the lifetime of the process, so no PostgreSQL
// round trip ever happens on the message hot path.

const DETECTION_STATE_TTL_MS = 5 * 60 * 1000; // entries older than this are pruned
const DETECTION_STATE_MAX_KEYS = 20000;       // hard ceiling on tracked keys

function _bucket(state, key) {
    let arr = state.get(key);
    if (!arr) {
        arr = [];
        state.set(key, arr);
    }
    return arr;
}

function _prune(state, key, windowMs) {
    const arr = state.get(key);
    if (!arr) return [];
    const cutoff = Date.now() - Math.max(windowMs, 1000);
    while (arr.length && arr[0].ts < cutoff) arr.shift();
    if (arr.length === 0) state.delete(key);
    return state.get(key) || [];
}

/**
 * Opportunistically drop stale keys so long-running processes never leak. Called
 * at most once per second by the manager (not per message).
 */
function pruneDetectionState(state, { ttlMs = DETECTION_STATE_TTL_MS, maxKeys = DETECTION_STATE_MAX_KEYS } = {}) {
    if (!(state instanceof Map)) return 0;
    const cutoff = Date.now() - ttlMs;
    let removed = 0;
    for (const [key, arr] of state) {
        if (!Array.isArray(arr) || arr.length === 0 || arr[arr.length - 1].ts < cutoff) {
            state.delete(key);
            removed++;
        }
    }
    // Belt and braces: if a guild is being flooded by unique keys, drop the
    // oldest insertions rather than growing without bound.
    if (state.size > maxKeys) {
        const excess = state.size - maxKeys;
        let i = 0;
        for (const key of state.keys()) {
            state.delete(key);
            if (++i >= excess) break;
        }
    }
    return removed;
}

// ── Rule matcher ─────────────────────────────────────────────────────────────

/**
 * Pure, dependency-free rule matcher. Tests a single normalized rule against a
 * message/join context. `state` is an object of Maps the caller owns:
 *
 *   { spam, dupes, joins, names, cooldown }
 *
 * The matcher reads/writes those Maps so it stays pure w.r.t. everything else.
 *
 * Returns `{ reason, severity }` on match, or null.
 */
/**
 * Resolve the Map backing a stateful rule. Accepts either the named-state object
 * `{ spam, dupes, joins, names, cooldown }` (what the bot manager passes) or a
 * bare Map (legacy callers / tests that only exercise one stateful rule).
 */
function _stateMap(state, name) {
    if (state instanceof Map) return state;
    if (state && state[name] instanceof Map) return state[name];
    return new Map();
}

function matchRule(rule, ctx, state = {}) {
    if (!rule || rule.enabled === false) return null;
    const content = ctx.content || '';
    const type = rule.type;

    switch (type) {
        case 'blockedWords': {
            const words = Array.isArray(rule.words) ? rule.words : [];
            if (words.length === 0) return null;
            const { lower, folded, squeezed } = buildDetectionTexts(content);
            const partial = rule.partial !== false;
            for (const w of words) {
                if (!w) continue;
                const fw = foldText(w);
                const sw = foldAndSqueeze(w);
                const haystacks = [lower, folded, squeezed];
                for (const hay of haystacks) {
                    if (!hay) continue;
                    if (partial) {
                        if (hay.includes(fw) || hay.includes(sw)) {
                            return { reason: `Blocked word: \`${w}\``, severity: rule.severity };
                        }
                    } else {
                        // Whole-word match against a word boundary.
                        const re = new RegExp(`(^|[^a-z0-9])${escapeRegex(fw)}([^a-z0-9]|$)`, 'i');
                        if (re.test(hay)) {
                            return { reason: `Blocked word: \`${w}\``, severity: rule.severity };
                        }
                    }
                }
            }
            return null;
        }
        case 'invites': {
            const m = content.match(/(https?:\/\/)?(www\.)?(discord\.gg|discord(?:app)?\.com\/invite)\/[a-z0-9-]+/i);
            if (!m) return null;
            const code = (m[0].match(/\/([a-z0-9-]+)$/i) || [])[1] || '';
            if (rule.allowOwnInvite && ctx.guildInviteCode && code.toLowerCase() === String(ctx.guildInviteCode).toLowerCase()) {
                return null;
            }
            if (Array.isArray(rule.allowedInvites) && rule.allowedInvites.includes(code.toLowerCase())) {
                return null;
            }
            return { reason: `Discord invite link: \`${m[0]}\``, severity: rule.severity };
        }
        case 'links': {
            const urls = content.match(/https?:\/\/[^\s<>"']+/gi) || [];
            if (urls.length === 0) return null;
            const hosts = extractHosts(content);
            // Blocked domains always win — even when the link would otherwise be
            // allowed — so an admin can deny a specific host outright.
            const blocked = Array.isArray(rule.blockedDomains) ? rule.blockedDomains : [];
            for (const h of hosts) {
                if (hostMatchesAny(h, blocked)) {
                    return { reason: `Blocked domain link: \`${h}\``, severity: rule.severity };
                }
            }
            const allowed = Array.isArray(rule.allowedDomains) ? rule.allowedDomains : [];
            for (const url of urls) {
                const host = (url.match(/^https?:\/\/([^/?#]+)/i) || [])[1];
                const bare = String(host || '').toLowerCase().replace(/^www\./, '').replace(/:\d+$/, '');
                if (!bare) continue;
                if (rule.allowDiscordLinks !== false && (bare === 'discord.com' || bare === 'discord.gg' || bare.endsWith('.discord.com') || bare === 'discordapp.com')) {
                    continue;
                }
                if (hostMatchesAny(bare, allowed)) continue;
                return { reason: `Link: \`${url}\``, severity: rule.severity };
            }
            return null;
        }
        case 'badLinks': {
            const urls = content.match(/https?:\/\/[^\s<]+/gi) || [];
            if (urls.length === 0) return null;
            const extra = Array.isArray(rule.words) ? rule.words.map(w => String(w).toLowerCase()).filter(Boolean) : [];
            for (const url of urls) {
                const u = url.toLowerCase();
                const host = (u.match(/^https?:\/\/([^/]+)/) || [])[1] || '';
                const bareHost = host.replace(/^www\./, '').replace(/:\d+$/, '');
                if (BAD_LINK_SAFE_HOSTS.some(s => bareHost === s || bareHost.endsWith('.' + s))) continue;
                const hostLabel = bareHost.split('.')[0] || bareHost;
                const isImpersonation = BAD_LINK_DOMAINS.some(d => bareHost.includes(d) || hostLabel === d) ||
                    extra.some(d => bareHost.includes(d) || hostLabel === d);
                const hasLure = BAD_LINK_LURES.some(l => u.includes(l));
                if (isImpersonation) {
                    return { reason: `Suspicious/impersonation link: \`${url}\``, severity: rule.severity };
                }
                if (hasLure && /disc(o|0)rd|ste(a|4)m|nitr(o|0)|gift|free|claim/i.test(bareHost)) {
                    return { reason: `Suspicious scam link: \`${url}\``, severity: rule.severity };
                }
            }
            return null;
        }
        case 'nsfw': {
            const terms = Array.from(new Set([...NSFW_TERMS, ...(Array.isArray(rule.words) ? rule.words : [])]));
            if (terms.length === 0) return null;
            const { lower, folded, squeezed } = buildDetectionTexts(content);
            const hit = terms.find(t => {
                if (!t) return false;
                const ft = foldText(t);
                return lower.includes(t) || folded.includes(ft) || squeezed.includes(foldAndSqueeze(t));
            });
            return hit ? { reason: `NSFW term: \`${hit.trim()}\``, severity: rule.severity } : null;
        }
        case 'attachments': {
            const files = Array.isArray(ctx.attachments) ? ctx.attachments : [];
            if (files.length === 0) return null;
            const safe = new Set([
                ...SAFE_EXTENSIONS,
                ...(Array.isArray(rule.safeExtensions) ? rule.safeExtensions : []),
            ]);
            const maxBytes = (rule.maxSizeMb || 25) * 1024 * 1024;
            for (const f of files) {
                const name = String((f && f.name) || '');
                const size = Number((f && f.size) || 0);
                const ext = (name.match(/\.([a-z0-9]+)$/i) || [])[1];
                const lower = ext ? ext.toLowerCase() : '';
                if (rule.blockAll === true) {
                    return { reason: `Attachment blocked by policy: \`${name || 'unnamed file'}\``, severity: rule.severity };
                }
                if (lower && DANGEROUS_EXTENSIONS.includes(lower)) {
                    return { reason: `Unsafe attachment type \`.${lower}\``, severity: rule.severity };
                }
                if (size > maxBytes) {
                    return { reason: `Attachment too large (${Math.round(size / 1024 / 1024)}MB > ${rule.maxSizeMb || 25}MB)`, severity: rule.severity };
                }
                if (lower && !safe.has(lower)) {
                    return { reason: `Unrecognised attachment type \`.${lower}\``, severity: rule.severity };
                }
            }
            return null;
        }
        case 'repeatedChars': {
            const threshold = rule.threshold || 12;
            const m = content.match(/(.)\1+/g);
            if (!m) return null;
            const longest = m.reduce((max, run) => Math.max(max, run.length), 0);
            return longest >= threshold ? { reason: `Repeated characters (${longest}x)`, severity: rule.severity } : null;
        }
        case 'newAccount': {
            const days = rule.threshold || 7;
            const created = ctx.authorCreatedAt;
            if (!created) return null;
            const ageMs = Date.now() - (created instanceof Date ? created.getTime() : new Date(created).getTime());
            const ageDays = ageMs / (1000 * 60 * 60 * 24);
            if (Number.isFinite(ageDays) && ageDays >= 0 && ageDays < days) {
                return { reason: `New account (${ageDays.toFixed(1)} days old, < ${days}d)`, severity: rule.severity };
            }
            return null;
        }
        case 'mentions': {
            const threshold = rule.threshold || 5;
            const count = (content.match(/<@!?\d+>/g) || []).length + (content.match(/<@&\d+>/g) || []).length;
            return count >= threshold ? { reason: `Mention spam (${count}/${threshold})`, severity: rule.severity } : null;
        }
        case 'massMention': {
            const threshold = rule.threshold || 5;
            const everyone = /@everyone|@here/.test(content) ||
                /<@&\d+>/.test(content) && (content.match(/<@&\d+>/g) || []).length >= threshold;
            if (!everyone) return null;
            const isEveryone = /@everyone|@here/.test(content);
            return {
                reason: isEveryone ? 'Mass ping (@everyone/@here)' : `Large role mention (${threshold}+ roles)`,
                severity: rule.severity,
            };
        }
        case 'spam': {
            const threshold = rule.threshold || 5;
            const seconds = rule.seconds || 10;
            const store = _stateMap(state, 'spam');
            const key = `${ctx.guildId}|${ctx.channelId}|${ctx.userId}`;
            const now = Date.now();
            let arr = store.get(key) || [];
            arr = arr.filter(e => now - e.ts < seconds * 1000);
            arr.push({ content, ts: now });
            if (arr.length > 100) arr = arr.slice(-100);
            store.set(key, arr);
            if (arr.length >= threshold) {
                return { reason: `Message flooding (${arr.length} messages/${seconds}s)`, severity: rule.severity };
            }
            return null;
        }
        case 'duplicateMessages': {
            const threshold = rule.threshold || 3;
            const seconds = rule.seconds || 15;
            const simThreshold = rule.similarity || 80;
            const store = _stateMap(state, 'dupes');
            const key = `${ctx.guildId}|${ctx.channelId}|${ctx.userId}`;
            const now = Date.now();
            let arr = store.get(key) || [];
            arr = arr.filter(e => now - e.ts < seconds * 1000);
            arr.push({ content, ts: now });
            if (arr.length > 30) arr = arr.slice(-30);
            store.set(key, arr);
            const recent = arr.slice(0, -1); // exclude the message we just pushed
            const dupes = recent.filter(e => similarity(e.content, content) >= simThreshold).length;
            if (dupes + 1 >= threshold) {
                return { reason: `Duplicate messages (${dupes + 1}x in ${seconds}s)`, severity: rule.severity };
            }
            return null;
        }
        case 'caps': {
            const threshold = rule.threshold || 70;
            const minLength = rule.minLength || 8;
            const letters = content.replace(/[^a-zA-Z]/g, '');
            if (letters.length < minLength) return null;
            const caps = content.replace(/[^A-Z]/g, '').length;
            const pct = Math.round((caps / letters.length) * 100);
            return pct >= threshold ? { reason: `Excessive caps (${pct}%)`, severity: rule.severity } : null;
        }
        case 'emojiSpam': {
            const threshold = rule.threshold || 10;
            const count = (content.match(/<a?:\w+:\d+>/g) || []).length +
                (content.match(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F02F}]/gu) || []).length;
            return count >= threshold ? { reason: `Emoji spam (${count})`, severity: rule.severity } : null;
        }
        case 'newlines': {
            const threshold = rule.threshold || 10;
            const count = (content.match(/\n/g) || []).length + 1;
            return count >= threshold ? { reason: `Wall of text (${count} lines)`, severity: rule.severity } : null;
        }
        case 'zalgo': {
            const count = (content.match(/[\u0300-\u036f\u1ab0-\u1aff\u20d0-\u20ff\ufe00-\ufe0f]/g) || []).length;
            return count >= 5 ? { reason: `Zalgo / glitch text (${count} combining marks)`, severity: rule.severity } : null;
        }

        // ── Raid protection (driven by guildMemberAdd, not messages) ────────
        case 'raidJoin': {
            const threshold = rule.threshold || 10;
            const seconds = rule.seconds || 20;
            const store = _stateMap(state, 'joins');
            const key = String(ctx.guildId);
            const now = Date.now();
            let arr = store.get(key) || [];
            arr = arr.filter(e => now - e.ts < seconds * 1000);
            arr.push({ ts: now, accountAgeDays: ctx.accountAgeDays });
            if (arr.length > 200) arr = arr.slice(-200);
            store.set(key, arr);
            if (arr.length < threshold) return null;
            const minAge = rule.minAccountAgeDays || 0;
            // Only escalate when the burst is ALSO suspicious (unless the admin
            // deliberately configured a 0-day minimum, i.e. count joins alone).
            if (minAge > 0) {
                const young = arr.filter(e => Number.isFinite(e.accountAgeDays) && e.accountAgeDays < minAge).length;
                if (young < Math.ceil(threshold / 2)) return null;
                return { reason: `Raid join burst (${arr.length} joins/${seconds}s, ${young} new accounts)`, severity: rule.severity };
            }
            return { reason: `Join burst (${arr.length} joins/${seconds}s)`, severity: rule.severity };
        }
        case 'raidSimilarNames': {
            const threshold = rule.threshold || 5;
            const seconds = rule.seconds || 30;
            const simThreshold = rule.similarity || 80;
            const store = _stateMap(state, 'names');
            const key = String(ctx.guildId);
            const now = Date.now();
            let arr = store.get(key) || [];
            arr = arr.filter(e => now - e.ts < seconds * 1000);
            const username = String(ctx.username || '');
            arr.push({ ts: now, username });
            if (arr.length > 100) arr = arr.slice(-100);
            store.set(key, arr);
            if (arr.length < threshold) return null;
            const similar = arr.filter(e => similarity(e.username, username) >= simThreshold).length;
            if (similar >= threshold) {
                return { reason: `Similar join names (${similar} × "${username}" in ${seconds}s)`, severity: rule.severity };
            }
            return null;
        }
        default:
            return null;
    }
}

function escapeRegex(s) {
    return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── Cooldown helper ──────────────────────────────────────────────────────────

/**
 * Per-rule per-member cooldown. Returns true when the action may run (and
 * records the attempt), false while the cooldown is still active. Keeps the
 * engine from punishing the same member on every single message in a flood.
 */
function checkCooldown(state, key, seconds) {
    const secs = Number(seconds);
    if (!Number.isFinite(secs) || secs <= 0) return true;
    const store = state.cooldown instanceof Map ? state.cooldown : new Map();
    const now = Date.now();
    const until = store.get(key) || 0;
    if (now < until) return false;
    store.set(key, now + secs * 1000);
    return true;
}

/**
 * Exemption evaluation shared by the manager and the rule-test endpoint.
 * `subject` carries the ids of the member/channel/role being evaluated.
 */
function isExemptFromRule(rule, settings, subject = {}) {
    const adminBypass = subject.isAdministrator === true;
    if (adminBypass) return true;
    const { userId, channelId, roleIds = [] } = subject;
    const checks = [
        [settings && settings.exemptUserIds, userId],
        [settings && settings.exemptChannelIds, channelId],
        [rule && rule.exemptUserIds, userId],
        [rule && rule.exemptChannelIds, channelId],
    ];
    for (const [list, value] of checks) {
        if (Array.isArray(list) && value && list.includes(value)) return true;
    }
    const roleLists = [settings && settings.exemptRoleIds, rule && rule.exemptRoleIds];
    for (const list of roleLists) {
        if (Array.isArray(list) && list.length && roleIds.some(r => list.includes(r))) return true;
    }
    return false;
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
    SEVERITIES,
    SEVERITY_KEYS,
    SEVERITY_BY_KEY,
    RULES,
    RULE_KEYS,
    RULE_BY_KEY,
    MESSAGE_RULE_KEYS,
    JOIN_RULE_KEYS,
    RULE_CATEGORIES,
    RULE_PARAMS,
    ruleParamDefs,
    ruleParamValue,
    DEFAULT_RULES,
    DEFAULT_DM_MESSAGES,
    BAD_LINK_DOMAINS,
    BAD_LINK_LURES,
    BAD_LINK_SAFE_HOSTS,
    NSFW_TERMS,
    SAFE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    normalizeRules,
    normalizeAction,
    normalizeActions,
    normalizeWarnActions,
    normalizeWarnLadder,
    normalizeDmMessages,
    normalizeSeverity,
    normalizeStringList,
    metaFor,
    severityMeta,
    matchRule,
    renderDmMessage,
    // Detection helpers (exported for tests + the rule-test endpoint)
    foldText,
    foldAndSqueeze,
    buildDetectionTexts,
    extractHosts,
    hostMatchesAny,
    similarity,
    pruneDetectionState,
    checkCooldown,
    isExemptFromRule,
    escapeRegex,
};
