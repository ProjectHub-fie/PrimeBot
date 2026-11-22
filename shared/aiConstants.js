/**
 * AI Assistant shared constants + normalizers.
 *
 * Imported by the bot (manager/commands) and the dashboard (render/API), so the
 * two sides can never drift on defaults, limits or allowed values. No secrets
 * live here — provider keys are read only from the environment by the bot.
 */

const AI_LIMITS = {
    maxPromptChars: 6000,
    maxResponseChars: 2000,
    maxKnowledgeEntries: 50,
    maxKnowledgeTitle: 120,
    maxKnowledgeContent: 2000,
    maxInstructions: 1500,
    maxSessionsListed: 50,
    contextMessages: 12,
    contextChars: 12000,
    sessionTtlMinutes: { min: 5, max: 1440, default: 60 },
    cooldownSeconds: { min: 0, max: 300, default: 5 },
    dailyUserRequests: { min: 1, max: 1000, default: 60 },
    dailyGuildRequests: { min: 10, max: 5000, default: 600 },
    maxResponseCharsSetting: { min: 200, max: 2000, default: 1800 },
};

const AI_MODES = [
    { key: 'mention', label: 'Mention & reply only', description: 'Responds only when mentioned or when replying to the bot.' },
    { key: 'auto', label: 'Automatic in allowed channels', description: 'Also answers ordinary messages in the allowed channels.' },
];

const AI_PERSONALITIES = [
    { key: 'balanced', label: 'Balanced', prompt: 'You are PrimeBot, a friendly and knowledgeable Discord assistant. Be clear, concise and helpful.' },
    { key: 'friendly', label: 'Friendly', prompt: 'You are PrimeBot, a warm and encouraging Discord assistant. Be upbeat, kind and concise.' },
    { key: 'professional', label: 'Professional', prompt: 'You are PrimeBot, a professional Discord assistant. Be precise, structured and neutral.' },
    { key: 'gamer', label: 'Gamer', prompt: 'You are PrimeBot, a gamer-friendly Discord assistant. Use light gaming slang but stay clear and helpful.' },
    { key: 'teacher', label: 'Teacher', prompt: 'You are PrimeBot, a patient teacher. Explain step by step with short examples.' },
    { key: 'coder', label: 'Coder', prompt: 'You are PrimeBot, a senior software engineer. Prefer correct, runnable code and explain the reasoning briefly.' },
    { key: 'custom', label: 'Custom', prompt: '' },
];

const AI_LANGUAGES = [
    { key: 'auto', label: 'Auto (match the user)' },
    { key: 'en', label: 'English' },
    { key: 'es', label: 'Spanish' },
    { key: 'fr', label: 'French' },
    { key: 'de', label: 'German' },
    { key: 'pt', label: 'Portuguese' },
    { key: 'it', label: 'Italian' },
    { key: 'hi', label: 'Hindi' },
    { key: 'ja', label: 'Japanese' },
    { key: 'ko', label: 'Korean' },
    { key: 'zh', label: 'Chinese' },
    { key: 'ru', label: 'Russian' },
    { key: 'ar', label: 'Arabic' },
];

const DEFAULT_AI_SETTINGS = {
    enabled: true,
    mode: 'mention',
    channelIds: [],
    roleIds: [],
    personality: 'balanced',
    customInstructions: '',
    language: 'auto',
    maxResponseChars: AI_LIMITS.maxResponseCharsSetting.default,
    sessionTtlMinutes: AI_LIMITS.sessionTtlMinutes.default,
    cooldownSeconds: AI_LIMITS.cooldownSeconds.default,
    dailyUserRequests: AI_LIMITS.dailyUserRequests.default,
    dailyGuildRequests: AI_LIMITS.dailyGuildRequests.default,
    knowledgeEnabled: true,
    visionEnabled: true,
    allowAttachments: true,
};

function clampInt(value, { min, max, default: fallback }) {
    const n = parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

function idList(value, limit = 50) {
    if (!Array.isArray(value)) return [];
    return Array.from(new Set(value.map(String).filter(id => /^\d{15,22}$/.test(id)))).slice(0, limit);
}

function personalityPrompt(key) {
    const found = AI_PERSONALITIES.find(p => p.key === key);
    return found ? found.prompt : AI_PERSONALITIES[0].prompt;
}

/** Validate + clamp an incoming settings patch (never trust client input). */
function normalizeAiSettings(raw = {}, base = DEFAULT_AI_SETTINGS) {
    const src = raw && typeof raw === 'object' ? raw : {};
    const next = { ...DEFAULT_AI_SETTINGS, ...base };
    const bool = (v, fallback) => (typeof v === 'boolean' ? v : fallback);

    next.enabled = bool(src.enabled, next.enabled);
    if (typeof src.mode === 'string' && AI_MODES.some(m => m.key === src.mode)) next.mode = src.mode;
    if (Array.isArray(src.channelIds)) next.channelIds = idList(src.channelIds);
    if (Array.isArray(src.roleIds)) next.roleIds = idList(src.roleIds);
    if (typeof src.personality === 'string' && AI_PERSONALITIES.some(p => p.key === src.personality)) next.personality = src.personality;
    if (typeof src.customInstructions === 'string') next.customInstructions = src.customInstructions.trim().slice(0, AI_LIMITS.maxInstructions);
    if (typeof src.language === 'string' && AI_LANGUAGES.some(l => l.key === src.language)) next.language = src.language;
    next.maxResponseChars = clampInt(src.maxResponseChars ?? next.maxResponseChars, AI_LIMITS.maxResponseCharsSetting);
    next.sessionTtlMinutes = clampInt(src.sessionTtlMinutes ?? next.sessionTtlMinutes, AI_LIMITS.sessionTtlMinutes);
    next.cooldownSeconds = clampInt(src.cooldownSeconds ?? next.cooldownSeconds, AI_LIMITS.cooldownSeconds);
    next.dailyUserRequests = clampInt(src.dailyUserRequests ?? next.dailyUserRequests, AI_LIMITS.dailyUserRequests);
    next.dailyGuildRequests = clampInt(src.dailyGuildRequests ?? next.dailyGuildRequests, AI_LIMITS.dailyGuildRequests);
    next.knowledgeEnabled = bool(src.knowledgeEnabled, next.knowledgeEnabled);
    next.visionEnabled = bool(src.visionEnabled, next.visionEnabled);
    next.allowAttachments = bool(src.allowAttachments, next.allowAttachments);
    return next;
}

/** Channel/role gate. An empty channel list means "any channel". */
function aiChannelAllowed(settings, channelId) {
    if (!settings) return false;
    if (!Array.isArray(settings.channelIds) || settings.channelIds.length === 0) return true;
    return settings.channelIds.map(String).includes(String(channelId));
}

function aiRoleAllowed(settings, member) {
    if (!settings || !Array.isArray(settings.roleIds) || settings.roleIds.length === 0) return true;
    if (!member) return false;
    if (member.permissions?.has?.('ManageGuild')) return true;
    return settings.roleIds.map(String).some(id => member.roles?.cache?.has?.(id));
}

module.exports = {
    AI_LIMITS,
    AI_MODES,
    AI_PERSONALITIES,
    AI_LANGUAGES,
    DEFAULT_AI_SETTINGS,
    normalizeAiSettings,
    personalityPrompt,
    aiChannelAllowed,
    aiRoleAllowed,
};
