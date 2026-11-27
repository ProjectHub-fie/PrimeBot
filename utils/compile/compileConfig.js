/**
 * Code Compile configuration, resolved from the environment.
 *
 * `JUDGE0_API_URL` defaults to the public Judge0 CE instance, which needs no
 * API key and no extra hosting. Point it at a self-hosted Judge0 (or any
 * compatible endpoint) to change providers without touching the commands.
 */

const { DEFAULT_LIMITS } = require('./limits');

const DEFAULT_API_URL = 'https://ce.judge0.com';

const DEFAULTS = Object.freeze({
    requestTimeoutMs: 15000,
    pollIntervalMs: 900,
    pollDeadlineMs: 30000,
    languageCacheTtlMs: 6 * 60 * 60 * 1000,
    cooldownMs: 10000,
    userConcurrent: 1,
    guildConcurrent: 3,
    userRateLimit: 6,
    guildRateLimit: 20,
    rateWindowMs: 60000,
});

function intEnv(value, fallback) {
    const parsed = parseInt(value, 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

/** Normalise the base URL: require http(s), drop a trailing slash. */
function normalizeBaseUrl(value) {
    const raw = String(value == null ? '' : value).trim();
    if (!raw) return DEFAULT_API_URL;
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    try {
        const url = new URL(withScheme);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') return DEFAULT_API_URL;
        return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
    } catch (_) {
        return DEFAULT_API_URL;
    }
}

function getCompileConfig(overrides = {}) {
    const env = process.env;
    const resolved = {
        apiUrl: normalizeBaseUrl(overrides.apiUrl || env.JUDGE0_API_URL || DEFAULT_API_URL),
        requestTimeoutMs: intEnv(overrides.requestTimeoutMs ?? env.JUDGE0_REQUEST_TIMEOUT_MS, DEFAULTS.requestTimeoutMs),
        pollIntervalMs: intEnv(overrides.pollIntervalMs ?? env.JUDGE0_POLL_INTERVAL_MS, DEFAULTS.pollIntervalMs),
        pollDeadlineMs: intEnv(overrides.pollDeadlineMs ?? env.JUDGE0_POLL_DEADLINE_MS, DEFAULTS.pollDeadlineMs),
        languageCacheTtlMs: intEnv(overrides.languageCacheTtlMs ?? env.JUDGE0_LANGUAGE_CACHE_TTL_MS, DEFAULTS.languageCacheTtlMs),
        cooldownMs: intEnv(overrides.cooldownMs ?? env.COMPILE_COOLDOWN_MS, DEFAULTS.cooldownMs),
        userConcurrent: intEnv(overrides.userConcurrent ?? env.COMPILE_MAX_CONCURRENT_USER, DEFAULTS.userConcurrent),
        guildConcurrent: intEnv(overrides.guildConcurrent ?? env.COMPILE_MAX_CONCURRENT_GUILD, DEFAULTS.guildConcurrent),
        userRateLimit: intEnv(overrides.userRateLimit ?? env.COMPILE_RATE_LIMIT_USER, DEFAULTS.userRateLimit),
        guildRateLimit: intEnv(overrides.guildRateLimit ?? env.COMPILE_RATE_LIMIT_GUILD, DEFAULTS.guildRateLimit),
        rateWindowMs: intEnv(overrides.rateWindowMs ?? env.COMPILE_RATE_WINDOW_MS, DEFAULTS.rateWindowMs),
        maxCodeBytes: DEFAULT_LIMITS.maxCodeBytes,
        maxStdinBytes: DEFAULT_LIMITS.maxStdinBytes,
        maxOutputBytes: DEFAULT_LIMITS.maxOutputBytes,
        maxSectionChars: DEFAULT_LIMITS.maxSectionChars,
    };
    // A zero poll interval would spin; clamp to a sane minimum.
    if (resolved.pollIntervalMs < 100) resolved.pollIntervalMs = DEFAULTS.pollIntervalMs;
    return resolved;
}

module.exports = {
    DEFAULT_API_URL,
    DEFAULTS,
    getCompileConfig,
    normalizeBaseUrl,
};
