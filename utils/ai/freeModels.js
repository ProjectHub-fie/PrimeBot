/**
 * Free-only AI provider catalog.
 *
 * Every model listed here is on a provider free tier. The guard is deliberate:
 *  - Groq / Gemini models must be in the explicit allowlist.
 *  - OpenRouter models must be in the allowlist AND end with `:free`.
 * An `AI_MODEL_*` env override that is not free is ignored (the default is
 * used instead), so a misconfiguration can never silently bill a paid model.
 */

const PROVIDER_ORDER = ['groq', 'gemini', 'openrouter'];

const PROVIDERS = {
    groq: {
        key: 'groq',
        label: 'Groq',
        envKey: 'GROQ_API_KEY',
        envModel: 'AI_MODEL_GROQ',
        endpoint: 'https://api.groq.com/openai/v1/chat/completions',
        defaultModel: 'llama-3.3-70b-versatile',
        freeModels: [
            'llama-3.3-70b-versatile',
            'llama-3.1-8b-instant',
            'openai/gpt-oss-120b',
            'openai/gpt-oss-20b',
            'qwen/qwen3-32b',
            'meta-llama/llama-4-scout-17b-16e-instruct',
            'meta-llama/llama-4-maverick-17b-128e-instruct',
        ],
        visionModels: [],
        capabilities: { chat: true, vision: false },
    },
    gemini: {
        key: 'gemini',
        label: 'Google Gemini',
        envKey: 'GEMINI_API_KEY',
        envModel: 'AI_MODEL_GEMINI',
        endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
        defaultModel: 'gemini-2.0-flash',
        freeModels: [
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
            'gemini-2.5-flash',
            'gemini-2.5-flash-lite',
        ],
        visionModels: [
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
            'gemini-2.5-flash',
            'gemini-2.5-flash-lite',
        ],
        capabilities: { chat: true, vision: true },
    },
    openrouter: {
        key: 'openrouter',
        label: 'OpenRouter (free models)',
        envKey: 'OPENROUTER_API_KEY',
        envModel: 'AI_MODEL_OPENROUTER',
        endpoint: 'https://openrouter.ai/api/v1/chat/completions',
        defaultModel: 'meta-llama/llama-3.3-70b-instruct:free',
        requireFreeSuffix: true,
        freeModels: [
            'meta-llama/llama-3.3-70b-instruct:free',
            'meta-llama/llama-3.2-3b-instruct:free',
            'deepseek/deepseek-chat-v3-0324:free',
            'deepseek/deepseek-r1:free',
            'google/gemini-2.0-flash-exp:free',
            'qwen/qwen-2.5-72b-instruct:free',
            'mistralai/mistral-small-3.1-24b-instruct:free',
            'microsoft/phi-4-reasoning:free',
            'meta-llama/llama-3.2-11b-vision-instruct:free',
        ],
        visionModels: [
            'google/gemini-2.0-flash-exp:free',
            'meta-llama/llama-3.2-11b-vision-instruct:free',
            'qwen/qwen2.5-vl-72b-instruct:free',
        ],
        capabilities: { chat: true, vision: true },
    },
};

function providerMeta(provider) {
    return PROVIDERS[provider] || null;
}

/** True only for models on a provider free tier (paid ids are rejected). */
function isFreeModel(provider, model) {
    const meta = providerMeta(provider);
    if (!meta || typeof model !== 'string' || !model.trim()) return false;
    const id = model.trim();
    if (meta.requireFreeSuffix && !id.endsWith(':free')) return false;
    return meta.freeModels.includes(id);
}

/** Env override when it is free, otherwise the provider default. */
function resolveModel(provider) {
    const meta = providerMeta(provider);
    if (!meta) return null;
    const override = process.env[meta.envModel];
    if (override && isFreeModel(provider, override)) return override.trim();
    return meta.defaultModel;
}

function providerConfigured(provider) {
    const meta = providerMeta(provider);
    return Boolean(meta && process.env[meta.envKey]);
}

function configuredProviders() {
    return PROVIDER_ORDER.filter(providerConfigured);
}

function supportsVision(provider, model = resolveModel(provider)) {
    const meta = providerMeta(provider);
    if (!meta || !model) return false;
    return meta.visionModels.includes(model);
}

function supportsChat(provider) {
    const meta = providerMeta(provider);
    return Boolean(meta && meta.capabilities.chat);
}

/** Mask a key for diagnostics: never the full value. */
function maskSecret(value) {
    if (!value) return null;
    const s = String(value);
    return `••••${s.slice(-4)}`;
}

module.exports = {
    PROVIDER_ORDER,
    PROVIDERS,
    providerMeta,
    isFreeModel,
    resolveModel,
    providerConfigured,
    configuredProviders,
    supportsVision,
    supportsChat,
    maskSecret,
};
