/**
 * Free-only AI provider catalog.
 *
 * Two layers keep a model choice honest:
 *  1. the static lists below (last-known free models + preference order), and
 *  2. `modelCatalog.js`, which asks each provider for its live model list and
 *     picks a model that actually exists for the configured key.
 *
 * A model is never assumed to exist just because it is listed here: the
 * provider's own `/models` response is authoritative. An `AI_MODEL_*` override
 * is honoured only when it is a free model the provider reports.
 */

const PROVIDER_ORDER = ['groq', 'gemini', 'openrouter'];

// Accepted env-var names per provider (first non-empty wins).
const ENV_KEY_ALIASES = {
    groq: ['GROQ_API_KEY', 'GROQ_KEY', 'GROQ_API_TOKEN'],
    gemini: ['GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_GENAI_API_KEY', 'GEMINI_KEY'],
    openrouter: ['OPENROUTER_API_KEY', 'OPENROUTER_KEY', 'OPEN_ROUTER_API_KEY', 'OPENROUTER_API_TOKEN'],
};

const PROVIDERS = {
    groq: {
        key: 'groq',
        label: 'Groq',
        envKey: 'GROQ_API_KEY',
        envModel: 'AI_MODEL_GROQ',
        modelsEndpoint: 'https://api.groq.com/openai/v1/models',
        endpoint: 'https://api.groq.com/openai/v1/chat/completions',
        // `llama-3.3-70b-versatile` was retired for new Groq orgs; gpt-oss-120b
        // is the current generally-available free chat model.
        defaultModel: 'openai/gpt-oss-120b',
        preferredModels: [
            'openai/gpt-oss-120b',
            'openai/gpt-oss-20b',
            'llama-3.1-8b-instant',
            'qwen/qwen3.8-27b',
            'qwen/qwen3-32b',
            'moonshotai/kimi-k2-instruct',
            'meta-llama/llama-4-scout-17b-16e-instruct',
            'meta-llama/llama-4-maverick-17b-128e-instruct',
            'llama-3.3-70b-versatile',
        ],
        freeModels: [
            'openai/gpt-oss-120b',
            'openai/gpt-oss-20b',
            'llama-3.1-8b-instant',
            'qwen/qwen3.8-27b',
            'qwen/qwen3-32b',
            'moonshotai/kimi-k2-instruct',
            'meta-llama/llama-4-scout-17b-16e-instruct',
            'meta-llama/llama-4-maverick-17b-128e-instruct',
            'llama-3.3-70b-versatile',
            'gemma2-9b-it',
        ],
        visionModels: [
            'meta-llama/llama-4-scout-17b-16e-instruct',
            'meta-llama/llama-4-maverick-17b-128e-instruct',
        ],
        capabilities: { chat: true, vision: false },
    },
    gemini: {
        key: 'gemini',
        label: 'Google Gemini',
        envKey: 'GEMINI_API_KEY',
        envModel: 'AI_MODEL_GEMINI',
        modelsEndpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
        endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
        // `gemini-2.0-flash` was retired; 2.5-flash is the long-lived free model.
        defaultModel: 'gemini-2.5-flash',
        preferredModels: [
            'gemini-2.5-flash',
            'gemini-2.5-flash-lite',
            'gemini-3.8-flash',
            'gemini-3.5-flash-lite',
            'gemini-3-flash-preview',
            'gemini-3.1-flash-lite',
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
        ],
        freeModels: [
            'gemini-2.5-flash',
            'gemini-2.5-flash-lite',
            'gemini-3.8-flash',
            'gemini-3.5-flash-lite',
            'gemini-3-flash-preview',
            'gemini-3.1-flash-lite',
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
        ],
        visionModels: [
            'gemini-2.5-flash',
            'gemini-2.5-flash-lite',
            'gemini-3.8-flash',
            'gemini-3.5-flash-lite',
            'gemini-3-flash-preview',
            'gemini-3.1-flash-lite',
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
        ],
        capabilities: { chat: true, vision: true },
    },
    openrouter: {
        key: 'openrouter',
        label: 'OpenRouter (free models)',
        envKey: 'OPENROUTER_API_KEY',
        envModel: 'AI_MODEL_OPENROUTER',
        modelsEndpoint: 'https://openrouter.ai/api/v1/models',
        endpoint: 'https://openrouter.ai/api/v1/chat/completions',
        defaultModel: 'google/gemma-4-31b-it:free',
        // Free models are discovered from pricing (prompt + completion = 0).
        preferredModels: [
            'google/gemma-4-31b-it:free',
            'inclusionai/ling-3.2-flash:free',
            'nvidia/nemotron-3.5-super-vl:free',
            'nvidia/nemotron-3.5-lightning:free',
            'dots-studio/dots-3-note-preview:free',
            'baidu/ernie-5.5-flash-preview:free',
            'meta-llama/llama-3.3-70b-instruct:free',
            'deepseek/deepseek-chat-v3-0324:free',
            'qwen/qwen-2.5-72b-instruct:free',
            'meta-llama/llama-3.2-3b-instruct:free',
        ],
        freeModels: [
            'google/gemma-4-31b-it:free',
            'inclusionai/ling-3.2-flash:free',
            'nvidia/nemotron-3.5-super-vl:free',
            'nvidia/nemotron-3.5-lightning:free',
            'dots-studio/dots-3-note-preview:free',
            'baidu/ernie-5.5-flash-preview:free',
            'meta-llama/llama-3.3-70b-instruct:free',
            'deepseek/deepseek-chat-v3-0324:free',
            'qwen/qwen-2.5-72b-instruct:free',
            'meta-llama/llama-3.2-3b-instruct:free',
            'google/gemini-2.0-flash-exp:free',
            'meta-llama/llama-3.2-11b-vision-instruct:free',
            'qwen/qwen2.5-vl-72b-instruct:free',
        ],
        requireFreeSuffix: true,
        visionModels: [
            'nvidia/nemotron-3.5-super-vl:free',
            'dots-studio/dots-3-note-preview:free',
            'meta-llama/llama-3.2-11b-vision-instruct:free',
            'qwen/qwen2.5-vl-72b-instruct:free',
            'google/gemini-2.0-flash-exp:free',
        ],
        capabilities: { chat: true, vision: true },
    },
};

function providerMeta(provider) {
    return PROVIDERS[provider] || null;
}

function cleanEnvValue(value) {
    if (value == null) return null;
    const s = String(value).trim().replace(/^["']|["']$/g, '').trim();
    return s || null;
}

/** Placeholder/blank values are treated as "not configured" (never sent). */
function isPlaceholderKey(value) {
    const s = cleanEnvValue(value);
    if (!s) return true;
    if (s.length < 10) return true;
    if (/[<>]/.test(s)) return true;
    return /^(your|changeme|change-me|placeholder|example|none|null|undefined|todo|test|dummy)/i.test(s);
}

/** Resolve a provider key from the first non-placeholder env alias. */
function readProviderKey(provider) {
    const aliases = ENV_KEY_ALIASES[provider] || [];
    for (const name of aliases) {
        const value = cleanEnvValue(process.env[name]);
        if (value && !isPlaceholderKey(value)) return value;
    }
    return null;
}

/** Which env var supplied the key (for diagnostics; never the value). */
function keySource(provider) {
    const aliases = ENV_KEY_ALIASES[provider] || [];
    for (const name of aliases) {
        const value = cleanEnvValue(process.env[name]);
        if (value && !isPlaceholderKey(value)) return name;
    }
    return null;
}

/** True only for models on a provider free tier (paid ids are rejected). */
function isFreeModel(provider, model) {
    const meta = providerMeta(provider);
    if (!meta || typeof model !== 'string' || !model.trim()) return false;
    const id = model.trim();
    if (meta.requireFreeSuffix && !id.endsWith(':free')) return false;
    return meta.freeModels.includes(id) || meta.preferredModels.includes(id);
}

/** Env override when it is free, otherwise the provider default. */
function resolveModel(provider, { vision = false } = {}) {
    const meta = providerMeta(provider);
    if (!meta) return null;
    const override = cleanEnvValue(process.env[meta.envModel]);
    if (override && isFreeModel(provider, override) && (!vision || supportsVision(provider, override))) {
        return override;
    }
    if (vision) {
        const preferredVision = (meta.preferredModels || []).find(id => supportsVision(provider, id));
        if (preferredVision) return preferredVision;
        return (meta.visionModels || [])[0] || meta.defaultModel;
    }
    return meta.defaultModel;
}

function providerConfigured(provider) {
    return Boolean(providerMeta(provider) && readProviderKey(provider));
}

function configuredProviders() {
    return PROVIDER_ORDER.filter(providerConfigured);
}

function supportsVision(provider, model = resolveModel(provider)) {
    const meta = providerMeta(provider);
    if (!meta || !model) return false;
    if ((meta.visionModels || []).includes(model)) return true;
    // Discovered Gemini flash/pro families accept images.
    if (provider === 'gemini') return /^gemini-(1\.5|2|3|4)[\w.-]*-(flash|pro)\b/.test(model) && !/-tts|-audio/.test(model);
    return false;
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
    ENV_KEY_ALIASES,
    providerMeta,
    cleanEnvValue,
    isPlaceholderKey,
    readProviderKey,
    keySource,
    isFreeModel,
    resolveModel,
    providerConfigured,
    configuredProviders,
    supportsVision,
    supportsChat,
    maskSecret,
};
