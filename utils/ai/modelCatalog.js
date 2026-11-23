/**
 * Live model discovery for the free AI providers.
 *
 * Providers retire models without warning (`llama-3.3-70b-versatile` disappeared
 * for new Groq orgs, `gemini-2.0-flash` was retired), so a hardcoded id is never
 * trusted on its own. Each provider's own `/models` endpoint is authoritative:
 *
 *   Groq        GET https://api.groq.com/openai/v1/models
 *   Gemini      GET https://generativelanguage.googleapis.com/v1beta/models
 *   OpenRouter  GET https://openrouter.ai/api/v1/models   (public, no key needed)
 *
 * A model is used only when the provider reports it (and, on OpenRouter, only
 * when both prompt and completion pricing are `0`). Discovery is cached for
 * `AI_MODEL_DISCOVERY_TTL_MS` (6h) and refreshed on demand when a model turns
 * out to be invalid. Network failures fall back to the static catalog, so the
 * assistant still works offline-ish; they never throw into a command.
 */

const {
    PROVIDER_ORDER, providerMeta, readProviderKey, keySource, maskSecret,
    isFreeModel, supportsVision, resolveModel: staticResolveModel,
} = require('./freeModels');

const TTL_MS = Math.max(60_000, Number(process.env.AI_MODEL_DISCOVERY_TTL_MS) || 6 * 60 * 60 * 1000);
const DISCOVERY_TIMEOUT_MS = Math.max(1000, Number(process.env.AI_MODEL_DISCOVERY_TIMEOUT_MS) || 8000);

const cache = new Map(); // provider -> { at, ok, models, error }

function timeoutSignal(ms) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
        return AbortSignal.timeout(ms);
    }
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms).unref?.();
    return controller.signal;
}

function safeMessage(err) {
    return String((err && err.message) || err || 'unknown error')
        .replace(/key=[^&\s]+/gi, 'key=••••')
        .replace(/Bearer\s+[A-Za-z0-9._-]+/g, 'Bearer ••••')
        .slice(0, 200);
}

function isChatModelId(id) {
    const value = String(id || '').toLowerCase();
    if (!value) return false;
    return !/(whisper|tts|guard|embed|moderation|rerank|lyria|imagen|veo|aqa|audio|image-preview|computer-use)/.test(value);
}

function groqModels(data) {
    const list = Array.isArray(data?.data) ? data.data : [];
    return list
        .map(m => String(m?.id || ''))
        .filter(isChatModelId)
        .map(id => ({
            id,
            vision: /llama-4|qwen.*vl|vision/i.test(id),
        }));
}

function geminiModels(data) {
    const list = Array.isArray(data?.models) ? data.models : [];
    return list
        .filter(m => (m?.supportedGenerationMethods || []).includes('generateContent'))
        .map(m => String(m?.name || '').replace(/^models\//, ''))
        .filter(isChatModelId)
        .map(id => ({
            id,
            vision: /^gemini-(1\.5|2|3|4)[\w.-]*-(flash|pro)\b/.test(id) && !/-tts|-audio/.test(id),
        }));
}

function openRouterModels(data) {
    const list = Array.isArray(data?.data) ? data.data : [];
    return list
        .filter(m => {
            const p = m?.pricing || {};
            return String(p.prompt) === '0' && String(p.completion) === '0';
        })
        .map(m => {
            const arch = m?.architecture || {};
            const inputs = arch.input_modalities || [];
            const outputs = arch.output_modalities || [];
            return {
                id: String(m?.id || ''),
                vision: inputs.includes('image'),
                textOut: outputs.length ? outputs.includes('text') : true,
                textIn: inputs.length ? inputs.includes('text') : true,
            };
        })
        .filter(m => m.id && m.textIn && m.textOut && isChatModelId(m.id))
        .map(({ id, vision }) => ({ id, vision }));
}

async function fetchList(provider, { fetchFn = fetch, timeoutMs = DISCOVERY_TIMEOUT_MS } = {}) {
    const meta = providerMeta(provider);
    if (!meta) return { ok: false, models: [], error: 'unknown_provider' };
    const key = readProviderKey(provider);
    if (!key && provider !== 'openrouter') return { ok: false, models: [], error: 'no_key' };

    const headers = { Accept: 'application/json' };
    if (key) headers.Authorization = `Bearer ${key}`;
    if (provider === 'gemini') headers['x-goog-api-key'] = key;

    let res;
    try {
        res = await fetchFn(meta.modelsEndpoint, { headers, signal: timeoutSignal(timeoutMs) });
    } catch (err) {
        return { ok: false, models: [], error: `network: ${safeMessage(err)}` };
    }
    if (!res || !res.ok) {
        return { ok: false, models: [], error: `http_${res ? res.status : '?'}` };
    }
    let data = null;
    try { data = await res.json(); } catch (err) {
        return { ok: false, models: [], error: `bad_json: ${safeMessage(err)}` };
    }
    const models = provider === 'groq'
        ? groqModels(data)
        : provider === 'gemini'
            ? geminiModels(data)
            : openRouterModels(data);
    return { ok: true, models };
}

async function discoverModels(provider, opts = {}) {
    const cached = cache.get(provider);
    if (!opts.force && cached && Date.now() - cached.at < TTL_MS) return cached;
    const result = await fetchList(provider, opts);
    const entry = { at: Date.now(), ...result };
    cache.set(provider, entry);
    return entry;
}

/** Refresh every configured provider whose cache is stale (best effort). */
async function ensureDiscovered(providers = PROVIDER_ORDER, opts = {}) {
    const targets = providers.filter(p => providerMeta(p));
    await Promise.all(targets.map(p => discoverModels(p, opts).catch(() => null)));
}

function invalidate(provider) {
    if (provider) cache.delete(provider);
    else cache.clear();
}

function discovered(provider) {
    const entry = cache.get(provider);
    return entry && entry.ok ? entry.models : null;
}

/**
 * Pick a model. Order: valid free env override → preferred list that the
 * provider actually reports → any discovered free model → static default.
 */
function resolveModel(provider, { vision = false } = {}) {
    const meta = providerMeta(provider);
    if (!meta) return null;

    const override = (process.env[meta.envModel] || '').trim();
    const models = discovered(provider);
    // An empty list carries no information (unexpected payload shape), so it is
    // treated like "not discovered" rather than "this provider has no models".
    const usable = models && models.length ? models : null;
    const has = (id) => !usable || usable.some(m => m.id === id && (!vision || m.vision));

    if (override && isFreeModel(provider, override) && has(override)) {
        return override;
    }

    if (usable) {
        const candidates = usable.filter(m => !vision || m.vision);
        for (const id of meta.preferredModels || []) {
            if (candidates.some(m => m.id === id)) return id;
        }
        if (candidates.length) return candidates[0].id;
        return null; // reachable, but nothing there can handle this request
    }

    return staticResolveModel(provider, { vision });
}

function modelSource(provider) {
    const meta = providerMeta(provider);
    if (!meta) return null;
    const override = (process.env[meta.envModel] || '').trim();
    const models = discovered(provider);
    if (override && isFreeModel(provider, override) && (!models || models.some(m => m.id === override))) return 'env';
    return models ? 'discovered' : 'static';
}

function supportsVisionFor(provider, model) {
    if (!model) return false;
    const models = discovered(provider);
    const found = models && models.find(m => m.id === model);
    if (found) return Boolean(found.vision);
    return supportsVision(provider, model);
}

/** Non-secret provider health for the dashboard and `/ai` status. */
function providerHealth(provider) {
    const meta = providerMeta(provider);
    if (!meta) return null;
    const key = readProviderKey(provider);
    const entry = cache.get(provider);
    const model = resolveModel(provider);
    return {
        provider,
        label: meta.label,
        configured: Boolean(key),
        keySource: keySource(provider),
        keyHint: maskSecret(key),
        model,
        modelSource: modelSource(provider),
        vision: supportsVisionFor(provider, model),
        discovery: {
            ok: Boolean(entry && entry.ok),
            count: entry && entry.ok ? entry.models.length : 0,
            error: entry && !entry.ok ? entry.error : null,
            at: entry ? new Date(entry.at).toISOString() : null,
        },
    };
}

module.exports = {
    TTL_MS,
    discoverModels,
    ensureDiscovered,
    invalidate,
    discovered,
    resolveModel,
    modelSource,
    supportsVision: supportsVisionFor,
    providerHealth,
};
