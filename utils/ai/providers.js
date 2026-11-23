/**
 * Provider adapters (Groq, Gemini, OpenRouter) — plain `fetch`, no SDK.
 *
 * Each adapter returns a normalized result:
 *   { ok: true, text, model, usage: { tokens }, raw }
 *   { ok: false, kind, status, retryAfter, message }
 *
 * `kind` drives the manager's failover: auth | rate_limit | quota | timeout |
 * server | bad_request | config | network. Errors never contain the API key or
 * the request URL (Gemini carries its key in the query string).
 */

const { providerMeta, readProviderKey } = require('./freeModels');
const modelCatalog = require('./modelCatalog');

const resolveModel = (provider, opts) => modelCatalog.resolveModel(provider, opts);
const supportsVision = (provider, model) => modelCatalog.supportsVision(provider, model);

const MAX_IMAGE_BYTES = 6 * 1024 * 1024;

function timeoutSignal(ms) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
        return AbortSignal.timeout(ms);
    }
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms).unref?.();
    return controller.signal;
}

function sanitizeErrorText(value) {
    if (!value) return null;
    return String(value)
        .replace(/key=[^&\s]+/gi, 'key=••••')
        .replace(/Bearer\s+[A-Za-z0-9._-]+/g, 'Bearer ••••')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 240) || null;
}

const INVALID_MODEL_RE = /(does not exist|not found|no longer available|is not supported|unsupported|deprecated|retired|decommissioned|invalid model)/i;
const MODEL_WORD_RE = /\bmodels?\b/i;
const MISSING_AUTH_RE = /(missing authentication|no auth|unauthori[sz]ed|invalid api key|incorrect api key|api key not valid|authentication header)/i;
const QUOTA_RE = /(insufficient_quota|quota|billing|credit|exceeded your current)/i;

/**
 * Normalize a provider failure. `kind` drives the manager:
 *   auth          → provider is unusable for this process (never retried)
 *   invalid_model → rediscover the model list once, then disable if still bad
 *   quota         → long cooldown (free quota exhausted)
 *   rate_limit    → short cooldown, then the next provider
 *   timeout/server/network → bounded retry
 */
function classify(status, body, err) {
    const detail = sanitizeErrorText(
        body?.error?.message || body?.message || body?.error || (err && err.message) || null
    );
    if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
        return { kind: 'timeout', status: 0, message: 'The provider took too long to respond.' };
    }
    if (!status) return { kind: 'network', status: 0, message: detail || 'Network error.' };
    if (status === 401 || status === 403) {
        return { kind: 'auth', status, message: detail || 'Authentication failed.' };
    }
    if (status === 400 && detail && MISSING_AUTH_RE.test(detail)) {
        return { kind: 'auth', status, message: detail };
    }
    if (status === 402) return { kind: 'quota', status, message: detail || 'Free quota exhausted.' };
    if (status === 429) {
        const retry = Number(body?.retry_after ?? body?.error?.retry_after ?? body?.error?.details?.find?.(d => d.retryDelay)?.retryDelay) || null;
        const kind = detail && QUOTA_RE.test(detail) ? 'quota' : 'rate_limit';
        return { kind, status, retryAfter: retry, message: detail || 'Rate limited.' };
    }
    if (status === 404 || (status === 400 && detail && MODEL_WORD_RE.test(detail) && INVALID_MODEL_RE.test(detail))) {
        return { kind: 'invalid_model', status, message: detail || 'That model is not available.' };
    }
    if (status === 400 || status === 422) return { kind: 'bad_request', status, message: detail || 'The provider rejected the request.' };
    if (status >= 500) return { kind: 'server', status, message: detail || 'The provider is having trouble.' };
    return { kind: 'unknown', status, message: detail || 'The provider returned an unexpected response.' };
}

async function fetchImageBase64(url, timeoutMs) {
    if (typeof url !== 'string' || !/^https:\/\//i.test(url)) {
        throw new Error('Only https image URLs are supported.');
    }
    const res = await fetch(url, { signal: timeoutSignal(timeoutMs) });
    if (!res.ok) throw new Error(`Image download failed (${res.status}).`);
    const type = res.headers.get('content-type') || 'image/png';
    if (!/^image\//i.test(type)) throw new Error('The attachment is not an image.');
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_IMAGE_BYTES) throw new Error('That image is too large (max 6 MB).');
    return { mimeType: type.split(';')[0], data: buf.toString('base64') };
}

function toOpenAiMessages(messages, images = []) {
    return messages.map((m, index) => {
        const isLastUser = index === messages.length - 1 && m.role === 'user';
        if (!isLastUser || !images.length) return { role: m.role, content: m.content };
        return {
            role: m.role,
            content: [
                { type: 'text', text: m.content },
                ...images.map(img => ({ type: 'image_url', image_url: { url: img } })),
            ],
        };
    });
}

async function callOpenAiCompatible(provider, { messages, images = [], maxTokens, timeoutMs = 30000 }) {
    const meta = providerMeta(provider);
    const key = readProviderKey(provider);
    const model = resolveModel(provider);
    if (!key) return { ok: false, kind: 'config', status: 0, message: `${meta.label} is not configured.` };
    if (!model) return { ok: false, kind: 'invalid_model', status: 0, message: `${meta.label} offers no usable free model right now.` };
    if (images.length && !supportsVision(provider, model)) {
        return { ok: false, kind: 'capability', status: 0, message: `${meta.label} cannot analyse images.` };
    }

    const payload = {
        model,
        messages: toOpenAiMessages(messages, images),
        max_tokens: Math.min(Math.max(Number(maxTokens) || 700, 64), 2000),
        temperature: 0.7,
    };
    const headers = {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
    };
    if (provider === 'openrouter') {
        headers['HTTP-Referer'] = process.env.AI_OPENROUTER_REFERER || 'https://primebot.dashboard';
        headers['X-Title'] = 'PrimeBot';
    }

    let res;
    try {
        res = await fetch(meta.endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            signal: timeoutSignal(timeoutMs),
        });
    } catch (err) {
        return { ok: false, ...classify(0, null, err) };
    }

    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) return { ok: false, ...classify(res.status, data, null) };

    const choice = data?.choices?.[0];
    const rawContent = choice?.message?.content;
    const text = Array.isArray(rawContent)
        ? rawContent.map(part => (typeof part === 'string' ? part : part?.text || '')).join('')
        : (typeof rawContent === 'string' ? rawContent : '');
    if (!text.trim()) {
        return { ok: false, kind: 'bad_response', status: res.status, message: 'The provider returned an empty answer.' };
    }
    return {
        ok: true,
        text,
        model,
        usage: { tokens: Number(data?.usage?.total_tokens) || 0 },
    };
}

async function callGemini({ messages, images = [], maxTokens, timeoutMs = 30000 }) {
    const meta = providerMeta('gemini');
    const key = readProviderKey('gemini');
    const model = resolveModel('gemini', { vision: images.length > 0 });
    if (!key) return { ok: false, kind: 'config', status: 0, message: 'Google Gemini is not configured.' };
    if (!model) return { ok: false, kind: 'invalid_model', status: 0, message: 'Gemini offers no usable free model right now.' };
    if (images.length && !modelCatalog.supportsVision('gemini', model)) {
        return { ok: false, kind: 'capability', status: 0, message: 'The selected Gemini model cannot analyse images.' };
    }

    const system = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const contents = messages
        .filter(m => m.role !== 'system')
        .map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));

    if (images.length && contents.length) {
        const parts = contents[contents.length - 1].parts;
        for (const url of images) {
            try {
                const img = await fetchImageBase64(url, Math.min(timeoutMs, 10000));
                parts.push({ inline_data: { mime_type: img.mimeType, data: img.data } });
            } catch (err) {
                return { ok: false, kind: 'bad_request', status: 0, message: sanitizeErrorText(err.message) };
            }
        }
    }

    const payload = {
        contents,
        generationConfig: { maxOutputTokens: Math.min(Math.max(Number(maxTokens) || 700, 64), 2000), temperature: 0.7 },
    };
    if (system) payload.systemInstruction = { parts: [{ text: system }] };

    let res;
    try {
        res = await fetch(`${meta.endpoint}/${encodeURIComponent(model)}:generateContent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
            body: JSON.stringify(payload),
            signal: timeoutSignal(timeoutMs),
        });
    } catch (err) {
        return { ok: false, ...classify(0, null, err) };
    }

    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) return { ok: false, ...classify(res.status, data, null) };

    const candidate = data?.candidates?.[0];
    const text = (candidate?.content?.parts || []).map(p => p?.text || '').join('').trim();
    if (!text) {
        const blocked = candidate?.finishReason || data?.promptFeedback?.blockReason;
        return {
            ok: false,
            kind: 'bad_response',
            status: res.status,
            message: blocked ? `Gemini declined to answer (${blocked}).` : 'The provider returned an empty answer.',
        };
    }
    return {
        ok: true,
        text,
        model,
        usage: { tokens: Number(data?.usageMetadata?.totalTokenCount) || 0 },
    };
}

async function callProvider(provider, opts = {}) {
    if (provider === 'gemini') return callGemini(opts);
    if (provider === 'groq' || provider === 'openrouter') return callOpenAiCompatible(provider, opts);
    return { ok: false, kind: 'config', status: 0, message: 'Unknown provider.' };
}

module.exports = {
    callProvider,
    sanitizeErrorText,
    fetchImageBase64,
    classify,
};
