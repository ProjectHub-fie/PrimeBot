/**
 * Judge0 CE provider — the only place that talks to the execution API.
 *
 * The command layer talks to this interface, never to Judge0 directly, so a
 * different provider can be added later by implementing the same three methods
 * (`listLanguages`, `createSubmission`, `getSubmission`).
 *
 * Public endpoint: https://ce.judge0.com (no API key required for basic use).
 * Submitted code is never executed on PrimeBot's own host.
 */

const { DEFAULT_API_URL, normalizeBaseUrl } = require('./compileConfig');
const { encodeBase64 } = require('./limits');

const ERROR_KINDS = Object.freeze({
    TIMEOUT: 'timeout',
    RATE_LIMITED: 'rate_limited',
    PROVIDER_ERROR: 'provider_error',
    NETWORK: 'network',
    INVALID_RESPONSE: 'invalid_response',
    INVALID_TOKEN: 'invalid_token',
});

/** User-facing wording per failure kind — never a raw provider response. */
const ERROR_MESSAGES = Object.freeze({
    timeout: 'The execution service did not answer in time. The shared public API may be busy — try again shortly.',
    rate_limited: 'The shared execution service is rate-limiting requests right now. Please try again in a moment.',
    provider_error: 'The execution service is unavailable right now. This is a provider-side problem, not your code.',
    network: 'Could not reach the execution service. Please try again shortly.',
    invalid_response: 'The execution service returned an unexpected response.',
    invalid_token: 'The execution service rejected the submission token.',
});

class Judge0Error extends Error {
    constructor(kind, message, { status = null, retryAfterMs = null, cause = null } = {}) {
        super(message);
        this.name = 'Judge0Error';
        this.kind = kind;
        this.status = status;
        this.retryAfterMs = retryAfterMs;
        this.cause = cause;
    }

    /** Safe to show a Discord user. */
    get userMessage() {
        return ERROR_MESSAGES[this.kind] || ERROR_MESSAGES.provider_error;
    }
}

function headerValue(response, name) {
    const headers = response && response.headers;
    if (!headers) return null;
    try {
        if (typeof headers.get === 'function') return headers.get(name);
        const lower = String(name).toLowerCase();
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === lower) return headers[key];
        }
    } catch (_) { /* ignore */ }
    return null;
}

function parseRetryAfter(response) {
    const raw = headerValue(response, 'retry-after');
    const seconds = Number(raw);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000);
    return null;
}

/** Submission tokens are opaque; reject anything that is not URL-safe. */
const TOKEN_RE = /^[A-Za-z0-9-]{1,64}$/;

function createJudge0Provider(options = {}) {
    const baseUrl = normalizeBaseUrl(
        options.baseUrl || options.apiUrl || process.env.JUDGE0_API_URL || DEFAULT_API_URL
    );
    const requestTimeoutMs = Number.isFinite(options.requestTimeoutMs) ? options.requestTimeoutMs : 15000;
    const fetchFn = options.fetchFn || (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null);

    async function request(path, { method = 'GET', body } = {}) {
        if (typeof fetchFn !== 'function') {
            throw new Judge0Error(ERROR_KINDS.NETWORK, 'no fetch implementation available');
        }
        const url = `${baseUrl}${path}`;
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        const timer = controller && requestTimeoutMs > 0
            ? setTimeout(() => controller.abort(), requestTimeoutMs)
            : null;
        if (timer && timer.unref) timer.unref();

        let response;
        try {
            response = await fetchFn(url, {
                method,
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: body === undefined ? undefined : JSON.stringify(body),
                signal: controller ? controller.signal : undefined,
            });
        } catch (err) {
            if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) {
                throw new Judge0Error(ERROR_KINDS.TIMEOUT, 'request aborted after timeout', { cause: err });
            }
            throw new Judge0Error(ERROR_KINDS.NETWORK, err && err.message ? err.message : 'network failure', { cause: err });
        } finally {
            if (timer) clearTimeout(timer);
        }

        const status = Number(response && response.status);
        if (status === 429) {
            throw new Judge0Error(ERROR_KINDS.RATE_LIMITED, 'provider rate limit', {
                status,
                retryAfterMs: parseRetryAfter(response),
            });
        }
        if (status === 404 && path.startsWith('/submissions/')) {
            throw new Judge0Error(ERROR_KINDS.INVALID_TOKEN, 'submission token not found', { status });
        }
        if (!response || response.ok === false || status >= 400) {
            throw new Judge0Error(ERROR_KINDS.PROVIDER_ERROR, `provider responded ${status || 'unknown'}`, { status });
        }

        let data;
        try {
            if (typeof response.json === 'function') data = await response.json();
            else if (typeof response.text === 'function') data = JSON.parse(await response.text());
            else data = null;
        } catch (err) {
            throw new Judge0Error(ERROR_KINDS.INVALID_RESPONSE, 'response was not valid JSON', { cause: err });
        }
        if (data == null) {
            throw new Judge0Error(ERROR_KINDS.INVALID_RESPONSE, 'empty response body');
        }
        return data;
    }

    /** `GET /languages` — the authoritative id/name list. */
    async function listLanguages() {
        const data = await request('/languages');
        if (!Array.isArray(data)) {
            throw new Judge0Error(ERROR_KINDS.INVALID_RESPONSE, 'languages payload was not an array');
        }
        return data
            .filter(entry => entry && entry.id != null && typeof entry.name === 'string')
            .map(entry => ({ id: Number(entry.id), name: entry.name }));
    }

    /**
     * `POST /submissions?base64_encoded=true&wait=false` — creates the
     * submission and returns its token. Never retried: a retry here would
     * execute the same code again.
     */
    async function createSubmission({ sourceCode, languageId, stdin = '' }) {
        const body = {
            source_code: encodeBase64(sourceCode),
            language_id: Number(languageId),
            stdin: encodeBase64(stdin),
        };
        const data = await request('/submissions?base64_encoded=true&wait=false', { method: 'POST', body });
        const token = data && data.token;
        if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
            throw new Judge0Error(ERROR_KINDS.INVALID_RESPONSE, 'submission response carried no usable token');
        }
        return { token };
    }

    /** `GET /submissions/{token}?base64_encoded=true` — current state. */
    async function getSubmission(token) {
        if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
            throw new Judge0Error(ERROR_KINDS.INVALID_TOKEN, 'malformed submission token');
        }
        const fields = 'stdout,stderr,compile_output,message,exit_code,time,memory,status,token';
        const data = await request(
            `/submissions/${encodeURIComponent(token)}?base64_encoded=true&fields=${fields}`
        );
        if (!data || typeof data !== 'object' || !data.status || typeof data.status !== 'object') {
            throw new Judge0Error(ERROR_KINDS.INVALID_RESPONSE, 'submission payload had no status');
        }
        return data;
    }

    return {
        name: 'judge0',
        baseUrl,
        supportsFetch: typeof fetchFn === 'function',
        listLanguages,
        createSubmission,
        getSubmission,
    };
}

module.exports = {
    ERROR_KINDS,
    ERROR_MESSAGES,
    Judge0Error,
    createJudge0Provider,
    TOKEN_RE,
};
