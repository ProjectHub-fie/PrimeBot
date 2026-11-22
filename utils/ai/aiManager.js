/**
 * Central AI manager — the single backend used by slash commands, prefix
 * commands and mention/reply handling.
 *
 * Responsibilities:
 *  - guild settings cache (adaptive poll, never a hot-path DB read)
 *  - free-provider failover (Groq -> Gemini -> OpenRouter free models)
 *  - session memory (per guild+user, persisted, expiry, context trimming)
 *  - usage protection (global / guild / user daily limits + cooldowns)
 *  - honest provider status for the dashboard
 *
 * It never reads a provider key into a response, a log line or a prompt.
 */

const repo = require('../../server/aiRepo');
const { AdaptivePoller } = require('../adaptivePoller');
const { AI_LIMITS, aiChannelAllowed, aiRoleAllowed } = require('../../shared/aiConstants');
const {
    PROVIDER_ORDER, providerMeta, resolveModel, providerConfigured,
    supportsVision, supportsChat, maskSecret,
} = require('./freeModels');
const { callProvider } = require('./providers');
const {
    sanitizeUserText, buildSystemPrompt, wrapUserContent, chunkText,
} = require('./promptSafety');

const MAX_PROVIDER_ATTEMPTS = 2;
const TRANSIENT = new Set(['timeout', 'server', 'network']);

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function envInt(name, fallback) {
    const n = parseInt(process.env[name], 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

class AiManager {
    constructor(client = null) {
        this.client = client;
        this._settings = new Map();
        this._tableReady = false;
        this._disabled = new Set();        // provider ids disabled for this process (auth errors)
        this._cooldowns = new Map();       // provider -> epoch ms
        this._lastRequest = new Map();     // `${guildId}:${userId}` -> epoch ms
        this._global = { day: this._today(), requests: 0 };
        this._initPromise = this._init();
    }

    _today() {
        return new Date().toISOString().slice(0, 10);
    }

    async _init() {
        try {
            await repo.ensureAiTables();
            this._tableReady = true;
            await this._loadSettings();
            this._startPoller();
            const removed = await repo.purgeExpiredSessions().catch(() => 0);
            if (removed) console.log(`[AI] purged ${removed} expired session(s)`);
            console.log('✅ AiManager database connection established');
        } catch (err) {
            this._tableReady = false;
            console.error('❌ AiManager initialization failed:', err.message);
            console.log('⚠️ AI Assistant will use fallback mode (AI unavailable)');
        }
    }

    ready() { return this._initPromise; }

    _startPoller() {
        if (this._poller) return;
        this._poller = new AdaptivePoller({
            name: 'AI SETTINGS',
            task: async () => {
                const changed = await this._loadSettings();
                // Session expiry is enforced lazily on read too; this sweep only
                // runs when the poller ticks (never per message).
                await repo.purgeExpiredSessions().catch(() => 0);
                return changed;
            },
            initialMs: 120000,
            maxMs: 30 * 60 * 1000,
        });
        this._poller.start();
    }

    stop() {
        if (this._poller) { this._poller.stop(); this._poller = null; }
    }

    async _loadSettings() {
        if (!this._tableReady) return false;
        try {
            const rows = await repo.getAllAiSettings();
            const next = new Map(rows.map(r => [String(r.guildId), r.settings]));
            let changed = next.size !== this._settings.size;
            if (!changed) {
                for (const [id, s] of next) {
                    if (JSON.stringify(this._settings.get(id)) !== JSON.stringify(s)) { changed = true; break; }
                }
            }
            this._settings = next;
            return changed;
        } catch (err) {
            console.warn('[AI] settings reload failed:', err.message);
            return false;
        }
    }

    // ── Settings / access ───────────────────────────────────────────────────
    getSettings(guildId) {
        return this._settings.get(String(guildId)) || {
            enabled: false, channelIds: [], roleIds: [], mode: 'mention',
        };
    }

    isEnabled(guildId) {
        return this.getSettings(guildId).enabled === true;
    }

    async updateSettings(guildId, patch) {
        const next = await repo.upsertAiSettings(guildId, patch);
        this._settings.set(String(guildId), next);
        return next;
    }

    /** Channel + role gate. Returns `{ ok, reason }` — never throws. */
    checkAccess({ guildId, channelId, member }) {
        const settings = this.getSettings(guildId);
        if (!settings.enabled) return { ok: false, reason: 'disabled', settings };
        if (!aiChannelAllowed(settings, channelId)) return { ok: false, reason: 'channel', settings };
        if (!aiRoleAllowed(settings, member)) return { ok: false, reason: 'role', settings };
        return { ok: true, settings };
    }

    _globalBudget() {
        const day = this._today();
        if (this._global.day !== day) this._global = { day, requests: 0 };
        return envInt('AI_GLOBAL_DAILY_REQUESTS', 2000);
    }

    /** Cooldown + daily quota pre-check (cheap, in-memory + one indexed row). */
    async _checkQuota({ guildId, userId, settings }) {
        const key = `${guildId}:${userId}`;
        const now = Date.now();
        const last = this._lastRequest.get(key) || 0;
        const cooldownMs = Math.max(0, Number(settings.cooldownSeconds) || 0) * 1000;
        if (cooldownMs && now - last < cooldownMs) {
            return { ok: false, reason: 'cooldown', retryAfterMs: cooldownMs - (now - last) };
        }
        if (this._global.requests >= this._globalBudget()) {
            return { ok: false, reason: 'global_quota' };
        }
        try {
            const [userUsage, guildUsage] = await Promise.all([
                repo.getUsageToday(guildId, userId),
                repo.getGuildUsageToday(guildId),
            ]);
            if (userUsage.requests >= settings.dailyUserRequests) return { ok: false, reason: 'user_quota' };
            if (guildUsage.requests >= settings.dailyGuildRequests) return { ok: false, reason: 'guild_quota' };
        } catch (err) {
            // A usage read failure must not block the feature; limits still
            // apply through the in-memory cooldown + global counter.
            console.warn('[AI] usage pre-check failed:', err.message);
        }
        return { ok: true };
    }

    _markRequest(guildId, userId, tokens) {
        this._lastRequest.set(`${guildId}:${userId}`, Date.now());
        this._global.requests += 1;
        if (this._lastRequest.size > 5000) {
            const cutoff = Date.now() - 60 * 60 * 1000;
            for (const [key, at] of this._lastRequest) if (at < cutoff) this._lastRequest.delete(key);
        }
        repo.incrementUsage(guildId, userId, { requests: 1, tokens: tokens || 0 }).catch(() => {});
    }

    // ── Provider loop ───────────────────────────────────────────────────────
    _providerReady(provider, { vision }) {
        if (!providerConfigured(provider)) return false;
        if (this._disabled.has(provider)) return false;
        const until = this._cooldowns.get(provider);
        if (until && until > Date.now()) return false;
        if (!supportsChat(provider)) return false;
        const model = resolveModel(provider);
        if (!model) return false;
        if (vision && !supportsVision(provider, model)) return false;
        return true;
    }

    /**
     * Try every configured free provider in priority order. Bounded retries for
     * transient failures; a rate limit moves to the next provider; an auth
     * failure disables that provider for the process.
     */
    async _runProviders({ messages, images = [], vision = false, maxTokens = 700 }) {
        const configured = PROVIDER_ORDER.filter(p => providerConfigured(p));
        if (!configured.length) {
            return { ok: false, reason: 'not_configured', message: 'No AI provider is configured.' };
        }

        let lastError = null;
        for (const provider of PROVIDER_ORDER) {
            if (!this._providerReady(provider, { vision })) continue;
            const model = resolveModel(provider);

            for (let attempt = 0; attempt < MAX_PROVIDER_ATTEMPTS; attempt++) {
                const res = await callProvider(provider, {
                    messages, images, maxTokens,
                    timeoutMs: envInt('AI_TIMEOUT_MS', 30000),
                });

                if (res.ok) {
                    this._cooldowns.delete(provider);
                    repo.recordProviderResult(provider, { ok: true }).catch(() => {});
                    return { ...res, provider };
                }

                lastError = { provider, model, ...res };
                console.warn(`[AI] ${provider} failed (${res.kind}): ${res.message}`);

                if (res.kind === 'auth') {
                    this._disabled.add(provider);
                    repo.recordProviderResult(provider, { ok: false, error: 'auth failed' }).catch(() => {});
                    break;
                }
                if (res.kind === 'rate_limit' || res.kind === 'quota') {
                    const seconds = Math.min(900, Math.max(30, Number(res.retryAfter) || 60));
                    this._cooldowns.set(provider, Date.now() + seconds * 1000);
                    repo.recordProviderResult(provider, {
                        ok: false,
                        error: res.kind === 'quota' ? 'free quota exhausted' : 'rate limited',
                        cooldownUntil: new Date(Date.now() + seconds * 1000),
                    }).catch(() => {});
                    break;
                }
                if (res.kind === 'capability' || res.kind === 'bad_request' || res.kind === 'bad_response') {
                    repo.recordProviderResult(provider, { ok: false, error: res.message }).catch(() => {});
                    break;
                }
                if (TRANSIENT.has(res.kind) && attempt < MAX_PROVIDER_ATTEMPTS - 1) {
                    await sleep(400);
                    continue;
                }
                repo.recordProviderResult(provider, { ok: false, error: res.message }).catch(() => {});
                break;
            }
        }

        return {
            ok: false,
            reason: vision ? 'vision_unavailable' : 'unavailable',
            message: vision
                ? 'Image analysis is temporarily unavailable — no free vision model is available right now.'
                : 'The AI assistant is temporarily unavailable. All free providers are busy or rate-limited — please try again in a few minutes.',
            lastError,
        };
    }

    // ── Context ─────────────────────────────────────────────────────────────
    _historyToMessages(history) {
        let budget = AI_LIMITS.contextChars;
        const kept = [];
        for (let i = history.length - 1; i >= 0; i--) {
            const m = history[i];
            const cost = String(m.content || '').length;
            if (cost > budget) break;
            budget -= cost;
            kept.unshift(m);
        }
        return kept.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));
    }

    async _knowledgeFor(guildId, settings, prompt) {
        if (!settings.knowledgeEnabled) return [];
        try {
            const entries = await repo.listKnowledge(guildId, { limit: AI_LIMITS.maxKnowledgeEntries });
            if (!entries.length) return [];
            // Prefer entries whose title/tags appear in the prompt, else the
            // most recently updated ones (bounded by the prompt builder).
            const needle = String(prompt || '').toLowerCase();
            const ranked = entries.slice().sort((a, b) => {
                const score = (e) => {
                    const hay = `${e.title} ${e.tags}`.toLowerCase();
                    return hay.split(/\s+/).some(word => word.length > 3 && needle.includes(word)) ? 1 : 0;
                };
                return score(b) - score(a);
            });
            return ranked.slice(0, 12);
        } catch (err) {
            console.warn('[AI] knowledge read failed:', err.message);
            return [];
        }
    }

    // ── Public chat API ─────────────────────────────────────────────────────
    /**
     * One conversational turn. Persists memory when `useSession` is true.
     * Returns `{ ok, text, chunks, provider, model, usage }` or `{ ok:false, reason }`.
     */
    async chat({
        guildId, userId, channelId = null, guildName = '', prompt,
        images = [], capability = 'chat', useSession = true, maxTokens = 700,
    }) {
        if (!this._tableReady) {
            return { ok: false, reason: 'unavailable', message: 'The AI assistant is not available right now.' };
        }
        const settings = this.getSettings(guildId);
        if (!settings.enabled) {
            return { ok: false, reason: 'disabled', message: 'The AI assistant is disabled in this server.' };
        }
        if (capability === 'vision' && !settings.visionEnabled) {
            return { ok: false, reason: 'vision_disabled', message: 'Image analysis is disabled in this server.' };
        }

        const clean = sanitizeUserText(prompt, AI_LIMITS.maxPromptChars);
        if (!clean) {
            return { ok: false, reason: 'empty', message: 'Please include a question or some text.' };
        }
        if (images.length && !settings.allowAttachments) {
            return { ok: false, reason: 'attachments_disabled', message: 'Attachments are disabled for the AI assistant in this server.' };
        }

        const quota = await this._checkQuota({ guildId, userId, settings });
        if (!quota.ok) return { ok: false, ...quota };

        let session = null;
        let history = [];
        if (useSession) {
            try {
                session = await repo.getSession(guildId, userId);
                if (session && new Date(session.expiresAt).getTime() <= Date.now()) {
                    await repo.deleteSession(guildId, userId);
                    session = null;
                }
                if (!session) session = await repo.createSession(guildId, userId, channelId, settings.sessionTtlMinutes);
                history = await repo.getMessages(session.id, AI_LIMITS.contextMessages);
            } catch (err) {
                console.warn('[AI] session read failed:', err.message);
                session = null;
            }
        }

        const knowledge = await this._knowledgeFor(guildId, settings, clean);
        const messages = [
            {
                role: 'system',
                content: buildSystemPrompt({
                    settings, guildName, knowledge,
                    extra: capability === 'vision'
                        ? 'The user attached an image. Describe and analyse it, then answer their question.'
                        : '',
                }),
            },
            ...this._historyToMessages(history),
            { role: 'user', content: wrapUserContent(clean) },
        ];

        const result = await this._runProviders({
            messages,
            images,
            vision: capability === 'vision',
            maxTokens: Math.min(maxTokens, settings.maxResponseChars),
        });

        if (!result.ok) return result;

        const text = String(result.text).slice(0, settings.maxResponseChars);
        this._markRequest(guildId, userId, result.usage?.tokens || 0);

        if (session) {
            try {
                await repo.addMessage(session.id, 'user', clean);
                await repo.addMessage(session.id, 'assistant', text);
                await repo.trimMessages(session.id, 24);
                await repo.touchSession(session.id, settings.sessionTtlMinutes);
            } catch (err) {
                console.warn('[AI] session write failed:', err.message);
            }
        }

        return {
            ok: true,
            text,
            chunks: chunkText(text, 1900),
            provider: result.provider,
            model: result.model,
            usage: result.usage,
            sessionId: session ? session.id : null,
        };
    }

    /** One-shot completion with no session memory (summaries, translation…). */
    async complete({ guildId, guildName = '', system, user, images = [], capability = 'chat', maxTokens = 700 }) {
        const settings = this.getSettings(guildId);
        const messages = [
            { role: 'system', content: system || buildSystemPrompt({ settings, guildName }) },
            { role: 'user', content: user },
        ];
        const result = await this._runProviders({ messages, images, vision: capability === 'vision', maxTokens });
        if (result.ok) result.chunks = chunkText(String(result.text).slice(0, settings.maxResponseChars), 1900);
        return result;
    }

    async resetSession(guildId, userId) {
        try {
            return await repo.deleteSession(guildId, userId);
        } catch (err) {
            console.warn('[AI] reset failed:', err.message);
            return 0;
        }
    }

    async clearGuildSessions(guildId) {
        try {
            return await repo.deleteGuildSessions(guildId);
        } catch (err) {
            console.warn('[AI] clear sessions failed:', err.message);
            return 0;
        }
    }

    // ── Diagnostics ─────────────────────────────────────────────────────────
    /**
     * Provider status for the dashboard. Keys are never included — only whether
     * a provider is configured and the last 4 characters of the key.
     */
    async getProviderStatus() {
        let meta = [];
        try { meta = await repo.getProviderMeta(); } catch (_) { meta = []; }
        const byProvider = new Map(meta.map(row => [row.provider, row]));
        return PROVIDER_ORDER.map(provider => {
            const info = providerMeta(provider);
            const row = byProvider.get(provider) || {};
            const model = resolveModel(provider);
            const cooldownUntil = this._cooldowns.get(provider) || (row.cooldown_until ? new Date(row.cooldown_until).getTime() : 0);
            return {
                provider,
                label: info.label,
                configured: providerConfigured(provider),
                keyHint: maskSecret(process.env[info.envKey]),
                model,
                modelIsFree: Boolean(model),
                vision: supportsVision(provider, model),
                active: this._providerReady(provider, { vision: false }),
                disabled: this._disabled.has(provider),
                cooldownUntil: cooldownUntil && cooldownUntil > Date.now() ? new Date(cooldownUntil).toISOString() : null,
                requests: Number(row.requests) || 0,
                failures: Number(row.failures) || 0,
                lastOkAt: row.last_ok_at || null,
                lastErrorAt: row.last_error_at || null,
                lastError: row.last_error || null,
            };
        });
    }

    /** Explicit admin-triggered provider check (the only proactive request). */
    async testProvider(provider) {
        if (!providerMeta(provider)) return { ok: false, message: 'Unknown provider.' };
        if (!providerConfigured(provider)) return { ok: false, message: `${providerMeta(provider).label} is not configured.` };
        const started = Date.now();
        const res = await callProvider(provider, {
            messages: [
                { role: 'system', content: 'You are a health check. Reply with exactly: OK' },
                { role: 'user', content: 'ping' },
            ],
            maxTokens: 16,
            timeoutMs: envInt('AI_TIMEOUT_MS', 20000),
        });
        if (res.ok) {
            repo.recordProviderResult(provider, { ok: true }).catch(() => {});
            return { ok: true, provider, model: res.model, latencyMs: Date.now() - started };
        }
        repo.recordProviderResult(provider, { ok: false, error: res.message }).catch(() => {});
        return { ok: false, provider, kind: res.kind, message: res.message };
    }
}

module.exports = { AiManager };
