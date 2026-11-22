/**
 * AI Assistant repository — raw SQL against the dedicated AI pool.
 *
 * Tables (self-created so a fresh database works without migrations):
 *   ai_settings        per-guild configuration
 *   ai_sessions        one conversation per (guild, user) with an expiry
 *   ai_messages        bounded conversation history
 *   ai_usage           per (guild, user, day) request/token counters
 *   ai_knowledge       per-guild FAQ entries
 *   ai_provider_meta   non-secret provider health (never API keys)
 *
 * Every conversation query is scoped by guild_id + user_id, so one member can
 * never read another member's (or another guild's) session.
 */

const { aiPool } = require('./aiDb');
const { once } = require('./schemaBootstrap');
const { DEFAULT_AI_SETTINGS, normalizeAiSettings } = require('../shared/aiConstants');

const DDL = `
CREATE TABLE IF NOT EXISTS ai_settings (
    guild_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mode TEXT NOT NULL DEFAULT 'mention',
    channel_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    role_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    personality TEXT NOT NULL DEFAULT 'balanced',
    custom_instructions TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT 'auto',
    max_response_chars INTEGER NOT NULL DEFAULT 1800,
    session_ttl_minutes INTEGER NOT NULL DEFAULT 60,
    cooldown_seconds INTEGER NOT NULL DEFAULT 5,
    daily_user_requests INTEGER NOT NULL DEFAULT 60,
    daily_guild_requests INTEGER NOT NULL DEFAULT 600,
    knowledge_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    vision_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    allow_attachments BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_sessions (
    id SERIAL PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    channel_id TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '60 minutes',
    UNIQUE (guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS ai_messages (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_usage (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    day DATE NOT NULL DEFAULT CURRENT_DATE,
    requests INTEGER NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (guild_id, user_id, day)
);

CREATE TABLE IF NOT EXISTS ai_knowledge (
    id SERIAL PRIMARY KEY,
    guild_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_provider_meta (
    provider TEXT PRIMARY KEY,
    last_ok_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    last_error TEXT,
    cooldown_until TIMESTAMPTZ,
    requests INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ai_sessions_expiry_idx ON ai_sessions (expires_at);
CREATE INDEX IF NOT EXISTS ai_sessions_guild_idx ON ai_sessions (guild_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS ai_messages_session_idx ON ai_messages (session_id, id DESC);
CREATE INDEX IF NOT EXISTS ai_usage_guild_day_idx ON ai_usage (guild_id, day);
CREATE INDEX IF NOT EXISTS ai_knowledge_guild_idx ON ai_knowledge (guild_id, updated_at DESC);
`;

async function ensureAiTables() {
    return once('ai-tables', async () => {
        await aiPool.query(DDL);
    });
}

function rowToSettings(row) {
    if (!row) return { ...DEFAULT_AI_SETTINGS, channelIds: [], roleIds: [] };
    return normalizeAiSettings({
        enabled: row.enabled === true,
        mode: row.mode,
        channelIds: row.channel_ids,
        roleIds: row.role_ids,
        personality: row.personality,
        customInstructions: row.custom_instructions,
        language: row.language,
        maxResponseChars: row.max_response_chars,
        sessionTtlMinutes: row.session_ttl_minutes,
        cooldownSeconds: row.cooldown_seconds,
        dailyUserRequests: row.daily_user_requests,
        dailyGuildRequests: row.daily_guild_requests,
        knowledgeEnabled: row.knowledge_enabled,
        visionEnabled: row.vision_enabled,
        allowAttachments: row.allow_attachments,
    });
}

function rowToSession(row) {
    if (!row) return null;
    return {
        id: row.id,
        guildId: row.guild_id,
        userId: row.user_id,
        channelId: row.channel_id,
        messageCount: Number(row.message_count) || 0,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        expiresAt: row.expires_at,
    };
}

// ── Settings ────────────────────────────────────────────────────────────────
async function getAiSettings(guildId) {
    await ensureAiTables();
    const res = await aiPool.query('SELECT * FROM ai_settings WHERE guild_id = $1', [guildId]);
    return rowToSettings(res.rows[0]);
}

async function getAllAiSettings() {
    await ensureAiTables();
    const res = await aiPool.query('SELECT * FROM ai_settings');
    return res.rows.map(r => ({ guildId: r.guild_id, settings: rowToSettings(r) }));
}

async function upsertAiSettings(guildId, patch = {}) {
    await ensureAiTables();
    const cur = await getAiSettings(guildId);
    const next = normalizeAiSettings(patch, cur);
    const res = await aiPool.query(
        `INSERT INTO ai_settings
            (guild_id, enabled, mode, channel_ids, role_ids, personality, custom_instructions,
             language, max_response_chars, session_ttl_minutes, cooldown_seconds,
             daily_user_requests, daily_guild_requests, knowledge_enabled, vision_enabled,
             allow_attachments, updated_at)
         VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW())
         ON CONFLICT (guild_id) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            mode = EXCLUDED.mode,
            channel_ids = EXCLUDED.channel_ids,
            role_ids = EXCLUDED.role_ids,
            personality = EXCLUDED.personality,
            custom_instructions = EXCLUDED.custom_instructions,
            language = EXCLUDED.language,
            max_response_chars = EXCLUDED.max_response_chars,
            session_ttl_minutes = EXCLUDED.session_ttl_minutes,
            cooldown_seconds = EXCLUDED.cooldown_seconds,
            daily_user_requests = EXCLUDED.daily_user_requests,
            daily_guild_requests = EXCLUDED.daily_guild_requests,
            knowledge_enabled = EXCLUDED.knowledge_enabled,
            vision_enabled = EXCLUDED.vision_enabled,
            allow_attachments = EXCLUDED.allow_attachments,
            updated_at = NOW()
         RETURNING *`,
        [
            guildId, next.enabled, next.mode, JSON.stringify(next.channelIds), JSON.stringify(next.roleIds),
            next.personality, next.customInstructions, next.language, next.maxResponseChars,
            next.sessionTtlMinutes, next.cooldownSeconds, next.dailyUserRequests,
            next.dailyGuildRequests, next.knowledgeEnabled, next.visionEnabled, next.allowAttachments,
        ]
    );
    return rowToSettings(res.rows[0]);
}

// ── Sessions ────────────────────────────────────────────────────────────────
async function getSession(guildId, userId) {
    await ensureAiTables();
    const res = await aiPool.query(
        'SELECT * FROM ai_sessions WHERE guild_id = $1 AND user_id = $2',
        [guildId, userId]
    );
    return rowToSession(res.rows[0]);
}

async function createSession(guildId, userId, channelId, ttlMinutes = 60) {
    await ensureAiTables();
    const res = await aiPool.query(
        `INSERT INTO ai_sessions (guild_id, user_id, channel_id, expires_at)
         VALUES ($1,$2,$3, NOW() + ($4 || ' minutes')::interval)
         ON CONFLICT (guild_id, user_id) DO UPDATE SET
            channel_id = EXCLUDED.channel_id,
            expires_at = EXCLUDED.expires_at,
            updated_at = NOW()
         RETURNING *`,
        [guildId, userId, channelId || null, String(ttlMinutes)]
    );
    return rowToSession(res.rows[0]);
}

async function touchSession(sessionId, ttlMinutes = 60) {
    await ensureAiTables();
    await aiPool.query(
        `UPDATE ai_sessions
         SET updated_at = NOW(), expires_at = NOW() + ($2 || ' minutes')::interval
         WHERE id = $1`,
        [sessionId, String(ttlMinutes)]
    );
}

async function deleteSession(guildId, userId) {
    await ensureAiTables();
    const res = await aiPool.query(
        'DELETE FROM ai_sessions WHERE guild_id = $1 AND user_id = $2',
        [guildId, userId]
    );
    return res.rowCount;
}

async function deleteGuildSessions(guildId) {
    await ensureAiTables();
    const res = await aiPool.query('DELETE FROM ai_sessions WHERE guild_id = $1', [guildId]);
    return res.rowCount;
}

async function listSessions(guildId, { limit = 25, offset = 0 } = {}) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT * FROM ai_sessions WHERE guild_id = $1
         ORDER BY updated_at DESC LIMIT $2 OFFSET $3`,
        [guildId, Math.min(limit, 100), Math.max(offset, 0)]
    );
    return res.rows.map(rowToSession);
}

async function countSessions(guildId) {
    await ensureAiTables();
    const res = await aiPool.query('SELECT COUNT(*)::int AS n FROM ai_sessions WHERE guild_id = $1', [guildId]);
    return Number(res.rows[0].n) || 0;
}

/** Delete expired sessions. Returns the number removed. */
async function purgeExpiredSessions() {
    await ensureAiTables();
    const res = await aiPool.query('DELETE FROM ai_sessions WHERE expires_at < NOW()');
    return res.rowCount;
}

// ── Messages ────────────────────────────────────────────────────────────────
async function getMessages(sessionId, limit = 12) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT * FROM (
            SELECT id, role, content, created_at FROM ai_messages
            WHERE session_id = $1 ORDER BY id DESC LIMIT $2
         ) t ORDER BY id ASC`,
        [sessionId, Math.min(limit, 50)]
    );
    return res.rows.map(r => ({ id: r.id, role: r.role, content: r.content, createdAt: r.created_at }));
}

async function addMessage(sessionId, role, content) {
    await ensureAiTables();
    const res = await aiPool.query(
        'INSERT INTO ai_messages (session_id, role, content) VALUES ($1,$2,$3) RETURNING *',
        [sessionId, role, String(content).slice(0, 12000)]
    );
    await aiPool.query('UPDATE ai_sessions SET message_count = message_count + 1 WHERE id = $1', [sessionId]);
    return res.rows[0];
}

/** Keep only the newest `keep` messages for a session. */
async function trimMessages(sessionId, keep = 24) {
    await ensureAiTables();
    await aiPool.query(
        `DELETE FROM ai_messages WHERE session_id = $1 AND id NOT IN (
            SELECT id FROM ai_messages WHERE session_id = $1 ORDER BY id DESC LIMIT $2
         )`,
        [sessionId, keep]
    );
}

async function clearSessionMessages(sessionId) {
    await ensureAiTables();
    await aiPool.query('DELETE FROM ai_messages WHERE session_id = $1', [sessionId]);
    await aiPool.query('UPDATE ai_sessions SET message_count = 0 WHERE id = $1', [sessionId]);
}

// ── Usage ───────────────────────────────────────────────────────────────────
async function incrementUsage(guildId, userId, { requests = 1, tokens = 0 } = {}) {
    await ensureAiTables();
    const res = await aiPool.query(
        `INSERT INTO ai_usage (guild_id, user_id, day, requests, tokens, updated_at)
         VALUES ($1,$2,CURRENT_DATE,$3,$4,NOW())
         ON CONFLICT (guild_id, user_id, day) DO UPDATE SET
            requests = ai_usage.requests + EXCLUDED.requests,
            tokens = ai_usage.tokens + EXCLUDED.tokens,
            updated_at = NOW()
         RETURNING *`,
        [guildId, userId, requests, tokens]
    );
    return res.rows[0];
}

async function getUsageToday(guildId, userId) {
    await ensureAiTables();
    const res = await aiPool.query(
        'SELECT * FROM ai_usage WHERE guild_id = $1 AND user_id = $2 AND day = CURRENT_DATE',
        [guildId, userId]
    );
    const row = res.rows[0];
    return { requests: Number(row?.requests) || 0, tokens: Number(row?.tokens) || 0 };
}

async function getGuildUsageToday(guildId) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT COALESCE(SUM(requests),0)::int AS requests, COALESCE(SUM(tokens),0)::int AS tokens
         FROM ai_usage WHERE guild_id = $1 AND day = CURRENT_DATE`,
        [guildId]
    );
    return { requests: Number(res.rows[0]?.requests) || 0, tokens: Number(res.rows[0]?.tokens) || 0 };
}

async function getUsageSeries(guildId, days = 14) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT day, SUM(requests)::int AS requests, SUM(tokens)::int AS tokens
         FROM ai_usage
         WHERE guild_id = $1 AND day >= CURRENT_DATE - ($2::int - 1)
         GROUP BY day ORDER BY day ASC`,
        [guildId, Math.max(1, Math.min(days, 90))]
    );
    return res.rows.map(r => ({
        day: r.day instanceof Date ? r.day.toISOString().slice(0, 10) : String(r.day),
        requests: Number(r.requests) || 0,
        tokens: Number(r.tokens) || 0,
    }));
}

async function getTopUsers(guildId, { days = 30, limit = 10 } = {}) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT user_id, SUM(requests)::int AS requests, SUM(tokens)::int AS tokens
         FROM ai_usage
         WHERE guild_id = $1 AND day >= CURRENT_DATE - ($2::int - 1)
         GROUP BY user_id ORDER BY requests DESC LIMIT $3`,
        [guildId, Math.max(1, Math.min(days, 90)), Math.min(limit, 50)]
    );
    return res.rows.map(r => ({ userId: r.user_id, requests: Number(r.requests) || 0, tokens: Number(r.tokens) || 0 }));
}

async function resetGuildUsage(guildId) {
    await ensureAiTables();
    const res = await aiPool.query('DELETE FROM ai_usage WHERE guild_id = $1', [guildId]);
    return res.rowCount;
}

// ── Knowledge ───────────────────────────────────────────────────────────────
async function listKnowledge(guildId, { limit = 50 } = {}) {
    await ensureAiTables();
    const res = await aiPool.query(
        `SELECT * FROM ai_knowledge WHERE guild_id = $1 ORDER BY updated_at DESC LIMIT $2`,
        [guildId, Math.min(limit, 100)]
    );
    return res.rows.map(r => ({
        id: r.id, guildId: r.guild_id, title: r.title, content: r.content,
        tags: r.tags, createdBy: r.created_by, createdAt: r.created_at, updatedAt: r.updated_at,
    }));
}

async function countKnowledge(guildId) {
    await ensureAiTables();
    const res = await aiPool.query('SELECT COUNT(*)::int AS n FROM ai_knowledge WHERE guild_id = $1', [guildId]);
    return Number(res.rows[0].n) || 0;
}

async function addKnowledge(guildId, { title, content, tags = '', createdBy = null }) {
    await ensureAiTables();
    const res = await aiPool.query(
        `INSERT INTO ai_knowledge (guild_id, title, content, tags, created_by)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [guildId, title, content, tags, createdBy]
    );
    return res.rows[0];
}

async function updateKnowledge(guildId, id, patch = {}) {
    await ensureAiTables();
    const res = await aiPool.query(
        `UPDATE ai_knowledge SET
            title = COALESCE($3, title),
            content = COALESCE($4, content),
            tags = COALESCE($5, tags),
            updated_at = NOW()
         WHERE guild_id = $1 AND id = $2 RETURNING *`,
        [guildId, id, patch.title ?? null, patch.content ?? null, patch.tags ?? null]
    );
    return res.rows[0] || null;
}

async function deleteKnowledge(guildId, id) {
    await ensureAiTables();
    const res = await aiPool.query('DELETE FROM ai_knowledge WHERE guild_id = $1 AND id = $2', [guildId, id]);
    return res.rowCount;
}

// ── Provider metadata (never keys) ──────────────────────────────────────────
async function getProviderMeta() {
    await ensureAiTables();
    const res = await aiPool.query('SELECT * FROM ai_provider_meta');
    return res.rows;
}

async function recordProviderResult(provider, { ok = false, error = null, cooldownUntil = null } = {}) {
    await ensureAiTables();
    await aiPool.query(
        `INSERT INTO ai_provider_meta (provider, last_ok_at, last_error_at, last_error, cooldown_until, requests, failures, updated_at)
         VALUES ($1, CASE WHEN $2 THEN NOW() END, CASE WHEN $2 THEN NULL ELSE NOW() END, $3, $4, 1, CASE WHEN $2 THEN 0 ELSE 1 END, NOW())
         ON CONFLICT (provider) DO UPDATE SET
            last_ok_at = CASE WHEN $2 THEN NOW() ELSE ai_provider_meta.last_ok_at END,
            last_error_at = CASE WHEN $2 THEN ai_provider_meta.last_error_at ELSE NOW() END,
            last_error = CASE WHEN $2 THEN ai_provider_meta.last_error ELSE $3 END,
            cooldown_until = COALESCE($4, ai_provider_meta.cooldown_until),
            requests = ai_provider_meta.requests + 1,
            failures = ai_provider_meta.failures + CASE WHEN $2 THEN 0 ELSE 1 END,
            updated_at = NOW()`,
        [provider, ok, error ? String(error).slice(0, 300) : null, cooldownUntil]
    );
}

module.exports = {
    ensureAiTables,
    rowToSettings, rowToSession,
    getAiSettings, getAllAiSettings, upsertAiSettings,
    getSession, createSession, touchSession, deleteSession, deleteGuildSessions,
    listSessions, countSessions, purgeExpiredSessions,
    getMessages, addMessage, trimMessages, clearSessionMessages,
    incrementUsage, getUsageToday, getGuildUsageToday, getUsageSeries, getTopUsers, resetGuildUsage,
    listKnowledge, countKnowledge, addKnowledge, updateKnowledge, deleteKnowledge,
    getProviderMeta, recordProviderResult,
};
