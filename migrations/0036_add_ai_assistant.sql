-- AI Assistant (AI_DATABASE_URL, falls back to FALLBACK_DATABASE_URL/DATABASE_URL).
-- Idempotent: the bot's AiManager and the dashboard's repo self-create the same
-- tables on first use, so this migration is only needed for a managed schema.
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

-- Non-secret provider health only. API keys are environment variables and are
-- never stored in the database.
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
