// Provider configuration: live model discovery, key hygiene, error classes and
// failover. No network, no database — `fetch` and the repo are stubbed.

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');

const SAVED = {};
for (const key of ['GROQ_API_KEY', 'GEMINI_API_KEY', 'OPENROUTER_API_KEY', 'AI_MODEL_GROQ',
    'AI_MODEL_GEMINI', 'AI_MODEL_OPENROUTER', 'AI_TIMEOUT_MS', 'OPENROUTER_KEY', 'GOOGLE_API_KEY']) {
    SAVED[key] = process.env[key];
}

function resetEnv() {
    for (const key of Object.keys(SAVED)) {
        if (SAVED[key] === undefined) delete process.env[key];
        else process.env[key] = SAVED[key];
    }
}

const freeModels = require('../utils/ai/freeModels');
const modelCatalog = require('../utils/ai/modelCatalog');
const providers = require('../utils/ai/providers');

let calls = [];
let routes = {};

function json(body, status = 200) {
    return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubFetch() {
    calls = [];
    global.fetch = async (url, opts) => {
        const target = String(url);
        calls.push({ url: target, opts });
        for (const [match, handler] of Object.entries(routes)) {
            if (target.includes(match)) return handler(target, opts);
        }
        return json({ error: { message: 'unexpected url' } }, 404);
    };
}

const isListCall = (url) => /\/models$/.test(url) || /v1beta\/models$/.test(url);

function chatCalls(host) {
    return calls.filter(c => c.url.includes(host) && !isListCall(c.url));
}

beforeEach(() => {
    resetEnv();
    modelCatalog.invalidate();
    routes = {};
    stubFetch();
});
afterEach(() => {
    resetEnv();
    modelCatalog.invalidate();
    delete global.fetch;
});

// ── Error classification ────────────────────────────────────────────────────
test('provider failures are classified into actionable kinds', () => {
    const { classify } = providers;
    const cases = [
        [401, { error: { message: 'Invalid API key' } }, 'auth'],
        [400, { error: { message: 'Missing Authentication header' } }, 'auth'],
        [400, { error: { message: 'The model `llama-3.3-70b-versatile` does not exist or you do not have access to it.' } }, 'invalid_model'],
        [400, { error: { message: 'This model models/gemini-2.0-flash is no longer available.' } }, 'invalid_model'],
        [404, { error: { message: 'not found' } }, 'invalid_model'],
        [402, {}, 'quota'],
        [429, { error: { message: 'You exceeded your current quota' } }, 'quota'],
        [429, { error: { message: 'Rate limit reached', retry_after: 12 } }, 'rate_limit'],
        [500, {}, 'server'],
        [400, { error: { message: 'messages must not be empty' } }, 'bad_request'],
    ];
    for (const [status, body, kind] of cases) {
        assert.equal(classify(status, body, null).kind, kind, `${status} ${body.error?.message}`);
    }
    assert.equal(classify(0, null, { name: 'TimeoutError', message: 'timed out' }).kind, 'timeout');
    assert.equal(classify(0, null, { message: 'fetch failed' }).kind, 'network');
});

// ── Keys ────────────────────────────────────────────────────────────────────
test('a missing or blank OpenRouter key means unconfigured, never an unauthenticated request', async () => {
    assert.equal(freeModels.providerConfigured('openrouter'), false);

    const res = await providers.callProvider('openrouter', { messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.ok, false);
    assert.equal(res.kind, 'config');
    assert.equal(chatCalls('openrouter').length, 0, 'no chat request without a key');

    process.env.OPENROUTER_API_KEY = '   ';
    assert.equal(freeModels.providerConfigured('openrouter'), false, 'whitespace is not a key');

    process.env.OPENROUTER_API_KEY = 'your-openrouter-key-here';
    assert.equal(freeModels.providerConfigured('openrouter'), false, 'placeholder is not a key');
});

test('a configured OpenRouter key is sent as a Bearer header', async () => {
    process.env.OPENROUTER_API_KEY = 'sk-or-v1-abcdefghijklmnop';
    routes['openrouter.ai/api/v1/chat/completions'] = () => json({
        choices: [{ message: { content: 'hello' } }],
        usage: { total_tokens: 3 },
    });
    const res = await providers.callProvider('openrouter', { messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.ok, true);
    const call = chatCalls('openrouter')[0];
    assert.equal(call.opts.headers.Authorization, 'Bearer sk-or-v1-abcdefghijklmnop');
    assert.ok(call.opts.headers['HTTP-Referer']);
});

test('key aliases and whitespace are handled (OPENROUTER_KEY, trailing newline)', () => {
    process.env.OPENROUTER_KEY = '  sk-or-v1-zzzzzzzzzzzz  \n';
    assert.equal(freeModels.readProviderKey('openrouter'), 'sk-or-v1-zzzzzzzzzzzz');
    assert.equal(freeModels.keySource('openrouter'), 'OPENROUTER_KEY');
    delete process.env.OPENROUTER_KEY;
    process.env.GOOGLE_API_KEY = 'AIzaSy_test_key_1234567890';
    assert.equal(freeModels.keySource('gemini'), 'GOOGLE_API_KEY');
});

// ── Model discovery ─────────────────────────────────────────────────────────
test('a retired Groq model override is replaced by a model the provider lists', async () => {
    process.env.GROQ_API_KEY = 'gsk_test_abcdefghijklmnop';
    process.env.AI_MODEL_GROQ = 'llama-3.3-70b-versatile';
    routes['api.groq.com/openai/v1/models'] = () => json({
        data: [{ id: 'openai/gpt-oss-120b' }, { id: 'llama-3.1-8b-instant' }, { id: 'whisper-large-v3' }],
    });

    await modelCatalog.discoverModels('groq', { force: true });
    assert.equal(modelCatalog.resolveModel('groq'), 'openai/gpt-oss-120b');
    assert.equal(modelCatalog.modelSource('groq'), 'discovered');
});

test('a retired Gemini model override is replaced and vision is decided per model', async () => {
    process.env.GEMINI_API_KEY = 'gm_test_abcdefghijklmnop';
    process.env.AI_MODEL_GEMINI = 'gemini-2.0-flash';
    routes['generativelanguage.googleapis.com/v1beta/models'] = () => json({
        models: [
            { name: 'models/gemini-2.5-flash', supportedGenerationMethods: ['generateContent'] },
            { name: 'models/gemini-2.5-flash-lite', supportedGenerationMethods: ['generateContent'] },
            { name: 'models/text-embedding-004', supportedGenerationMethods: ['embedContent'] },
        ],
    });

    await modelCatalog.discoverModels('gemini', { force: true });
    assert.equal(modelCatalog.resolveModel('gemini'), 'gemini-2.5-flash');
    assert.equal(modelCatalog.supportsVision('gemini', 'gemini-2.5-flash'), true);
    assert.equal(modelCatalog.supportsVision('gemini', 'gemini-2.5-flash-lite'), true);
    assert.equal(modelCatalog.supportsVision('gemini', 'text-embedding-004'), false);
});

test('OpenRouter discovery keeps only zero-priced text models', async () => {
    routes['openrouter.ai/api/v1/models'] = () => json({
        data: [
            { id: 'google/gemma-4-31b-it:free', pricing: { prompt: '0', completion: '0' }, architecture: { input_modalities: ['text', 'image'], output_modalities: ['text'] } },
            { id: 'openai/gpt-4o', pricing: { prompt: '0.000005', completion: '0.000015' }, architecture: { input_modalities: ['text'], output_modalities: ['text'] } },
            { id: 'google/lyria-3-pro-preview', pricing: { prompt: '0', completion: '0' }, architecture: { input_modalities: ['text'], output_modalities: ['audio'] } },
        ],
    });
    const result = await modelCatalog.discoverModels('openrouter', { force: true });
    assert.equal(result.ok, true);
    assert.deepEqual(result.models.map(m => m.id), ['google/gemma-4-31b-it:free']);
    assert.equal(modelCatalog.resolveModel('openrouter'), 'google/gemma-4-31b-it:free');
    assert.equal(modelCatalog.supportsVision('openrouter', 'google/gemma-4-31b-it:free'), true);
});

test('a paid OpenRouter override is ignored even when the model exists', () => {
    process.env.AI_MODEL_OPENROUTER = 'openai/gpt-4o';
    assert.equal(modelCatalog.resolveModel('openrouter'), 'google/gemma-4-31b-it:free');
});

test('discovery failure falls back to the built-in catalog instead of crashing', async () => {
    process.env.GROQ_API_KEY = 'gsk_test_abcdefghijklmnop';
    global.fetch = async () => { throw new Error('getaddrinfo ENOTFOUND'); };
    const result = await modelCatalog.discoverModels('groq', { force: true });
    assert.equal(result.ok, false);
    assert.match(result.error, /network/);
    assert.equal(modelCatalog.resolveModel('groq'), 'openai/gpt-oss-120b');
});

// ── Manager failover ────────────────────────────────────────────────────────
function makeRepoStub() {
    const state = {
        settings: new Map(),
        sessions: new Map(),
        messages: new Map(),
        usage: new Map(),
        guildUsage: new Map(),
        knowledge: [],
        meta: [],
        calls: { deleteSession: 0 },
        nextId: 1,
    };
    const repo = {
        ensureAiTables: async () => {},
        getAllAiSettings: async () => Array.from(state.settings.entries()).map(([guildId, settings]) => ({ guildId, settings })),
        getAiSettings: async (g) => state.settings.get(g) || { enabled: true, channelIds: [], roleIds: [] },
        upsertAiSettings: async (g, s) => { state.settings.set(g, s); return s; },
        getSession: async (g, u) => state.sessions.get(`${g}:${u}`) || null,
        createSession: async (g, u, channelId, ttl) => {
            const row = { id: state.nextId++, guildId: g, userId: u, channelId, messageCount: 0, createdAt: new Date(), expiresAt: new Date(Date.now() + (ttl || 60) * 60000) };
            state.sessions.set(`${g}:${u}`, row);
            state.messages.set(row.id, []);
            return row;
        },
        touchSession: async () => {},
        deleteSession: async (g, u) => { state.calls.deleteSession += 1; state.sessions.delete(`${g}:${u}`); },
        deleteGuildSessions: async () => 0,
        listSessions: async () => [],
        countSessions: async () => 0,
        purgeExpiredSessions: async () => 0,
        getMessages: async (id, limit) => (state.messages.get(id) || []).slice(-(limit || 50)),
        trimMessages: async () => {},
        addMessage: async (id, role, content) => {
            const list = state.messages.get(id) || [];
            list.push({ role, content });
            state.messages.set(id, list);
        },
        getUsage: async (g, u) => state.usage.get(`${g}:${u}`) || { requests: 0, tokens: 0 },
        getGuildUsage: async (g) => state.guildUsage.get(g) || { requests: 0, tokens: 0 },
        getUsageToday: async (g, u) => state.usage.get(`${g}:${u}`) || { requests: 0, tokens: 0 },
        getGuildUsageToday: async (g) => state.guildUsage.get(g) || { requests: 0, tokens: 0 },
        incrementUsage: async () => {},
        getUsageSeries: async () => [],
        getTopUsers: async () => [],
        listKnowledge: async () => state.knowledge,
        addKnowledge: async () => ({ id: 1 }),
        deleteKnowledge: async () => 1,
        getProviderMeta: async () => state.meta,
        recordProviderResult: async (provider, result) => { state.meta.push({ provider, ...result }); },
    };
    return { repo, state };
}

function loadManager(repoStub) {
    const repoPath = require.resolve('../server/aiRepo');
    const prev = require.cache[repoPath];
    require.cache[repoPath] = { id: repoPath, filename: repoPath, loaded: true, exports: repoStub };
    delete require.cache[require.resolve('../utils/ai/aiManager')];
    const { AiManager } = require('../utils/ai/aiManager');
    const manager = new AiManager(null);
    const restore = () => {
        manager.stop();
        if (prev) require.cache[repoPath] = prev;
        else delete require.cache[repoPath];
        delete require.cache[require.resolve('../utils/ai/aiManager')];
    };
    return { manager, restore };
}

function enabledSettings() {
    return {
        enabled: true, mode: 'mention', channelIds: [], roleIds: [],
        personality: 'balanced', customInstructions: '', language: 'auto',
        maxResponseChars: 1800, sessionTtlMinutes: 60, cooldownSeconds: 0,
        dailyUserRequests: 60, dailyGuildRequests: 600,
        knowledgeEnabled: true, visionEnabled: true, allowAttachments: true,
    };
}

async function managerWith(env) {
    Object.assign(process.env, env);
    const { repo, state } = makeRepoStub();
    state.settings.set('g1', enabledSettings());
    const loaded = loadManager(repo);
    await loaded.manager.ready();
    return { ...loaded, state };
}

test('an invalid model is rediscovered and retried once with the new model', async () => {
    const { manager, restore } = await managerWith({ GROQ_API_KEY: 'gsk_test_abcdefghijklmnop' });
    try {
        let refreshed = false;
        routes['api.groq.com/openai/v1/models'] = () => json({
            data: [{ id: refreshed ? 'llama-3.1-8b-instant' : 'openai/gpt-oss-120b' }],
        });
        routes['api.groq.com/openai/v1/chat/completions'] = (url, opts) => {
            const body = JSON.parse(opts.body);
            if (body.model === 'openai/gpt-oss-120b') {
                refreshed = true;
                return json({ error: { message: `The model \`${body.model}\` does not exist or you do not have access to it.` } }, 400);
            }
            return json({ choices: [{ message: { content: 'recovered' } }], usage: { total_tokens: 5 } });
        };
        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.ok, true);
        assert.equal(result.text, 'recovered');
        const chats = chatCalls('api.groq.com');
        assert.equal(chats.length, 2, 'one attempt per model, no loop');
        assert.equal(JSON.parse(chats[0].opts.body).model, 'openai/gpt-oss-120b');
        assert.equal(JSON.parse(chats[1].opts.body).model, 'llama-3.1-8b-instant',
            'the retry uses the model the refreshed catalog reports');
    } finally { restore(); }
});

test('an invalid model with no alternative disables the provider and falls through', async () => {
    const { manager, restore } = await managerWith({
        GROQ_API_KEY: 'gsk_test_abcdefghijklmnop',
        GEMINI_API_KEY: 'gm_test_abcdefghijklmnop',
    });
    try {
        routes['api.groq.com/openai/v1/models'] = () => json({ data: [{ id: 'openai/gpt-oss-120b' }] });
        routes['api.groq.com/openai/v1/chat/completions'] = () => json({ error: { message: 'model `openai/gpt-oss-120b` not found' } }, 404);
        routes['generativelanguage.googleapis.com'] = (url) => (url.includes(':generateContent')
            ? json({ candidates: [{ content: { parts: [{ text: 'gemini answer' }] } }] })
            : json({ models: [{ name: 'models/gemini-2.5-flash', supportedGenerationMethods: ['generateContent'] }] }));

        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.ok, true);
        assert.equal(result.provider, 'gemini');
        assert.equal(manager._disabled.get('groq'), 'model');

        const before = chatCalls('api.groq.com').length;
        await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'again' });
        assert.equal(chatCalls('api.groq.com').length, before, 'a disabled provider is not retried');
    } finally { restore(); }
});

test('an auth failure disables the provider and is reported as invalid_key', async () => {
    const { manager, restore } = await managerWith({
        GROQ_API_KEY: 'gsk_test_abcdefghijklmnop',
        GEMINI_API_KEY: 'gm_test_abcdefghijklmnop',
    });
    try {
        routes['api.groq.com/openai/v1/models'] = () => json({ data: [{ id: 'openai/gpt-oss-120b' }] });
        routes['api.groq.com/openai/v1/chat/completions'] = () => json({ error: { message: 'Missing Authentication header' } }, 401);
        routes['generativelanguage.googleapis.com'] = (url) => (url.includes(':generateContent')
            ? json({ candidates: [{ content: { parts: [{ text: 'ok' }] } }] })
            : json({ models: [{ name: 'models/gemini-2.5-flash', supportedGenerationMethods: ['generateContent'] }] }));

        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.provider, 'gemini');

        const status = await manager.getProviderStatus();
        const groq = status.find(p => p.provider === 'groq');
        assert.equal(groq.status, 'invalid_key');
        assert.equal(groq.disabledReason, 'auth');
        assert.ok(!JSON.stringify(status).includes('gsk_test_abcdefghijklmnop'), 'keys never appear in status');
    } finally { restore(); }
});

test('a free quota failure cools the provider down and reports rate_limited', async () => {
    const { manager, restore } = await managerWith({ GROQ_API_KEY: 'gsk_test_abcdefghijklmnop' });
    try {
        routes['api.groq.com/openai/v1/models'] = () => json({ data: [{ id: 'openai/gpt-oss-120b' }] });
        routes['api.groq.com/openai/v1/chat/completions'] = () => json({ error: { message: 'You exceeded your current quota' } }, 429);
        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'unavailable');
        const status = (await manager.getProviderStatus()).find(p => p.provider === 'groq');
        assert.equal(status.status, 'rate_limited');
        assert.ok(status.cooldownUntil);
    } finally { restore(); }
});

test('every provider failing returns one friendly message', async () => {
    const { manager, restore } = await managerWith({
        GROQ_API_KEY: 'gsk_test_abcdefghijklmnop',
        GEMINI_API_KEY: 'gm_test_abcdefghijklmnop',
        OPENROUTER_API_KEY: 'sk-or-v1-abcdefghijklmnop',
    });
    try {
        for (const host of ['api.groq.com', 'generativelanguage.googleapis.com', 'openrouter.ai']) {
            routes[host] = () => json({ error: { message: 'down' } }, 503);
        }
        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'unavailable');
        assert.match(result.message, /temporarily unavailable/i);
    } finally { restore(); }
});

test('only configured providers are contacted (missing keys are skipped)', async () => {
    const { manager, restore } = await managerWith({ GEMINI_API_KEY: 'gm_test_abcdefghijklmnop' });
    try {
        routes['generativelanguage.googleapis.com'] = (url) => (url.includes(':generateContent')
            ? json({ candidates: [{ content: { parts: [{ text: 'only gemini' }] } }] })
            : json({ models: [{ name: 'models/gemini-2.5-flash', supportedGenerationMethods: ['generateContent'] }] }));
        const result = await manager.chat({ guildId: 'g1', userId: 'u1', prompt: 'hi' });
        assert.equal(result.ok, true);
        assert.equal(result.provider, 'gemini');
        assert.equal(calls.filter(c => c.url.includes('groq')).length, 0);
        assert.equal(calls.filter(c => c.url.includes('openrouter')).length, 0);

        const status = await manager.getProviderStatus();
        assert.equal(status.find(p => p.provider === 'groq').status, 'unconfigured');
        assert.equal(status.find(p => p.provider === 'openrouter').status, 'unconfigured');
        assert.equal(status.find(p => p.provider === 'gemini').status, 'ok');
    } finally { restore(); }
});

// ── Surfaces ────────────────────────────────────────────────────────────────
test('mention, prefix and slash AI all run through the same manager', async () => {
    const { manager, restore } = await managerWith({ GROQ_API_KEY: 'gsk_test_abcdefghijklmnop' });
    try {
        routes['api.groq.com/openai/v1/models'] = () => json({ data: [{ id: 'openai/gpt-oss-120b' }] });
        routes['api.groq.com/openai/v1/chat/completions'] = () => json({
            choices: [{ message: { content: 'shared answer' } }], usage: { total_tokens: 4 },
        });

        const { handleAiMention } = require('../utils/ai/mentionHandler');
        const mentionReplies = [];
        const mentionMessage = {
            content: '<@1356575287151951943> hello there',
            author: { id: 'u1', bot: false, username: 'member' },
            member: { permissions: { has: () => false } },
            guild: { id: 'g1', name: 'Guild' },
            guildId: 'g1',
            channel: { id: 'c1', messages: { fetch: async () => new Map() } },
            channelId: 'c1',
            client: { user: { id: '1356575287151951943' }, aiManager: manager },
            mentions: { has: (u) => u.id === '1356575287151951943', users: new Map() },
            reply: async (payload) => { mentionReplies.push(payload); return { id: 'm1' }; },
        };
        const handled = await handleAiMention(mentionMessage.client, mentionMessage);
        assert.equal(handled, true);
        assert.equal(mentionReplies.length, 1);

        const { runAiAction } = require('../utils/ai/aiCommands');
        const prefixCtx = {
            manager, guildId: 'g1', guildName: 'Guild', channelId: 'c1',
            userId: 'u2', username: 'member2', member: null, isAdmin: false,
            prefix: '$', message: null, repliedMessage: null,
            fetchRecentMessages: async () => [],
        };
        const prefixReply = await runAiAction('ask', { question: 'hi' }, prefixCtx);
        assert.ok(prefixReply.embeds?.length || prefixReply.content, 'prefix produced a reply');

        const slash = require('../commands/ai');
        const edits = [];
        const interaction = {
            client: { aiManager: manager },
            guildId: 'g1',
            guild: { name: 'Guild' },
            channelId: 'c1',
            user: { id: 'u3', username: 'member3' },
            member: null,
            memberPermissions: { has: () => false },
            options: {
                getSubcommand: () => 'ask',
                getString: (name) => (name === 'question' ? 'hi' : null),
                getInteger: () => null,
                getBoolean: () => null,
                getAttachment: () => null,
                getChannel: () => null,
                getUser: () => null,
                getRole: () => null,
            },
            deferReply: async () => {},
            editReply: async (payload) => { edits.push(payload); },
            reply: async (payload) => { edits.push(payload); },
        };
        await slash.execute(interaction);
        assert.equal(edits.length, 1, 'slash command replied once');
    } finally { restore(); }
});
