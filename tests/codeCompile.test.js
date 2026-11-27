// Code Compile — Judge0 provider, language cache, service, limiter, view and
// the slash + prefix command wiring. Every provider response is mocked; the
// public API is never contacted.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Collection } = require('discord.js');

const ROOT = path.join(__dirname, '..');

const limits = require('../utils/compile/limits');
const { createJudge0Provider, Judge0Error } = require('../utils/compile/judge0Provider');
const {
    LanguageCatalog,
    TARGET_LANGUAGES,
    normalizeLanguageInput,
    resolveFromLanguages,
} = require('../utils/compile/languageCatalog');
const { CompileLimiter } = require('../utils/compile/compileLimiter');
const service = require('../utils/compile/compileService');
const view = require('../utils/compile/compileView');
const commandFlow = require('../utils/compile/compileCommand');
const { createCompileRuntime, setCompileRuntime, resetCompileRuntime } = require('../utils/compile/runtime');
const EmojiManager = require('../utils/emojiManager');

const b64 = text => Buffer.from(String(text), 'utf8').toString('base64');

// Judge0 CE language list (a trimmed copy of the real shape).
const LANGUAGES = [
    { id: 71, name: 'Python (3.8.1)' },
    { id: 63, name: 'JavaScript (Node.js 12.14.0)' },
    { id: 74, name: 'TypeScript (3.7.4)' },
    { id: 50, name: 'C (GCC 7.4.0)' },
    { id: 75, name: 'C (Clang 7.0.1)' },
    { id: 54, name: 'C++ (GCC 7.4.0)' },
    { id: 62, name: 'Java (OpenJDK 13.0.1)' },
    { id: 51, name: 'C# (Mono 6.6.0.161)' },
    { id: 60, name: 'Go (1.13.5)' },
    { id: 73, name: 'Rust (1.40.0)' },
    { id: 68, name: 'PHP (7.4.1)' },
    { id: 72, name: 'Ruby (2.7.0)' },
    { id: 78, name: 'Kotlin (1.3.70)' },
];

function submission(overrides = {}) {
    return {
        stdout: null,
        stderr: null,
        compile_output: null,
        message: null,
        exit_code: 0,
        time: '0.031',
        memory: 3200,
        status: { id: 3, description: 'Accepted' },
        ...overrides,
    };
}

/** A runtime whose provider replays `responses` (one per poll). */
function makeRuntime({
    languages = LANGUAGES,
    responses = [submission()],
    createError = null,
    getError = null,
    listError = null,
    config = {},
} = {}) {
    const calls = { list: 0, create: [], get: [] };
    const queue = [...responses];
    const provider = {
        name: 'fake',
        async listLanguages() {
            calls.list += 1;
            if (listError) throw listError;
            return languages;
        },
        async createSubmission(payload) {
            calls.create.push(payload);
            if (createError) throw createError;
            return { token: 'tok-abc' };
        },
        async getSubmission(token) {
            calls.get.push(token);
            if (getError) throw getError;
            return queue.length > 1 ? queue.shift() : queue[0];
        },
    };
    const catalog = new LanguageCatalog({
        provider,
        ttlMs: config.languageCacheTtlMs ?? 60_000,
        logger: { warn() {} },
    });
    const limiter = new CompileLimiter({ cooldownMs: 0, ...(config.limiter || {}) });
    const runtime = createCompileRuntime({
        provider,
        catalog,
        limiter,
        config: { pollIntervalMs: 100, pollDeadlineMs: 5000, ...config },
    });
    return { runtime, calls, catalog, limiter };
}

const noSleep = async () => {};

function payloadText(payload) {
    const container = (payload.components || [])[0] || {};
    return (container.components || []).map(c => c.content || '').join('\n');
}

// ── fenced blocks (the shape users actually paste) ───────────────────────
const { parseCompileArgs } = require('../utils/compile/compileCommand');

function parseMessage(content, prefix = '$') {
    const args = content.trim().split(/\s+/).slice(1);
    return parseCompileArgs(args, { prefix, raw: content, commandName: 'compile' });
}

test('a fenced block keeps its newlines and every line', () => {
    const content = [
        'compile nodejs ```const numbers = [10, 20, 30, 40, 50];',
        'const total = numbers.reduce((sum, n) => sum + n, 0);',
        'console.log("Total:", total);',
        'console.log("Average:", total / numbers.length);```',
    ].join('\n');

    const parsed = parseMessage(content);
    assert.equal(parsed.action, 'run');
    assert.equal(parsed.language, 'nodejs');
    assert.equal(parsed.stdin, '');
    assert.equal(parsed.code.split('\n').length, 4, 'all four lines survive');
    assert.ok(parsed.code.startsWith('const numbers = [10, 20, 30, 40, 50];'), 'the first line is code, not a language hint');
    assert.ok(parsed.code.endsWith('total / numbers.length);'));
    // The extracted program is valid JavaScript (it used to arrive mangled).
    assert.doesNotThrow(() => new Function(parsed.code));
});

test('indentation survives for indentation-sensitive languages', () => {
    const content = 'compile python ```def add(a, b):\n    return a + b\n\nprint(add(2, 3))```';
    const parsed = parseMessage(content);
    assert.equal(parsed.language, 'python');
    assert.equal(parsed.code, 'def add(a, b):\n    return a + b\n\nprint(add(2, 3))');
});

test('fenced parsing handles the info string, stdin blocks and inline forms', () => {
    // language inside the fence
    const hinted = parseMessage('compile ```python\nprint(1)```');
    assert.equal(hinted.language, 'python');
    assert.equal(hinted.code, 'print(1)');

    // code and stdin as two fenced blocks
    const withStdin = parseMessage('compile py ```print(input())``` ```7```');
    assert.equal(withStdin.language, 'py');
    assert.equal(withStdin.code, 'print(input())');
    assert.equal(withStdin.stdin, '7');

    // inline code + fenced stdin (previous behaviour, still supported)
    const inlineStdin = parseMessage('compile python print(1) ```5```');
    assert.equal(inlineStdin.code, 'print(1)');
    assert.equal(inlineStdin.stdin, '5');

    // single-line fence, no hint
    const inline = parseMessage('compile js ```console.log(1)```');
    assert.equal(inline.language, 'js');
    assert.equal(inline.code, 'console.log(1)');

    // plain inline form
    const plain = parseMessage('compile python print("hi")');
    assert.equal(plain.code, 'print("hi")');
});

test('the raw message is preferred over whitespace-split args', () => {
    const content = 'compile cpp ```int main() {\n  return 0;\n}```';
    const splitArgs = content.split(/\s+/).slice(1);
    const fromArgsOnly = parseCompileArgs(splitArgs, { prefix: '$' });
    assert.ok(!fromArgsOnly.code.includes('\n'), 'args alone cannot preserve newlines');

    const fromRaw = parseCompileArgs(splitArgs, { prefix: '$', raw: content, commandName: 'compile' });
    assert.ok(fromRaw.code.includes('\n'), 'raw content keeps the layout');
});


// ── nothing internal leaks into Discord ──────────────────────────────────
test('cards never expose the provider, its endpoint or the submission token', () => {
    const language = { key: 'python', label: 'Python', id: 71, name: 'Python (3.8.1)' };
    const result = service.normalizeSubmission(
        { ...submission({ stdout: b64('ok') }), token: 'TOPSECRET-SUBMISSION-TOKEN' },
        language,
        { maxOutputBytes: 10 * 1024, maxSectionChars: 3200 },
    );
    result.token = 'TOPSECRET-SUBMISSION-TOKEN';

    const payloads = [
        view.buildResultPayload(result),
        view.buildResultPayload({ ...result, kind: service.KINDS.RATE_LIMITED, error: { code: 'rate_limited', message: 'slow down' } }),
        view.buildResultPayload({ ...result, kind: service.KINDS.PROVIDER_ERROR, error: { code: 'provider_error', message: 'down' } }),
        view.buildProgressPayload({ stage: 'running', elapsedMs: 1200, language: 'Python' }),
        view.buildHelpPayload('$'),
        view.buildHelpPayload('/'),
        view.buildLanguagesPayload({ supported: [language], unsupported: [] }),
        view.buildLimitPayload({ reason: 'cooldown', message: 'Wait a moment.' }),
    ];

    for (const payload of payloads) {
        const text = payloadText(payload) + JSON.stringify(payload.components);
        assert.doesNotMatch(text, /TOPSECRET/i, 'the submission token is never rendered');
        assert.doesNotMatch(text, /judge0/i, 'the provider is never named');
        assert.doesNotMatch(text, /https?:\/\//i, 'no endpoint is rendered');
        assert.doesNotMatch(text, /api[ _-]?key/i, 'no key is ever mentioned');
        assert.doesNotMatch(text, /provider/i, 'no provider wording');
        assert.equal(payload.allowed_mentions?.parse?.length ?? 0, 0, 'no mentions are allowed');
    }
});

// ── provider ─────────────────────────────────────────────────────────────
test('provider lists languages, submits base64 code and reads base64 output', async () => {
    const seen = [];
    const fetchFn = async (url, init) => {
        seen.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : null });
        if (url.endsWith('/languages')) {
            return { ok: true, status: 200, json: async () => LANGUAGES };
        }
        if (url.includes('/submissions?') && init.method === 'POST') {
            return { ok: true, status: 201, json: async () => ({ token: 'abcd-1234' }) };
        }
        return { ok: true, status: 200, json: async () => submission({ stdout: b64('hi') }) };
    };

    const provider = createJudge0Provider({ baseUrl: 'https://ce.judge0.com', fetchFn });
    assert.equal(provider.baseUrl, 'https://ce.judge0.com');

    const languages = await provider.listLanguages();
    assert.equal(languages.length, LANGUAGES.length);

    const created = await provider.createSubmission({ sourceCode: 'print(1)', languageId: 71, stdin: '5' });
    assert.equal(created.token, 'abcd-1234');

    const post = seen.find(s => s.method === 'POST');
    assert.match(post.url, /\/submissions\?base64_encoded=true&wait=false$/);
    assert.equal(post.body.source_code, b64('print(1)'), 'source code is base64 encoded');
    assert.equal(post.body.stdin, b64('5'), 'stdin is base64 encoded');
    assert.equal(post.body.language_id, 71);

    const result = await provider.getSubmission('abcd-1234');
    assert.equal(result.status.id, 3);
    assert.match(seen.at(-1).url, /base64_encoded=true/);
});

test('provider classifies 429, 5xx, timeouts, bad JSON and bad tokens', async () => {
    const call = async (response, method = 'GET') => {
        const provider = createJudge0Provider({ baseUrl: 'https://ce.judge0.com', fetchFn: async () => response });
        try {
            await provider.listLanguages();
            return null;
        } catch (err) {
            return err;
        }
    };

    const limited = await call({ ok: false, status: 429, headers: { get: () => '7' } });
    assert.equal(limited.kind, 'rate_limited');
    assert.equal(limited.retryAfterMs, 7000);

    const server = await call({ ok: false, status: 503 });
    assert.equal(server.kind, 'provider_error');

    const aborted = await call({ json: async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); } });
    assert.equal(aborted.kind, 'invalid_response');

    const provider = createJudge0Provider({
        baseUrl: 'https://ce.judge0.com',
        fetchFn: async () => { throw Object.assign(new Error('boom'), { name: 'AbortError' }); },
    });
    await assert.rejects(provider.listLanguages(), err => err.kind === 'timeout');

    const netFail = createJudge0Provider({
        baseUrl: 'https://ce.judge0.com',
        fetchFn: async () => { throw new Error('ECONNRESET'); },
    });
    await assert.rejects(netFail.listLanguages(), err => err.kind === 'network');

    // A token that is not URL-safe never reaches the network.
    let touched = false;
    const guarded = createJudge0Provider({
        baseUrl: 'https://ce.judge0.com',
        fetchFn: async () => { touched = true; return { ok: true, status: 200, json: async () => ({}) }; },
    });
    await assert.rejects(guarded.getSubmission('../languages'), err => err.kind === 'invalid_token');
    assert.equal(touched, false);
});

test('provider rejects a submission response without a usable token', async () => {
    const provider = createJudge0Provider({
        baseUrl: 'https://ce.judge0.com',
        fetchFn: async () => ({ ok: true, status: 201, json: async () => ({}) }),
    });
    await assert.rejects(
        provider.createSubmission({ sourceCode: 'x', languageId: 71 }),
        err => err.kind === 'invalid_response',
    );
});

test('the default endpoint is the public Judge0 CE API and is configurable', () => {
    const { getCompileConfig } = require('../utils/compile/compileConfig');
    const previous = process.env.JUDGE0_API_URL;
    try {
        delete process.env.JUDGE0_API_URL;
        assert.equal(getCompileConfig().apiUrl, 'https://ce.judge0.com');
        process.env.JUDGE0_API_URL = 'https://judge0.example.test/';
        assert.equal(getCompileConfig().apiUrl, 'https://judge0.example.test');
        assert.equal(createJudge0Provider().baseUrl, 'https://judge0.example.test');
    } finally {
        if (previous === undefined) delete process.env.JUDGE0_API_URL;
        else process.env.JUDGE0_API_URL = previous;
    }
});

// ── language catalog ─────────────────────────────────────────────────────
test('language ids are resolved from the provider list, never hardcoded', () => {
    const snapshot = resolveFromLanguages(LANGUAGES);
    const byKey = Object.fromEntries(snapshot.supported.map(l => [l.key, l.id]));
    assert.deepEqual(byKey, {
        python: 71, javascript: 63, typescript: 74, c: 50, cpp: 54, java: 62,
        csharp: 51, go: 60, rust: 73, php: 68, ruby: 72, kotlin: 78,
    });
    assert.equal(snapshot.unsupported.length, 0);
    // C prefers GCC over Clang; C++ is never confused with C or C#.
    assert.equal(snapshot.byKey.get('c').name, 'C (GCC 7.4.0)');

    const source = fs.readFileSync(path.join(ROOT, 'utils', 'compile', 'languageCatalog.js'), 'utf8');
    assert.ok(!/language_id\s*:\s*\d/.test(source), 'no hardcoded language id');
});

test('language input accepts aliases and the cache refreshes on a TTL', async () => {
    assert.equal(normalizeLanguageInput('Node.js'), 'javascript');
    assert.equal(normalizeLanguageInput('JS'), 'javascript');
    assert.equal(normalizeLanguageInput('c++'), 'cpp');
    assert.equal(normalizeLanguageInput('C#'), 'csharp');
    assert.equal(normalizeLanguageInput('golang'), 'go');
    assert.equal(normalizeLanguageInput('brainfuck'), null);

    let clock = 0;
    const { runtime, calls } = makeRuntime({ config: { languageCacheTtlMs: 1000 } });
    runtime.catalog.now = () => clock;
    await runtime.catalog.load();
    await runtime.catalog.load();
    assert.equal(calls.list, 1, 'cached while fresh');
    clock = 5000;
    await runtime.catalog.load();
    assert.equal(calls.list, 2, 'refetched once stale');
});

test('a language the provider does not offer is reported as unsupported', async () => {
    const { runtime } = makeRuntime({ languages: [{ id: 71, name: 'Python (3.8.1)' }] });
    const result = await service.runCompilation({ language: 'rust', code: 'fn main(){}', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.UNSUPPORTED_LANGUAGE);
    assert.match(result.error.message, /not available/);

    const unknown = await service.runCompilation({ language: 'brainfuck', code: '++', runtime, sleep: noSleep });
    assert.equal(unknown.kind, service.KINDS.UNSUPPORTED_LANGUAGE);
});

// ── service outcomes ─────────────────────────────────────────────────────
test('successful compilation decodes stdout, exit code, time and memory', async () => {
    const { runtime, calls } = makeRuntime({
        responses: [submission({ stdout: b64('hello world\n'), exit_code: 0, time: '0.125', memory: 4096 })],
    });
    const result = await service.runCompilation({ language: 'python', code: 'print("hello world")', runtime, sleep: noSleep });

    assert.equal(result.kind, service.KINDS.SUCCESS);
    assert.equal(result.ok, true);
    assert.equal(result.stdout, 'hello world\n');
    assert.equal(result.exitCode, 0);
    assert.equal(result.timeMs, 125);
    assert.equal(result.memoryKb, 4096);
    assert.equal(result.language.name, 'Python (3.8.1)');
    assert.equal(calls.create.length, 1, 'submitted exactly once');
    assert.equal(calls.create[0].languageId, 71);
});

test('stdin is forwarded to the provider base64-encoded', async () => {
    const { runtime, calls } = makeRuntime({ responses: [submission({ stdout: b64('7') })] });
    await service.runCompilation({ language: 'python', code: 'print(3+4)', stdin: 'ignored', runtime, sleep: noSleep });
    assert.equal(calls.create[0].stdin, 'ignored');
});

test('a compilation error is reported with the compiler output', async () => {
    const { runtime } = makeRuntime({
        responses: [submission({
            status: { id: 6, description: 'Compilation Error' },
            compile_output: b64("main.cpp:1:1: error: expected ';'"),
            exit_code: 1,
        })],
    });
    const result = await service.runCompilation({ language: 'cpp', code: 'int main(){}', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.COMPILATION_ERROR);
    assert.equal(result.ok, false);
    assert.match(result.compileOutput, /expected ';'/);
    assert.equal(result.status.label, 'Compilation Error');

    const text = payloadText(view.buildResultPayload(result));
    assert.match(text, /Compilation failed/);
    assert.match(text, /Compiler output/);
    assert.match(text, /❌/, 'clc fallback emoji for a failure');
});

test('a runtime error is reported with stderr and a non-zero exit code', async () => {
    const { runtime } = makeRuntime({
        responses: [submission({
            status: { id: 11, description: 'Runtime Error (NZEC)' },
            stderr: b64('Traceback: ZeroDivisionError'),
            exit_code: 1,
        })],
    });
    const result = await service.runCompilation({ language: 'python', code: '1/0', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.RUNTIME_ERROR);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /ZeroDivisionError/);
    assert.match(payloadText(view.buildResultPayload(result)), /Runtime error/);
});

test('a time-limit-exceeded submission is its own outcome', async () => {
    const { runtime } = makeRuntime({ responses: [submission({ status: { id: 5, description: 'Time Limit Exceeded' } })] });
    const result = await service.runCompilation({ language: 'python', code: 'while True: pass', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.TIME_LIMIT);
    assert.match(payloadText(view.buildResultPayload(result)), /Time limit exceeded/);
});

test('polling stops at the terminal status and never re-submits', async () => {
    const { runtime, calls } = makeRuntime({
        responses: [
            submission({ status: { id: 2, description: 'Processing' } }),
            submission({ status: { id: 1, description: 'In Queue' } }),
            submission({ status: { id: 3, description: 'Accepted' }, stdout: b64('done') }),
        ],
    });
    const stages = [];
    const result = await service.runCompilation({
        language: 'go', code: 'package main', runtime, sleep: noSleep, onStage: s => stages.push(s),
    });
    assert.equal(result.kind, service.KINDS.SUCCESS);
    assert.equal(result.stdout, 'done');
    assert.equal(calls.get.length, 3, 'polled until terminal');
    assert.equal(calls.create.length, 1, 'submitted once');
    assert.deepEqual([...new Set(stages)], ['submitting', 'running', 'fetching']);
});

test('the polling deadline ends the wait with a timeout outcome', async () => {
    let clock = 0;
    const { runtime, calls } = makeRuntime({
        responses: [submission({ status: { id: 2, description: 'Processing' } })],
        config: { pollDeadlineMs: 5000 },
    });
    const result = await service.runCompilation({
        language: 'python', code: 'sleep()', runtime, sleep: noSleep, now: () => (clock += 1000),
    });
    assert.equal(result.kind, service.KINDS.TIMEOUT);
    assert.match(result.error.message, /did not finish/);
    assert.equal(calls.create.length, 1);
    assert.ok(calls.get.length >= 2);
});

test('invalid and oversized input is rejected before reaching the provider', async () => {
    const { runtime, calls } = makeRuntime();

    const noLanguage = await service.runCompilation({ language: '', code: 'x', runtime, sleep: noSleep });
    assert.equal(noLanguage.kind, service.KINDS.INVALID_INPUT);

    const noCode = await service.runCompilation({ language: 'python', code: '   ', runtime, sleep: noSleep });
    assert.equal(noCode.kind, service.KINDS.INVALID_INPUT);
    assert.match(noCode.error.message, /empty/);

    const bigCode = await service.runCompilation({ language: 'python', code: 'a'.repeat(15 * 1024 + 1), runtime, sleep: noSleep });
    assert.equal(bigCode.error.code, 'code_too_large');

    const bigStdin = await service.runCompilation({ language: 'python', code: 'x', stdin: 'b'.repeat(5 * 1024 + 1), runtime, sleep: noSleep });
    assert.equal(bigStdin.error.code, 'stdin_too_large');

    assert.equal(calls.create.length, 0, 'nothing was submitted');
});

test('long output is truncated to the 10 KB budget and flagged', () => {
    const huge = 'x'.repeat(20 * 1024);
    const result = service.normalizeSubmission(
        submission({ stdout: b64(huge), stderr: b64(huge) }),
        { key: 'python', label: 'Python', id: 71, name: 'Python (3.8.1)' },
        { maxOutputBytes: 10 * 1024, maxSectionChars: 3200 },
    );
    const total = limits.byteLength(result.stdout) + limits.byteLength(result.stderr);
    assert.ok(total <= 10 * 1024, `output kept to 10 KB (was ${total})`);
    assert.equal(result.truncated, true);
    assert.match(result.stdout, /\(truncated\)/);

    const text = payloadText(view.buildResultPayload(result));
    assert.match(text, /truncated to the 10 KB limit/);
    // Every TextDisplay must stay inside Discord's 4000-character cap.
    for (const child of view.buildResultPayload(result).components[0].components) {
        if (child.type === 10) assert.ok(child.content.length <= 4000);
    }
});

test('a base64 provider message is decoded and binary junk is dropped', () => {
    const language = { key: 'python', label: 'Python', id: 71, name: 'Python (3.8.1)' };
    const config = { maxOutputBytes: 10 * 1024, maxSectionChars: 3200 };

    const text = service.normalizeSubmission(
        submission({ status: { id: 6, description: 'Compilation Error' }, message: b64('Compilation error') }),
        language, config,
    );
    assert.equal(text.message, 'Compilation error');

    const junk = service.normalizeSubmission(
        submission({ status: { id: 13, description: 'Internal Error' }, message: Buffer.from([0, 1, 2, 3]).toString('base64') }),
        language, config,
    );
    assert.equal(junk.message, '', 'binary payloads are never rendered');
});

test('a malformed provider payload is reported instead of crashing', async () => {
    const { runtime } = makeRuntime({
        responses: [submission({ stdout: '!!! not base64 !!!' })],
    });
    const result = await service.runCompilation({ language: 'python', code: 'print(1)', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.PROVIDER_ERROR);
    assert.equal(result.error.code, 'malformed_response');

    const broken = await service.runCompilation({
        language: 'python',
        code: 'print(1)',
        runtime: makeRuntime({ getError: new Judge0Error('invalid_response', 'no status') }).runtime,
        sleep: noSleep,
    });
    assert.equal(broken.kind, service.KINDS.PROVIDER_ERROR);

    const emptyList = await service.runCompilation({
        language: 'python',
        code: 'print(1)',
        runtime: makeRuntime({ listError: new Judge0Error('invalid_response', 'not an array') }).runtime,
        sleep: noSleep,
    });
    assert.equal(emptyList.kind, service.KINDS.PROVIDER_ERROR);
});

test('HTTP 429 from the provider surfaces as a rate-limit result', async () => {
    const { runtime } = makeRuntime({
        createError: new Judge0Error('rate_limited', 'slow down', { status: 429, retryAfterMs: 3000 }),
    });
    const result = await service.runCompilation({ language: 'python', code: 'print(1)', runtime, sleep: noSleep });
    assert.equal(result.kind, service.KINDS.RATE_LIMITED);
    assert.match(result.error.message, /rate-limiting/);
    const text = payloadText(view.buildResultPayload(result));
    assert.match(text, /Rate limited/);
    assert.match(text, /❌/);
});

test('a provider network failure never leaks internals to the user', async () => {
    const { runtime } = makeRuntime({ getError: new Judge0Error('network', 'ECONNREFUSED 10.0.0.1:443') });
    const result = await service.runCompilation({ language: 'python', code: 'print(1)', runtime, sleep: noSleep });
    const text = payloadText(view.buildResultPayload(result));
    assert.match(text, /Could not reach the execution service/);
    assert.ok(!text.includes('ECONNREFUSED'), 'no internal detail');
    assert.ok(!text.includes('10.0.0.1'), 'no internal address');
});

// ── limiter ──────────────────────────────────────────────────────────────
test('the limiter enforces a per-user cooldown', () => {
    const limiter = new CompileLimiter({ cooldownMs: 10000 });
    const first = limiter.acquire({ userId: 'u1', guildId: 'g1', now: 1000 });
    assert.equal(first.ok, true);
    first.release();

    const second = limiter.acquire({ userId: 'u1', guildId: 'g1', now: 4000 });
    assert.equal(second.ok, false);
    assert.equal(second.reason, 'cooldown');
    assert.equal(second.retryAfterMs, 7000);

    assert.equal(limiter.acquire({ userId: 'u1', guildId: 'g1', now: 11001 }).ok, true);
});

test('the limiter caps concurrency and per-window requests per user and guild', () => {
    const limiter = new CompileLimiter({
        cooldownMs: 0, userConcurrent: 1, guildConcurrent: 2, userRateLimit: 3, guildRateLimit: 4, rateWindowMs: 60000,
    });
    const held = limiter.acquire({ userId: 'u1', guildId: 'g1', now: 0 });
    assert.equal(held.ok, true);
    const concurrent = limiter.acquire({ userId: 'u1', guildId: 'g1', now: 1 });
    assert.equal(concurrent.ok, false);
    assert.equal(concurrent.reason, 'concurrency');
    held.release();

    const guildBusy = [limiter.acquire({ userId: 'a', guildId: 'g1', now: 2 }), limiter.acquire({ userId: 'b', guildId: 'g1', now: 3 })];
    assert.ok(guildBusy.every(r => r.ok));
    const guildFull = limiter.acquire({ userId: 'c', guildId: 'g1', now: 4 });
    assert.equal(guildFull.ok, false);
    assert.equal(guildFull.reason, 'concurrency');
    guildBusy.forEach(r => r.release());

    const hits = [];
    for (let i = 0; i < 4; i++) {
        const attempt = limiter.acquire({ userId: 'd', guildId: 'g2', now: 10 + i });
        if (attempt.ok) attempt.release();
        hits.push(attempt);
    }
    assert.ok(hits.slice(0, 3).every(r => r.ok));
    assert.equal(hits[3].ok, false);
    assert.equal(hits[3].reason, 'rate_limit');
});

test('a cooldown rejection renders a limit card and never calls the provider', async () => {
    const { runtime, calls } = makeRuntime({ config: { cooldownMs: 60000, limiter: { cooldownMs: 60000 } } });
    const edits = [];
    const edit = async payload => { edits.push(payload); };

    const first = await commandFlow.runCompileRequest({
        userId: 'u1', guildId: 'g1', language: 'python', code: 'print(1)', edit, runtime, now: () => 1000, sleep: noSleep,
    });
    assert.equal(first.kind, service.KINDS.SUCCESS);

    const second = await commandFlow.runCompileRequest({
        userId: 'u1', guildId: 'g1', language: 'python', code: 'print(2)', edit, runtime, now: () => 2000, sleep: noSleep,
    });
    assert.equal(second.kind, 'rate_limited');
    assert.equal(second.reason, 'cooldown');
    assert.equal(calls.create.length, 1, 'the second request never reached the provider');
    assert.match(payloadText(edits.at(-1)), /Slow down a little/);
});

// ── view / emoji ─────────────────────────────────────────────────────────
test('the progress card uses the prc application emoji, with a Unicode fallback', async () => {
    const fallback = payloadText(view.buildProgressPayload({ stage: 'running', elapsedMs: 0 }));
    assert.match(fallback, /⏳/);
    assert.match(fallback, /Compiling and running/);

    globalThis.__primebotEmojiManager = {
        emoji: (name, fb) => (name === 'prc' ? '<:prc:900000000000000001>' : fb),
    };
    try {
        const custom = payloadText(view.buildProgressPayload({ stage: 'submitting' }));
        assert.match(custom, /<:prc:900000000000000001>/, 'custom emoji wins when available');
    } finally {
        delete globalThis.__primebotEmojiManager;
    }

    const result = await (async () => {
        const { runtime } = makeRuntime();
        return service.runCompilation({ language: 'python', code: 'print(1)', runtime, sleep: noSleep });
    })();
    globalThis.__primebotEmojiManager = {
        emoji: (name, fb) => (name === 'crc' ? '<:crc:900000000000000002>' : (name === 'clc' ? '<:clc:900000000000000003>' : fb)),
    };
    try {
        assert.match(payloadText(view.buildResultPayload(result)), /<:crc:900000000000000002>/);
    } finally {
        delete globalThis.__primebotEmojiManager;
    }
});

test('EmojiManager discovers application emojis without hardcoded ids', async () => {
    const appEmojis = new Collection();
    for (const [id, name] of [['900000000000000001', 'prc'], ['900000000000000002', 'crc'], ['900000000000000003', 'clc']]) {
        appEmojis.set(id, { id, name, animated: false, available: true });
    }
    const emptyGuild = id => ({
        id,
        available: true,
        emojis: { cache: new Collection(), fetch: async () => new Collection() },
        channels: { cache: new Collection(), fetch: async () => new Collection() },
    });
    const guilds = new Collection();
    const { DEFAULT_EMOJI_GUILDS } = require('../shared/emojiCatalog');
    for (const id of DEFAULT_EMOJI_GUILDS) guilds.set(id, emptyGuild(id));

    const manager = new EmojiManager({ global: false });
    manager.client = {
        guilds: { cache: guilds, fetch: async id => guilds.get(id) || null },
        application: { emojis: { cache: appEmojis, fetch: async () => appEmojis } },
        on() {},
    };
    await manager.refresh({ force: true });

    assert.equal(manager.emoji('prc'), '<:prc:900000000000000001>');
    assert.equal(manager.emoji('crc'), '<:crc:900000000000000002>');
    assert.equal(manager.emoji('clc'), '<:clc:900000000000000003>');
    assert.equal(EmojiManager.fallbackFor('prc'), '⏳');
    assert.equal(EmojiManager.fallbackFor('crc'), '✅');
    assert.equal(EmojiManager.fallbackFor('clc'), '❌');
});

test('help and languages cards render their real content', () => {
    const help = payloadText(view.buildHelpPayload('$'));
    assert.match(help, /Code Compile/);
    assert.match(help, /\$compile/);
    assert.match(help, /15 KB/);
    assert.match(help, /not guaranteed/);

    const languages = payloadText(view.buildLanguagesPayload(resolveFromLanguages(LANGUAGES)));
    assert.match(languages, /Python \(3\.8\.1\)/);
    assert.match(languages, /id `71`/);
    assert.match(languages, /never hardcoded|nothing is hardcoded/i);
});

// ── slash command ────────────────────────────────────────────────────────
const slashCommand = require('../commands/compile');

function fakeInteraction({ sub = 'run', language = 'python', code = 'print(1)', stdin = null } = {}) {
    const state = { deferred: false, replies: [], edits: [], responded: null };
    return {
        state,
        interaction: {
            user: { id: 'u1' },
            guildId: 'g1',
            options: {
                getSubcommand: () => sub,
                getString: name => ({ language, code, stdin }[name] ?? null),
                getFocused: () => ({ name: 'language', value: 'py' }),
            },
            async deferReply() { state.deferred = true; },
            async editReply(payload) { state.edits.push(payload); return payload; },
            async reply(payload) { state.replies.push(payload); return payload; },
            async respond(choices) { state.responded = choices; return choices; },
        },
    };
}

test('/compile declares run, languages and help with the right options', () => {
    const json = slashCommand.data.toJSON();
    assert.equal(json.name, 'compile');
    const subs = Object.fromEntries(json.options.map(o => [o.name, o]));
    assert.deepEqual(Object.keys(subs).sort(), ['help', 'languages', 'run']);

    const run = Object.fromEntries(subs.run.options.map(o => [o.name, o]));
    assert.equal(run.language.required, true);
    assert.equal(run.code.required, true);
    assert.ok(!run.stdin.required, 'stdin is optional');
    assert.equal(slashCommand.data.name, 'compile');
    assert.equal(typeof slashCommand.execute, 'function');
    assert.equal(typeof slashCommand.autocomplete, 'function');
});

test('/compile run defers immediately and renders the result', async () => {
    const { runtime, calls } = makeRuntime({ responses: [submission({ stdout: b64('42\n') })] });
    setCompileRuntime(runtime);
    try {
        const { interaction, state } = fakeInteraction();
        await slashCommand.execute(interaction);
        assert.equal(state.deferred, true);
        assert.equal(calls.create.length, 1);
        const text = payloadText(state.edits.at(-1));
        assert.match(text, /Compilation succeeded/);
        assert.match(text, /42/);
    } finally {
        resetCompileRuntime();
    }
});

test('/compile languages and /compile help answer without submitting', async () => {
    const { runtime, calls } = makeRuntime();
    setCompileRuntime(runtime);
    try {
        const languages = fakeInteraction({ sub: 'languages' });
        await slashCommand.execute(languages.interaction);
        assert.equal(languages.state.deferred, true);
        assert.match(payloadText(languages.state.edits[0]), /Supported languages/);

        const help = fakeInteraction({ sub: 'help' });
        await slashCommand.execute(help.interaction);
        assert.equal(help.state.deferred, false);
        assert.match(payloadText(help.state.replies[0]), /Code Compile/);
        assert.equal(calls.create.length, 0);
    } finally {
        resetCompileRuntime();
    }
});

test('/compile autocompletes the language option from the catalog', async () => {
    const { runtime } = makeRuntime();
    setCompileRuntime(runtime);
    try {
        const { interaction, state } = fakeInteraction();
        await slashCommand.autocomplete(interaction);
        assert.ok(Array.isArray(state.responded));
        assert.ok(state.responded.some(choice => choice.value === 'python'));
    } finally {
        resetCompileRuntime();
    }
});

// ── prefix command (real messageCreate handler) ──────────────────────────
function runPrefix(content, { runtime } = {}) {
    global.botActive = true;
    setCompileRuntime(runtime);
    const mcPath = require.resolve('../events/messageCreate');
    delete require.cache[mcPath];
    const mc = require(mcPath);

    const replies = [];
    const edits = [];
    const channel = { id: 'c1', isTextBased: () => true, permissionsFor: () => ({ has: () => true }) };
    const message = {
        content,
        guild: { id: 'g1', name: 'Test', members: { me: { id: 'bot' } }, channels: { cache: { get: () => channel } } },
        channel,
        member: { permissions: { has: () => true } },
        author: { id: 'u1', tag: 'u#0001', bot: false },
        mentions: { channels: { first: () => null } },
        reply: async payload => {
            replies.push(payload);
            return { id: 'm1', edit: async next => { edits.push(next); return next; } };
        },
    };
    const client = {
        user: { id: 'bot', displayAvatarURL: () => '' },
        commands: new Map(),
        serverSettingsManager: { getGuildPrefix: () => '$' },
    };
    return mc.execute(message, client).then(() => ({ replies, edits }));
}

test('$compile runs a snippet through the real prefix handler', async () => {
    const { runtime, calls } = makeRuntime({ responses: [submission({ stdout: b64('hi there') })] });
    try {
        const { replies, edits } = await runPrefix('$compile python print("hi there")', { runtime });
        assert.equal(calls.create.length, 1);
        assert.equal(calls.create[0].languageId, 71);
        assert.match(payloadText(replies[0]), /⏳/, 'prc shown immediately');
        assert.match(payloadText(edits.at(-1)), /✅/);
        assert.match(payloadText(edits.at(-1)), /hi there/);
    } finally {
        resetCompileRuntime();
    }
});

test('$compile accepts a fenced code block and a second block as stdin', async () => {
    const { runtime, calls } = makeRuntime({ responses: [submission({ stdout: b64('5') })] });
    try {
        const { edits } = await runPrefix('$compile python ```py\nprint(input())\n``` ```\n5\n```', { runtime });
        assert.equal(calls.create[0].stdin, '5');
        assert.match(calls.create[0].sourceCode, /print\(input\(\)\)/);
        assert.match(payloadText(edits.at(-1)), /Compilation succeeded/);
    } finally {
        resetCompileRuntime();
    }
});

test('$compile help and $compile languages answer without submitting', async () => {
    const { runtime, calls } = makeRuntime();
    try {
        const help = await runPrefix('$compile help', { runtime });
        assert.match(payloadText(help.replies[0]), /Code Compile/);
        assert.match(payloadText(help.replies[0]), /\$compile/);

        const languages = await runPrefix('$compile languages', { runtime });
        assert.match(payloadText(languages.replies[0]), /Supported languages/);

        assert.equal(calls.create.length, 0);
    } finally {
        resetCompileRuntime();
    }
});

test('$compile surfaces a compilation error with the failure emoji', async () => {
    const { runtime } = makeRuntime({
        responses: [submission({ status: { id: 6, description: 'Compilation Error' }, compile_output: b64('error: bad') })],
    });
    try {
        const { edits } = await runPrefix('$compile c int main(){', { runtime });
        const text = payloadText(edits.at(-1));
        assert.match(text, /❌/);
        assert.match(text, /Compilation failed/);
        assert.match(text, /error: bad/);
    } finally {
        resetCompileRuntime();
    }
});

test('$compile reports a provider outage without crashing the handler', async () => {
    const { runtime } = makeRuntime({ createError: new Judge0Error('provider_error', 'boom', { status: 502 }) });
    try {
        const { edits } = await runPrefix('$compile python print(1)', { runtime });
        assert.match(payloadText(edits.at(-1)), /Execution unavailable/);
    } finally {
        resetCompileRuntime();
    }
});

// ── wiring / catalog ─────────────────────────────────────────────────────
test('the command is wired into deploy-commands, the prefix switch and the help catalog', () => {
    assert.ok(fs.existsSync(path.join(ROOT, 'commands', 'compile.js')), 'slash command file exists');

    const deploy = fs.readFileSync(path.join(ROOT, 'deploy-commands.js'), 'utf8');
    assert.match(deploy, /readdirSync\(commandsPath\)/, 'commands/ is auto-registered');

    const messageCreate = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    assert.match(messageCreate, /case "compile": \{/);
    assert.match(messageCreate, /parseCompileArgs\(args, \{ prefix, raw: message\.content, commandName \}\)/);
    assert.match(messageCreate, /runCompileRequest\(/);
    // Linix music routing is untouched: the default branch still delegates.
    assert.match(messageCreate, /require\('\.\.\/music\/prefixRunner'\)/);

    const { CATALOG, CATEGORY_ORDER, categoryEmbed } = require('../utils/prefixHelp');
    assert.ok(CATEGORY_ORDER.includes('developer'));
    const names = CATALOG.developer.commands.flatMap(c => c.names);
    assert.ok(names.includes('compile'));
    assert.match(categoryEmbed('developer', '$').data.description, /`compile`/);

    const { buildCommandDocs } = require('../dashboard/commandDocs');
    const docs = buildCommandDocs();
    const entry = docs.commands.find(c => c.name === 'compile');
    assert.ok(entry, 'compile appears in /docs');
    assert.equal(entry.category, 'Utility');
    assert.match(entry.description, /Judge0/);
});

test('the compile module never executes code locally', () => {
    const files = fs.readdirSync(path.join(ROOT, 'utils', 'compile'))
        .filter(f => f.endsWith('.js'))
        .map(f => fs.readFileSync(path.join(ROOT, 'utils', 'compile', f), 'utf8'))
        .join('\n');
    for (const forbidden of ['child_process', 'execSync', 'spawnSync', 'vm.runInNewContext', 'eval(']) {
        assert.ok(!files.includes(forbidden), `compile subsystem must not use ${forbidden}`);
    }
    assert.ok(TARGET_LANGUAGES.length >= 12);
});
