/**
 * Discord presentation for the Code Compile feature.
 *
 * Every payload is a Components V2 card (no embeds, no content) so the result
 * reads as one PrimeBot card on both desktop and mobile. Status emojis come
 * from the central EmojiManager (`prc` / `crc` / `clc`) with Unicode fallbacks.
 */

const {
    ContainerBuilder,
    SeparatorBuilder,
    TextDisplayBuilder,
    MessageFlags,
} = require('discord.js');
const config = require('../../config');
const { EMOJI_FALLBACKS } = require('../../shared/emojiCatalog');
const { emoji } = require('../emoji');
const { codeBlock, truncateText } = require('./limits');
const { KINDS } = require('./compileService');
const { TARGET_LANGUAGES } = require('./languageCatalog');

// Application emoji names. Resolved through EmojiManager; never hardcoded ids.
const EMOJI_PROGRESS = 'prc';
const EMOJI_SUCCESS = 'crc';
const EMOJI_FAILURE = 'clc';

const MAX_TEXT_CHARS = 4000;
const API_NOTE = 'shared public Judge0 CE API — availability is not guaranteed';

function resolveEmoji(name) {
    return emoji(name, EMOJI_FALLBACKS[name] || '');
}

function statusEmoji(kind) {
    return resolveEmoji(kind === KINDS.SUCCESS ? EMOJI_SUCCESS : EMOJI_FAILURE);
}

function textDisplay(content) {
    const value = truncateText(content, { maxChars: MAX_TEXT_CHARS - 16 });
    return value.trim() ? new TextDisplayBuilder().setContent(value) : null;
}

function separator() {
    return new SeparatorBuilder().setDivider(true);
}

function buildPayload(children) {
    const container = new ContainerBuilder();
    for (const child of children.flat().filter(Boolean)) {
        if (typeof child === 'string') {
            const display = textDisplay(child);
            if (display) container.addTextDisplayComponents(display);
            continue;
        }
        const type = child && (child.data ? child.data.type : child.type);
        if (type === 14) container.addSeparatorComponents(child);
        else if (type === 10) container.addTextDisplayComponents(child);
    }
    return {
        components: [container.toJSON()],
        flags: MessageFlags.IsComponentsV2,
        allowedMentions: { parse: [] },
    };
}

function elapsedLabel(ms) {
    return `${(Math.max(0, ms) / 1000).toFixed(1)}s`;
}

function formatTime(ms) {
    if (ms == null) return '—';
    if (ms < 1000) return `${ms} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}

function formatMemory(kb) {
    if (kb == null) return '—';
    return kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`;
}

function footer(extra = '') {
    const parts = ['PrimeBot', extra, API_NOTE, `v${config.version}`].filter(Boolean);
    return `-# ${parts.join(' • ')}`;
}

// ── progress ──────────────────────────────────────────────────────────────
const STAGE_LINES = Object.freeze({
    preparing: 'Preparing',
    submitting: 'Submitting your code',
    running: 'Compiling and running',
    fetching: 'Fetching results',
});

/** The `prc` status card, re-rendered while the submission is in flight. */
function buildProgressPayload({ stage = 'submitting', elapsedMs = 0, language = null } = {}) {
    const mark = resolveEmoji(EMOJI_PROGRESS);
    const dots = '.'.repeat(1 + (Math.floor(Math.max(0, elapsedMs) / 700) % 3));
    const line = `${mark} **${STAGE_LINES[stage] || 'Compiling'}${dots}**`;
    const meta = [
        language ? `Language: \`${language}\`` : null,
        `Elapsed: ${elapsedLabel(elapsedMs)}`,
    ].filter(Boolean).join(' • ');
    return buildPayload([line, `-# ${meta}`]);
}

// ── result ────────────────────────────────────────────────────────────────
const HEADLINES = Object.freeze({
    [KINDS.SUCCESS]: 'Compilation succeeded',
    [KINDS.COMPILATION_ERROR]: 'Compilation failed',
    [KINDS.RUNTIME_ERROR]: 'Runtime error',
    [KINDS.WRONG_ANSWER]: 'Wrong answer',
    [KINDS.TIME_LIMIT]: 'Time limit exceeded',
    [KINDS.TIMEOUT]: 'Execution timed out',
    [KINDS.PROVIDER_ERROR]: 'Provider error',
    [KINDS.RATE_LIMITED]: 'Provider rate limit',
    [KINDS.UNSUPPORTED_LANGUAGE]: 'Unsupported language',
    [KINDS.INVALID_INPUT]: 'Invalid request',
});

function metaLine(result) {
    const language = result.language ? result.language.name : '—';
    const parts = [
        `**Language** \`${language}\``,
        `**Status** \`${result.status?.label || '—'}\``,
        `**Exit code** \`${result.exitCode == null ? '—' : result.exitCode}\``,
        `**Time** \`${formatTime(result.timeMs)}\``,
        `**Memory** \`${formatMemory(result.memoryKb)}\``,
    ];
    return parts.join(' • ');
}

function section(title, body) {
    return `**${title}**\n${codeBlock(body)}`;
}

function buildResultPayload(result) {
    const mark = statusEmoji(result.kind);
    const children = [`${mark} **${HEADLINES[result.kind] || 'Compilation finished'}**`, metaLine(result)];

    const compileOutput = (result.compileOutput || '').trim();
    const stderr = (result.stderr || '').trim();
    const stdout = (result.stdout || '').trim();

    if (compileOutput) children.push(section('Compiler output', result.compileOutput));
    if (stderr) children.push(section('Standard error', result.stderr));
    if (stdout) children.push(section('Standard output', result.stdout));
    if (!compileOutput && !stderr && !stdout) {
        children.push(result.kind === KINDS.SUCCESS ? '-# No output.' : '-# No output was produced.');
    }

    if (result.message && result.kind !== KINDS.SUCCESS) {
        children.push(`-# ${truncateText(result.message, { maxChars: 300 })}`);
    }
    if (result.error && result.error.message) {
        children.push(`-# ${truncateText(result.error.message, { maxChars: 400 })}`);
    }
    if (result.truncated) {
        children.push('-# Output was truncated to the 10 KB limit.');
    }

    children.push(separator(), footer());
    return buildPayload(children);
}

// ── notices (limits, validation, provider availability) ───────────────────
function buildNoticePayload({ title, body = '', emojiKey = EMOJI_FAILURE, hint = null } = {}) {
    const mark = resolveEmoji(emojiKey);
    const children = [`${mark} **${title}**`];
    if (body) children.push(body);
    if (hint) children.push(`-# ${hint}`);
    children.push(separator(), footer());
    return buildPayload(children);
}

/** Rendered when the local limiter rejects a request (cooldown / rate limit). */
function buildLimitPayload(gate) {
    return buildNoticePayload({
        title: gate.reason === 'cooldown' ? 'Slow down a little' : 'Compile limit reached',
        body: gate.message || 'Please wait a moment before compiling again.',
        emojiKey: EMOJI_FAILURE,
    });
}

// ── help ──────────────────────────────────────────────────────────────────
function buildHelpPayload(prefix = '/') {
    const languages = TARGET_LANGUAGES.map(l => l.key).join('`, `');
    const usage = prefix === '/'
        ? [
            '`/compile run language:<language> code:<your code> [stdin:<input>]` — run a snippet',
            '`/compile languages` — supported languages and their provider ids',
            '`/compile help` — this card',
        ]
        : [
            `\`${prefix}compile <language> <code>\` — run a snippet (a fenced block also works)`,
            `\`${prefix}compile <language> <code> <stdin>\` — program input from a second fenced block`,
            `\`${prefix}compile languages\` — supported languages`,
            `\`${prefix}compile help\` — this card`,
        ];
    const lines = [
        '**Code Compile** — compile and run code on Judge0 CE',
        '',
        `**Usage**`,
        usage.join('\n'),
        '',
        '**Languages**',
        `\`${languages}\``,
        '',
        '**Limits**',
        'Source code 15 KB • program input 5 KB • returned output 10 KB\n'
            + 'One compile at a time per member, plus a short cooldown and rate limits per member and server.',
        '',
        '**Notes**',
        'Code runs on a shared public API — availability and queue times are not guaranteed.\n'
            + 'PrimeBot never executes submitted code on its own host.',
    ];
    return buildPayload(lines.map(line => (line === '' ? '\u200b' : line)).concat([separator(), footer()]));
}

// ── languages ─────────────────────────────────────────────────────────────
function buildLanguagesPayload(snapshot, { error = null } = {}) {
    const supported = (snapshot && snapshot.supported) || [];
    const unsupported = (snapshot && snapshot.unsupported) || [];

    const children = ['**Supported languages**'];
    if (supported.length) {
        children.push(supported
            .map(l => `\`${l.label}\` — id \`${l.id}\` (\`${l.name}\`)`)
            .join('\n'));
    } else {
        children.push('-# The language list could not be loaded from the provider.');
    }
    if (unsupported.length) {
        children.push(`-# Currently unavailable on the provider: ${unsupported.map(l => l.label).join(', ')}`);
    }
    if (error) children.push(`-# ${error}`);
    children.push(
        `-# Language ids are fetched from the provider's \`/languages\` endpoint and cached; nothing is hardcoded.`,
        separator(),
        footer()
    );
    return buildPayload(children);
}

module.exports = {
    EMOJI_PROGRESS,
    EMOJI_SUCCESS,
    EMOJI_FAILURE,
    HEADLINES,
    buildHelpPayload,
    buildLanguagesPayload,
    buildLimitPayload,
    buildNoticePayload,
    buildProgressPayload,
    buildResultPayload,
    resolveEmoji,
    statusEmoji,
};
