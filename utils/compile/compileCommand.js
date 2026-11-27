/**
 * Shared Code Compile flow — the slash command and the prefix command both
 * call these functions, so behaviour can never drift between them.
 */

const view = require('./compileView');
const { runCompilation } = require('./compileService');
const { getCompileRuntime } = require('./runtime');
const { normalizeLanguageInput } = require('./languageCatalog');

const ANIMATION_INTERVAL_MS = 1500;
const FENCE_RE = /```([\s\S]*?)```/g;
const LANGUAGE_HINT_RE = /^[A-Za-z0-9+#._-]{1,20}$/;

/**
 * Split a fenced block into an optional language hint and the code.
 * The first line is only treated as a hint when it is a real language name,
 * so ```` ```const numbers = … ```` keeps its first line.
 */
function splitFenceBlock(body) {
    const text = String(body || '').replace(/\r\n/g, '\n').replace(/\n$/, '');
    const lines = text.split('\n');
    if (lines.length > 1) {
        const hint = lines[0].trim();
        if (LANGUAGE_HINT_RE.test(hint) && normalizeLanguageInput(hint)) {
            return { info: hint, code: lines.slice(1).join('\n') };
        }
    }
    return { info: '', code: text.replace(/^\n/, '') };
}

function defaultSleep(ms) {
    return new Promise(resolve => {
        const timer = setTimeout(resolve, ms);
        if (timer.unref) timer.unref();
    });
}

/** Everything after the command word, with its original whitespace intact. */
function textAfterCommand(raw, commandName) {
    const text = String(raw || '');
    const needle = String(commandName || 'compile').toLowerCase();
    const at = text.toLowerCase().indexOf(needle);
    return at >= 0 ? text.slice(at + needle.length) : text;
}

/**
 * `$compile …` argument parsing.
 *   help | languages
 *   <language> <code…>                          (inline)
 *   <language> ```code``` ```stdin```           (fenced, newlines preserved)
 *   ```python\ncode```                          (language from the fence hint)
 *
 * `raw` (the message content) is preferred over `args`: splitting on
 * whitespace destroys newlines and indentation, which breaks every fenced
 * block and every indentation-sensitive language.
 */
function parseCompileArgs(args, { prefix = '$', raw = null, commandName = 'compile' } = {}) {
    const list = Array.isArray(args) ? args.filter(a => a !== undefined) : [];
    const first = (list[0] || '').toLowerCase();

    if (!first || first === 'help' || first === '?' || first === 'usage') {
        return { action: 'help', prefix };
    }
    if ((first === 'languages' || first === 'langs' || first === 'language') && list.length === 1) {
        return { action: 'languages', prefix };
    }

    const text = (typeof raw === 'string' && raw.trim()
        ? textAfterCommand(raw, commandName)
        : list.join(' ')).replace(/\r\n/g, '\n').trim();
    if (!text) return { action: 'help', prefix };

    const blocks = [...text.matchAll(FENCE_RE)].map(m => ({
        ...splitFenceBlock(m[1]),
        index: m.index,
    }));

    if (blocks.length) {
        const before = text.slice(0, blocks[0].index).trim();
        const words = before ? before.split(/\s+/) : [];
        if (words.length > 1) {
            // `<language> <inline code> ```stdin``` `
            return {
                action: 'run',
                prefix,
                language: words[0],
                code: before.slice(words[0].length).trim(),
                stdin: blocks[0].code,
            };
        }
        return {
            action: 'run',
            prefix,
            language: words[0] || blocks[0].info || '',
            code: blocks[0].code,
            stdin: blocks[1] ? blocks[1].code : '',
        };
    }

    const language = text.split(/\s+/)[0];
    const code = text.slice(language.length).trim();
    if (!code) return { action: 'help', prefix };
    return { action: 'run', prefix, language, code, stdin: '' };
}

/**
 * Re-render the progress card on a timer while the submission is in flight.
 * Edits are serialised so a slow Discord call cannot pile up.
 */
function startProgressAnimator(edit, { language = null, now = Date.now } = {}) {
    const startedAt = now();
    let stage = 'submitting';
    let busy = false;
    let stopped = false;

    const render = () => {
        if (busy || stopped) return;
        busy = true;
        Promise.resolve()
            .then(() => edit(view.buildProgressPayload({
                stage,
                language,
                elapsedMs: now() - startedAt,
            })))
            .catch(() => {})
            .finally(() => { busy = false; });
    };

    const timer = setInterval(render, ANIMATION_INTERVAL_MS);
    if (timer.unref) timer.unref();

    return {
        setStage(next) { if (next) stage = next; },
        stop() {
            stopped = true;
            clearInterval(timer);
        },
    };
}

/**
 * Acquire a slot, animate progress, run the submission and render the result.
 * `edit` receives a payload and must send/edit the message that shows it.
 *
 * @returns {Promise<object>} the compile result (or the limiter rejection)
 */
async function runCompileRequest({
    userId,
    guildId = null,
    language,
    code,
    stdin = '',
    edit,
    progressSent = false,
    runtime = getCompileRuntime(),
    now = Date.now,
    sleep = defaultSleep,
} = {}) {
    if (typeof edit !== 'function') throw new TypeError('runCompileRequest needs an edit() callback');

    const gate = runtime.limiter.acquire({ userId, guildId, now: now() });
    if (!gate.ok) {
        await edit(view.buildLimitPayload(gate));
        return { kind: 'rate_limited', ok: false, reason: gate.reason, retryAfterMs: gate.retryAfterMs };
    }

    const languageLabel = String(language == null ? '' : language).trim() || null;
    let animator = null;
    try {
        if (!progressSent) {
            await edit(view.buildProgressPayload({ stage: 'submitting', language: languageLabel }));
        }
        animator = startProgressAnimator(edit, { language: languageLabel, now });

        const result = await runCompilation({
            language,
            code,
            stdin,
            runtime,
            now,
            sleep,
            onStage: stage => animator.setStage(stage),
        });

        animator.stop();
        animator = null;
        await edit(view.buildResultPayload(result));
        return result;
    } catch (err) {
        console.error('[COMPILE] Unexpected failure:', err && err.message ? err.message : err);
        if (animator) animator.stop();
        await edit(view.buildNoticePayload({
            title: 'Compilation failed',
            body: 'Something went wrong while compiling your code. Please try again shortly.',
        })).catch(() => {});
        return { kind: 'provider_error', ok: false };
    } finally {
        gate.release();
    }
}

/** Language list card; degrades to a notice when the provider is unreachable. */
async function buildLanguagesCard({ runtime = getCompileRuntime() } = {}) {
    try {
        const snapshot = await runtime.catalog.load();
        return view.buildLanguagesPayload(snapshot);
    } catch (err) {
        console.warn('[COMPILE] Language list unavailable:', err && err.message ? err.message : err);
        return view.buildNoticePayload({
            title: 'Language list unavailable',
            body: 'The execution service could not be reached, so the language list cannot be shown right now.',
        });
    }
}

/** Autocomplete choices for the language option (never throws). */
async function languageChoices({ runtime = getCompileRuntime(), query = '', limit = 25 } = {}) {
    const needle = String(query || '').toLowerCase().trim();
    let labels = [];
    try {
        const snapshot = await runtime.catalog.load();
        labels = snapshot.supported.map(l => l.key);
    } catch (_) {
        const { TARGET_LANGUAGES } = require('./languageCatalog');
        labels = TARGET_LANGUAGES.map(l => l.key);
    }
    return labels
        .filter(key => !needle || key.includes(needle))
        .slice(0, limit)
        .map(key => ({ name: key, value: key }));
}

module.exports = {
    ANIMATION_INTERVAL_MS,
    buildLanguagesCard,
    languageChoices,
    parseCompileArgs,
    runCompileRequest,
    startProgressAnimator,
};
