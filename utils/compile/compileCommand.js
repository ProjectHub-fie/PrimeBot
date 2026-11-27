/**
 * Shared Code Compile flow — the slash command and the prefix command both
 * call these functions, so behaviour can never drift between them.
 */

const view = require('./compileView');
const { runCompilation } = require('./compileService');
const { getCompileRuntime } = require('./runtime');

const ANIMATION_INTERVAL_MS = 1500;
const FENCE_RE = /```[a-zA-Z0-9+#._-]*[ \t]*\r?\n([\s\S]*?)```/g;

function defaultSleep(ms) {
    return new Promise(resolve => {
        const timer = setTimeout(resolve, ms);
        if (timer.unref) timer.unref();
    });
}

/**
 * `$compile …` argument parsing.
 *   help | languages
 *   <language> <code…>            (a fenced block is used as the code)
 *   <language> ```code``` ```stdin```
 */
function parseCompileArgs(args, { prefix = '$' } = {}) {
    const list = Array.isArray(args) ? args.filter(a => a !== undefined) : [];
    const first = (list[0] || '').toLowerCase();

    if (!first || first === 'help' || first === '?' || first === 'usage') {
        return { action: 'help', prefix };
    }
    if ((first === 'languages' || first === 'langs' || first === 'language') && list.length === 1) {
        return { action: 'languages', prefix };
    }

    const language = list[0];
    const rest = list.slice(1).join(' ');
    const blocks = [...rest.matchAll(FENCE_RE)].map(m => m[1].replace(/\r?\n$/, ''));

    if (blocks.length) {
        return {
            action: 'run',
            prefix,
            language,
            code: blocks[0],
            stdin: blocks[1] || '',
        };
    }
    if (!rest.trim()) return { action: 'help', prefix };
    return { action: 'run', prefix, language, code: rest, stdin: '' };
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
