/**
 * Compilation workflow: validate → submit → poll → normalise.
 *
 * Provider-agnostic: it only needs `provider.createSubmission` /
 * `provider.getSubmission` and a `catalog.find`. Nothing here touches Discord,
 * and nothing here retries a submission (a retry would run the same code twice).
 */

const { createOutputBudget, decodeBase64, byteLength } = require('./limits');

const SUBMISSION_TERMINAL = new Set([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

const STATUS_LABELS = Object.freeze({
    1: 'In Queue',
    2: 'Processing',
    3: 'Accepted',
    4: 'Wrong Answer',
    5: 'Time Limit Exceeded',
    6: 'Compilation Error',
    7: 'Runtime Error (SIGSEGV)',
    8: 'Runtime Error (SIGXFSZ)',
    9: 'Runtime Error (SIGFPE)',
    10: 'Runtime Error (SIGABRT)',
    11: 'Runtime Error (NZEC)',
    12: 'Runtime Error (Other)',
    13: 'Internal Error',
    14: 'Exec Format Error',
});

/** Result kinds the view layer renders. */
const KINDS = Object.freeze({
    SUCCESS: 'success',
    COMPILATION_ERROR: 'compilation_error',
    RUNTIME_ERROR: 'runtime_error',
    WRONG_ANSWER: 'wrong_answer',
    TIME_LIMIT: 'time_limit',
    TIMEOUT: 'timeout',
    PROVIDER_ERROR: 'provider_error',
    RATE_LIMITED: 'rate_limited',
    UNSUPPORTED_LANGUAGE: 'unsupported_language',
    INVALID_INPUT: 'invalid_input',
    PENDING: 'pending',
});

function statusIdOf(submission) {
    const id = submission && submission.status && submission.status.id;
    return Number.isFinite(Number(id)) ? Number(id) : null;
}

/** Judge0 status id → result kind. Unknown/queued ids stay `pending`. */
function classifyStatus(statusId) {
    const id = Number(statusId);
    switch (id) {
        case 3: return KINDS.SUCCESS;
        case 4: return KINDS.WRONG_ANSWER;
        case 5: return KINDS.TIME_LIMIT;
        case 6: return KINDS.COMPILATION_ERROR;
        case 13: return KINDS.PROVIDER_ERROR;
        case 14: return KINDS.RUNTIME_ERROR;
        default:
            return id >= 7 && id <= 12 ? KINDS.RUNTIME_ERROR : KINDS.PENDING;
    }
}

function toNumber(value) {
    if (value == null || value === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
}

function emptyResult(kind, extra = {}) {
    return {
        kind,
        ok: kind === KINDS.SUCCESS,
        language: null,
        status: { id: null, label: '—' },
        stdout: '',
        stderr: '',
        compileOutput: '',
        message: '',
        exitCode: null,
        timeMs: null,
        memoryKb: null,
        truncated: false,
        error: null,
        ...extra,
    };
}

function decodeField(value, label) {
    const decoded = decodeBase64(value);
    if (decoded === null) {
        const err = new Error(`${label} was not valid Base64`);
        err.code = 'malformed_field';
        throw err;
    }
    return decoded;
}

const PRINTABLE_RE = /^[\t\n\r\x20-\x7E\u00A0-\uFFFF]*$/;

/** Judge0's `message` is base64-encoded too; keep it only when it is text. */
function safeMessage(value) {
    if (typeof value !== 'string' || !value) return '';
    const decoded = decodeBase64(value);
    const candidate = decoded == null ? value : decoded;
    return PRINTABLE_RE.test(candidate) ? candidate : '';
}

/** Turn a completed Judge0 submission into the shared result shape. */
function normalizeSubmission(submission, language, config) {
    const statusId = statusIdOf(submission);
    const kind = classifyStatus(statusId);
    const label = (submission.status && submission.status.description)
        || STATUS_LABELS[statusId]
        || 'Unknown';

    const budget = createOutputBudget(config.maxOutputBytes);
    const sectionCap = 4096;
    let compileOutput;
    let stderr;
    let stdout;
    try {
        compileOutput = budget.take(decodeField(submission.compile_output, 'compile_output'), sectionCap);
        stderr = budget.take(decodeField(submission.stderr, 'stderr'), sectionCap);
        stdout = budget.take(decodeField(submission.stdout, 'stdout'), Infinity);
    } catch (err) {
        return emptyResult(KINDS.PROVIDER_ERROR, {
            language,
            status: { id: statusId, label },
            error: { code: 'malformed_response', message: 'The execution service returned output that could not be decoded.' },
        });
    }

    const truncated = [compileOutput, stderr, stdout]
        .some(text => text.includes('(truncated)'));

    const result = emptyResult(kind, {
        language,
        status: { id: statusId, label },
        stdout,
        stderr,
        compileOutput,
        message: safeMessage(submission.message),
        exitCode: toNumber(submission.exit_code),
        timeMs: toNumber(submission.time) != null ? Math.round(Number(submission.time) * 1000) : null,
        memoryKb: toNumber(submission.memory),
        truncated,
    });

    if (kind === KINDS.PROVIDER_ERROR) {
        result.error = {
            code: 'provider_internal',
            message: 'The execution service reported an internal error while running this submission.',
        };
    }
    return result;
}

function providerFailure(err) {
    const code = err && err.kind ? err.kind : 'provider_error';
    const kind = code === 'rate_limited' ? KINDS.RATE_LIMITED
        : code === 'timeout' ? KINDS.TIMEOUT
            : KINDS.PROVIDER_ERROR;
    return emptyResult(kind, {
        status: { id: null, label: kind === KINDS.TIMEOUT ? 'Timed out' : 'Provider unavailable' },
        error: {
            code,
            message: (err && err.userMessage)
                || 'The execution service is unavailable right now. Please try again shortly.',
        },
    });
}

function defaultSleep(ms) {
    // Deliberately ref'd: this is the awaited work that keeps the process alive
    // between polls, and it is bounded by the poll deadline.
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Run one compilation end to end.
 *
 * @param {object} options
 * @param {string} options.language  user-supplied language name/alias
 * @param {string} options.code      source code
 * @param {string} [options.stdin]   program input
 * @param {object} options.runtime   { config, provider, catalog }
 * @param {(stage: string) => void} [options.onStage]
 * @returns {Promise<object>} the shared result shape (never throws)
 */
async function runCompilation({
    language,
    code,
    stdin = '',
    runtime,
    onStage = () => {},
    now = Date.now,
    sleep = defaultSleep,
} = {}) {
    if (!runtime || !runtime.provider || !runtime.catalog) {
        return emptyResult(KINDS.PROVIDER_ERROR, {
            error: { code: 'not_configured', message: 'Code execution is not configured on this bot instance.' },
        });
    }
    const config = runtime.config;

    const languageInput = String(language == null ? '' : language).trim();
    if (!languageInput) {
        return emptyResult(KINDS.INVALID_INPUT, {
            error: { code: 'missing_language', message: 'Choose a language — for example `python` or `cpp`.' },
        });
    }

    const source = String(code == null ? '' : code);
    if (!source.trim()) {
        return emptyResult(KINDS.INVALID_INPUT, {
            error: { code: 'missing_code', message: 'Your code is empty.' },
        });
    }
    if (byteLength(source) > config.maxCodeBytes) {
        return emptyResult(KINDS.INVALID_INPUT, {
            error: {
                code: 'code_too_large',
                message: `Your code is ${(byteLength(source) / 1024).toFixed(1)} KB — the limit is ${Math.round(config.maxCodeBytes / 1024)} KB.`,
            },
        });
    }

    const input = String(stdin == null ? '' : stdin);
    if (byteLength(input) > config.maxStdinBytes) {
        return emptyResult(KINDS.INVALID_INPUT, {
            error: {
                code: 'stdin_too_large',
                message: `Program input is ${(byteLength(input) / 1024).toFixed(1)} KB — the limit is ${Math.round(config.maxStdinBytes / 1024)} KB.`,
            },
        });
    }

    let resolved;
    try {
        resolved = await runtime.catalog.find(languageInput);
    } catch (err) {
        return providerFailure(err);
    }
    if (!resolved) {
        return emptyResult(KINDS.UNSUPPORTED_LANGUAGE, {
            error: { code: 'unknown_language', message: `\`${languageInput}\` is not a language PrimeBot knows.` },
        });
    }
    if (!resolved.language) {
        return emptyResult(KINDS.UNSUPPORTED_LANGUAGE, {
            error: {
                code: 'language_unavailable',
                message: `\`${languageInput}\` is not available on the execution service right now.`,
            },
            available: (resolved.snapshot && resolved.snapshot.supported || []).map(l => l.label),
        });
    }
    const languageInfo = resolved.language;

    onStage('submitting');
    let submission;
    try {
        submission = await runtime.provider.createSubmission({
            sourceCode: source,
            languageId: languageInfo.id,
            stdin: input,
        });
    } catch (err) {
        return providerFailure(err);
    }

    const deadline = now() + config.pollDeadlineMs;
    let latest = null;

    for (;;) {
        onStage('running');
        try {
            latest = await runtime.provider.getSubmission(submission.token);
        } catch (err) {
            return providerFailure(err);
        }

        const statusId = statusIdOf(latest);
        if (statusId != null && SUBMISSION_TERMINAL.has(statusId)) break;
        if (now() >= deadline) {
            return emptyResult(KINDS.TIMEOUT, {
                language: languageInfo,
                status: { id: statusId, label: 'Timed out' },
                error: {
                    code: 'poll_deadline',
                    message: `The submission did not finish within ${Math.round(config.pollDeadlineMs / 1000)} seconds.`,
                },
            });
        }
        await sleep(config.pollIntervalMs);
    }

    onStage('fetching');
    return normalizeSubmission(latest, languageInfo, config);
}

module.exports = {
    KINDS,
    STATUS_LABELS,
    SUBMISSION_TERMINAL,
    classifyStatus,
    normalizeSubmission,
    runCompilation,
    statusIdOf,
};
