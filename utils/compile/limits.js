/**
 * Size limits and safe text handling for the Code Compile feature.
 *
 * Everything here is pure: no Discord, no network, no timers.
 */

const DEFAULT_LIMITS = Object.freeze({
    maxCodeBytes: 15 * 1024,
    maxStdinBytes: 5 * 1024,
    maxOutputBytes: 10 * 1024,
    // Components V2 rejects a TextDisplay above 4000 characters, so each
    // rendered section is additionally capped by character count.
    maxSectionChars: 3200,
});

const TRUNCATION_SUFFIX = '\n… (truncated)';

function byteLength(value) {
    const text = value == null ? '' : String(value);
    return Buffer.byteLength(text, 'utf8');
}

/**
 * Truncate `text` so the result fits both a byte and a character budget.
 * Iterates code points so a multi-byte glyph is never split.
 */
function truncateText(text, { maxBytes = Infinity, maxChars = Infinity, suffix = TRUNCATION_SUFFIX } = {}) {
    const value = text == null ? '' : String(text);
    if (byteLength(value) <= maxBytes && value.length <= maxChars) return value;

    const budgetBytes = Number.isFinite(maxBytes)
        ? Math.max(0, maxBytes - byteLength(suffix))
        : Infinity;
    const budgetChars = Number.isFinite(maxChars)
        ? Math.max(0, maxChars - suffix.length)
        : Infinity;

    let out = '';
    let usedBytes = 0;
    for (const char of value) {
        const size = Buffer.byteLength(char, 'utf8');
        if (usedBytes + size > budgetBytes || out.length + char.length > budgetChars) break;
        out += char;
        usedBytes += size;
    }
    return `${out}${suffix}`;
}

/**
 * A shared byte budget across several output sections, so stdout + stderr +
 * compiler output together never exceed the advertised limit.
 */
function createOutputBudget(maxBytes = DEFAULT_LIMITS.maxOutputBytes) {
    let remaining = Math.max(0, maxBytes);
    return {
        get remaining() { return remaining; },
        take(text, capBytes = Infinity) {
            const value = text == null ? '' : String(text);
            if (!value) return '';
            const allowance = Math.min(remaining, capBytes);
            if (allowance <= 0) {
                remaining = 0;
                return TRUNCATION_SUFFIX.trim();
            }
            const clipped = truncateText(value, { maxBytes: allowance });
            remaining = Math.max(0, remaining - byteLength(clipped));
            return clipped;
        },
    };
}

const BASE64_RE = /^[A-Za-z0-9+/=\s]*$/;

/**
 * Decode a Judge0 `base64_encoded=true` field. Returns `null` when the value
 * is not valid Base64, so a malformed provider response is detectable instead
 * of silently becoming mojibake.
 */
function decodeBase64(value) {
    if (value == null) return '';
    const text = String(value);
    if (!text) return '';
    if (!BASE64_RE.test(text)) return null;
    try {
        return Buffer.from(text, 'base64').toString('utf8').replace(/^\uFEFF/, '');
    } catch (_) {
        return null;
    }
}

function encodeBase64(value) {
    return Buffer.from(value == null ? '' : String(value), 'utf8').toString('base64');
}

/**
 * Fence `text` in a code block whose fence is longer than any backtick run in
 * the body, so pasted output containing ``` cannot escape the block.
 */
function codeBlock(text, hint = '') {
    const body = (text == null ? '' : String(text))
        .replace(/\u0000/g, '')
        .replace(/\n+$/, '');
    const longest = (body.match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
    const fence = '`'.repeat(Math.min(6, Math.max(3, longest + 1)));
    return `${fence}${hint}\n${body}\n${fence}`;
}

module.exports = {
    DEFAULT_LIMITS,
    TRUNCATION_SUFFIX,
    byteLength,
    truncateText,
    createOutputBudget,
    decodeBase64,
    encodeBase64,
    codeBlock,
};
