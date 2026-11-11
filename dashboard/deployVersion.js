/**
 * Single source of truth for the dashboard's "deployment version".
 *
 * The version identifies the *code* currently serving requests, so an
 * already-open browser tab can detect that a newer deployment shipped and
 * refresh itself (see dashboard/public/js/auto-update.js).
 *
 * Resolution order (first non-empty wins):
 *
 *   1. `PRIMEBOT_DEPLOY_VERSION` — an explicit override (used by the build
 *      script `scripts/write-version.js` at runtime and by tests).
 *   2. `VERCEL_GIT_COMMIT_SHA`   — Vercel's Git commit SHA, present during a
 *      Vercel build. It changes on every deployment, which is exactly what we
 *      want to compare against.
 *   3. `VERCEL_DEPLOYMENT_ID`    — a per-deployment identifier Vercel also
 *      exposes; a reliable fallback when the SHA is unavailable.
 *   4. `COMMIT_REF` / `GITHUB_SHA` — Netlify / generic CI fallbacks.
 *   5. A filesystem fingerprint — `mtime:size` of this file plus the dashboard
 *      server + shared layout. This is a *safe local-development fallback*:
 *      it changes when the code on disk changes, so a dev server also triggers
 *      the update banner, without inventing a fake constant.
 *   6. `BOT_VERSION`             — the last-resort string, so the value is
 *      never empty (an empty version would make every comparison equal and
 *      silently disable detection).
 *
 * The value is short and non-secret; it is embedded into every page and served
 * from `/version.json`. It is intentionally NOT a timestamp of "now" — a
 * constant-per-deployment value is required for the compare to be meaningful.
 */

const fs = require('fs');
const path = require('path');

const BOT_VERSION = (() => {
    try { return require('../config').version || '0.0.0'; } catch { return '0.0.0'; }
})();

function envVersion() {
    const candidates = [
        process.env.PRIMEBOT_DEPLOY_VERSION,
        process.env.VERCEL_GIT_COMMIT_SHA,
        process.env.VERCEL_DEPLOYMENT_ID,
        process.env.COMMIT_REF,
        process.env.GITHUB_SHA,
    ];
    for (const value of candidates) {
        if (value && String(value).trim()) return String(value).trim();
    }
    return null;
}

// Filesystem fingerprint for local development (no CI env vars set). `mtime` is
// resolution-limited on some filesystems, so it is combined with the byte size
// of a handful of files that change when the UI does.
const FINGERPRINT_FILES = [
    path.join(__dirname, 'deployVersion.js'),
    path.join(__dirname, 'server.js'),
    path.join(__dirname, 'render', 'layout.js'),
    path.join(__dirname, 'public', 'styles.css'),
];

function fileFingerprint() {
    const parts = [];
    for (const file of FINGERPRINT_FILES) {
        try {
            const stat = fs.statSync(file);
            parts.push(`${stat.size}:${Math.floor(stat.mtimeMs)}`);
        } catch {
            // A missing file just contributes nothing — the fingerprint still
            // varies with whatever is present.
        }
    }
    if (parts.length === 0) return null;
    // A short, stable digest so the value stays URL/JSON friendly.
    let hash = 5381;
    const joined = parts.join('|');
    for (let i = 0; i < joined.length; i++) {
        hash = ((hash << 5) + hash + joined.charCodeAt(i)) >>> 0;
    }
    return `dev-${hash.toString(36)}`;
}

let cached = null;

/** The current deployment version string (never empty). */
function getDeployVersion() {
    if (cached) return cached;
    cached = envVersion() || fileFingerprint() || BOT_VERSION;
    return cached;
}

/**
 * A short, cache-busting token safe to append to asset URLs (`?v=<token>`).
 * A full commit SHA is fine but long; the first 12 chars are plenty to bust a
 * browser cache and keep the URLs tidy.
 */
function getAssetVersion() {
    return String(getDeployVersion()).slice(0, 12).replace(/[^a-zA-Z0-9._-]/g, '');
}

/**
 * The public `/version.json` payload. `version` is what the client compares
 * against its loaded version; `builtAt` is informational only (never used for
 * comparison, so a client-clock-independent compare is impossible to break).
 */
function getVersionPayload() {
    return {
        version: getDeployVersion(),
        builtAt: new Date().toISOString(),
        name: 'PrimeBot Dashboard',
    };
}

/** Test-only: drop the memoized value so an env change is picked up. */
function _resetCache() {
    cached = null;
}

module.exports = { getDeployVersion, getAssetVersion, getVersionPayload, _resetCache };
