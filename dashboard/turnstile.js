/**
 * Cloudflare Turnstile (invisible) verification for the dashboard login flow.
 *
 * The login page renders an invisible Turnstile widget (site key from
 * TURNSTILE_SITE_KEY). The widget executes as soon as the page loads and the
 * resulting token is cached client-side; when the user clicks "Login with
 * Discord" the token is sent along to GET /auth/discord, which verifies it
 * here against Cloudflare's siteverify endpoint before starting the Discord
 * OAuth2 redirect. Pre-running the challenge removes the click-time wait.
 *
 * Env vars:
 *   TURNSTILE_SITE_KEY   — public site key, rendered into the login page.
 *   TURNSTILE_SECRET_KEY — secret key, used server-side for verification.
 *
 * If TURNSTILE_SECRET_KEY is unset, verification is skipped entirely (the
 * login page also renders no widget without a site key), so local/dev setups
 * keep working with zero extra config.
 */

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

function isTurnstileEnabled() {
    return Boolean(process.env.TURNSTILE_SECRET_KEY);
}

/**
 * Verify a Turnstile response token with Cloudflare.
 * @param {string} token    the cf-turnstile-response token from the client
 * @param {string} [remoteip] optional client IP (helps Cloudflare's checks)
 * @returns {Promise<{success: boolean, skipped?: boolean, 'error-codes'?: string[]}>}
 */
async function verifyTurnstile(token, remoteip) {
    const secret = process.env.TURNSTILE_SECRET_KEY;
    if (!secret) return { success: true, skipped: true };
    if (!token || typeof token !== 'string') {
        return { success: false, 'error-codes': ['missing-input-response'] };
    }
    const body = new URLSearchParams({ secret, response: token });
    if (remoteip) body.set('remoteip', remoteip);
    const res = await fetch(SITEVERIFY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });
    if (!res.ok) {
        throw new Error(`Turnstile siteverify responded ${res.status}`);
    }
    return res.json();
}

module.exports = { isTurnstileEnabled, verifyTurnstile, SITEVERIFY_URL };
