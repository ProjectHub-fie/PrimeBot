/* Login page — fetch /api/stats and animate the platform stat cards + donuts.
 * Optional: if the stats call fails (cold DB) the page stays usable with zeros.
 */

function animateCount(el, target, duration = 1200) {
  const start = performance.now();
  const tick = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(target * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function renderDonut(el, percent, colorVar) {
  if (!el) return;
  const pct = Math.max(0, Math.min(100, percent));
  el.style.background = `conic-gradient(var(${colorVar}) ${pct * 3.6}deg, var(--border) 0deg)`;
  el.querySelector('.donut-pct').textContent = `${pct}%`;
}

async function loadLoginStats() {
  let stats;
  try {
    stats = await api('/api/stats');
  } catch (err) {
    const sub = document.getElementById('stats-sub');
    if (sub) sub.textContent = 'Stats unavailable right now';
    return;
  }
  const sub = document.getElementById('stats-sub');
  if (sub) {
    const bot = stats.bot;
    sub.textContent = bot && bot.username
      ? `Running as @${esc(bot.username)}`
      : (stats.botName ? `${esc(stats.botName)} v${esc(stats.botVersion)}` : 'Live data from the bot database');
  }
  const serversEl = document.getElementById('stat-servers');
  const usersEl = document.getElementById('stat-users');
  const usersLabelEl = document.getElementById('stat-users-label');
  const serversLabelEl = document.getElementById('stat-servers-label');
  const versionEl = document.getElementById('stat-version');
  if (serversEl) animateCount(serversEl, stats.servers || 0);
  // The member count is only ever a real Discord total (live heartbeat 'bot' or
  // REST-summed 'rest'). We do NOT track members via leveling XP, so when
  // neither Discord source is available there is no number to show — render a
  // dash rather than a misleading 0 / leveling count.
  const hasMemberCount = stats.totalUsers != null
    && (stats.totalUsersSource === 'bot' || stats.totalUsersSource === 'rest');
  if (usersEl) {
    if (hasMemberCount) animateCount(usersEl, stats.totalUsers || 0);
    else usersEl.textContent = '—';
  }
  // The server number is the authoritative Discord guild count when sourced
  // from REST ('rest') or the live bot heartbeat ('bot'). When it is neither
  // ('db') it is only the lazy server_settings row count, which undercounts
  // guilds that were never configured — label it honestly so a fallback is
  // never presented as the total number of servers the bot is in.
  if (serversLabelEl) {
    serversLabelEl.textContent = stats.serversSource === 'db' ? 'Servers configured' : 'Servers';
  }
  if (usersLabelEl) {
    usersLabelEl.textContent = hasMemberCount ? 'Total members' : 'Members unavailable';
  }
  if (versionEl) versionEl.textContent = stats.botVersion ? `v${esc(stats.botVersion)}` : '—';

  const f = stats.features || {};
  renderDonut(document.getElementById('donut-leveling'), f.leveling?.percent ?? 0, '--green');
  renderDonut(document.getElementById('donut-welcome'), f.welcome?.percent ?? 0, '--blurple');
  renderDonut(document.getElementById('donut-reactions'), f.autoReactions?.percent ?? 0, '--yellow');
  renderDonut(document.getElementById('donut-broadcasts'), f.broadcasts?.percent ?? 0, '--gold');
  renderDonut(document.getElementById('donut-automod'), f.automod?.percent ?? 0, '--red');
  renderDonut(document.getElementById('donut-tickets'), f.tickets?.percent ?? 0, '--blurple');
  renderDonut(document.getElementById('donut-antinuke'), f.antiNuke?.percent ?? 0, '--red');
}

loadLoginStats();

/* ── Invisible Cloudflare Turnstile gate on "Login with Discord" ────────────
 * Pressing the button runs the invisible challenge on demand — Cloudflare
 * decides whether a puzzle is needed, the user never clicks a checkbox. While
 * it runs the button is disabled, the label stays exactly as it is, and an
 * inline spinner + "Verifying…" status appear. On success the spinner is
 * replaced by a ✓ in the same spot, held briefly, and only then does the
 * browser continue to the existing /auth/discord OAuth flow with the token.
 *
 * Failure, timeout or an unavailable widget stops the spinner, shows a clear
 * error and leaves the button usable: the widget is reset so the next tap runs
 * a fresh challenge. The token is ALWAYS verified server-side by
 * /auth/discord — nothing here is trusted on its own, it is only the UX.
 */
(function initTurnstile() {
  const siteKey = window.__TURNSTILE_SITE_KEY__;
  const btn = document.getElementById('login-discord-btn');
  if (!siteKey || !btn) return;

  const statusEl = document.getElementById('login-status');
  const errorEl = document.getElementById('turnstile-error');

  const API_WAIT_MS = 8000;        // how long to wait for Cloudflare's api.js
  const VERIFY_TIMEOUT_MS = 15000; // how long the challenge itself may take
  const SUCCESS_HOLD_MS = 700;     // how long the ✓ stays visible before redirect
  const MESSAGES = {
    verifying: 'Verifying…',
    verified: 'Verified — continuing to Discord…',
    failed: 'The security check could not be verified. Please try again.',
    timeout: 'The security check timed out. Please try again.',
    unavailable: 'The security check is unavailable right now. Please try again.',
  };

  let widgetId = null;
  let challenged = false; // a challenge has already run → reset() before the next execute()
  let state = 'idle';     // idle | verifying | verified | error
  let verifyTimer = null;
  let holdTimer = null;
  let apiTimer = null;
  let destroyed = false;

  function clearTimers() {
    if (verifyTimer) { clearTimeout(verifyTimer); verifyTimer = null; }
    if (holdTimer) { clearTimeout(holdTimer); holdTimer = null; }
    if (apiTimer) { clearTimeout(apiTimer); apiTimer = null; }
  }

  function setStatus(text, tone) {
    if (!statusEl) return;
    statusEl.textContent = text || '';
    statusEl.hidden = !text;
    statusEl.dataset.tone = tone || '';
  }

  function showError(text) {
    if (!errorEl) return;
    errorEl.textContent = text || '';
    errorEl.hidden = !text;
  }

  function setBusy(busy) {
    btn.classList[busy ? 'add' : 'remove']('is-busy');
    if (busy) {
      btn.setAttribute('aria-busy', 'true');
      btn.setAttribute('aria-disabled', 'true');
    } else {
      btn.removeAttribute('aria-busy');
      btn.removeAttribute('aria-disabled');
    }
  }

  function resetWidget() {
    if (widgetId === null) return;
    try {
      if (window.turnstile && typeof window.turnstile.reset === 'function') window.turnstile.reset(widgetId);
    } catch { /* the widget is already gone */ }
  }

  function destroyWidget() {
    if (widgetId === null) return;
    try {
      if (window.turnstile && typeof window.turnstile.remove === 'function') window.turnstile.remove(widgetId);
    } catch { /* the widget is already gone */ }
    widgetId = null;
    challenged = false;
  }

  function fail(message) {
    if (destroyed) return;
    clearTimers();
    state = 'error';
    btn.classList.remove('is-verifying', 'is-verified');
    setBusy(false);
    setStatus('', '');
    showError(message);
    // A completed or errored challenge must be reset before execute() runs again.
    resetWidget();
  }

  function succeed(token) {
    if (destroyed || state !== 'verifying') return;
    clearTimers();
    state = 'verified';
    btn.classList.remove('is-verifying');
    btn.classList.add('is-verified');
    showError('');
    setStatus(MESSAGES.verified, 'ok');
    holdTimer = setTimeout(() => {
      holdTimer = null;
      if (destroyed) return;
      // Same OAuth entry point as the plain link — only reached once Cloudflare
      // issued a token, and the server re-verifies it before redirecting.
      window.location.assign('/auth/discord?cf-turnstile-response=' + encodeURIComponent(token));
    }, SUCCESS_HOLD_MS);
  }

  function renderWidget() {
    if (widgetId !== null) return true;
    if (!window.turnstile || typeof window.turnstile.render !== 'function') return false;
    const id = window.turnstile.render('#cf-turnstile-widget', {
      sitekey: siteKey,
      size: 'invisible',
      theme: 'dark',
      retry: 'never', // we own retries, so the button state always matches
      callback: (token) => succeed(token),
      'error-callback': () => fail(MESSAGES.failed),
      'expired-callback': () => {
        if (state === 'verifying') fail(MESSAGES.timeout);
      },
    });
    if (id === null || id === undefined) return false;
    widgetId = id;
    return true;
  }

  // Cloudflare's api.js is loaded async/defer, so the first tap may arrive
  // before window.turnstile exists. Wait for it instead of failing instantly.
  function waitForApi() {
    return new Promise((resolve) => {
      if (window.turnstile && typeof window.turnstile.render === 'function') return resolve(true);
      const started = Date.now();
      const tick = () => {
        apiTimer = null;
        if (destroyed) return resolve(false);
        if (window.turnstile && typeof window.turnstile.render === 'function') return resolve(true);
        if (Date.now() - started >= API_WAIT_MS) return resolve(false);
        apiTimer = setTimeout(tick, 100);
      };
      tick();
    });
  }

  async function startVerification() {
    // Rapid taps: one challenge at a time, and never restart once verified.
    if (state === 'verifying' || state === 'verified' || destroyed) return;
    clearTimers();
    state = 'verifying';
    showError('');
    setStatus(MESSAGES.verifying, 'busy');
    setBusy(true);
    btn.classList.remove('is-verified');
    btn.classList.add('is-verifying');

    const apiReady = await waitForApi();
    if (destroyed || state !== 'verifying') return;
    if (!apiReady || !renderWidget()) {
      fail(MESSAGES.unavailable);
      return;
    }

    if (challenged) resetWidget(); // reset() is required before execute() re-runs
    challenged = true;
    verifyTimer = setTimeout(() => {
      verifyTimer = null;
      if (state === 'verifying') fail(MESSAGES.timeout);
    }, VERIFY_TIMEOUT_MS);

    try {
      const running = window.turnstile.execute(widgetId);
      // v0 execute() returns a promise when the challenge cannot be started.
      if (running && typeof running.catch === 'function') running.catch(() => fail(MESSAGES.failed));
    } catch {
      fail(MESSAGES.failed);
    }
  }

  btn.addEventListener('click', (e) => {
    e.preventDefault();
    startVerification();
  });

  // Never leave a timer or a widget behind when the page goes away; a bfcache
  // restore re-arms the gate so the button still works after going back.
  function cleanup() {
    destroyed = true;
    clearTimers();
    destroyWidget();
  }
  window.addEventListener('pagehide', cleanup);
  window.addEventListener('beforeunload', cleanup);
  window.addEventListener('pageshow', (e) => {
    if (!e || !e.persisted) return;
    destroyed = false;
    state = 'idle';
    setBusy(false);
    btn.classList.remove('is-verifying', 'is-verified');
    setStatus('', '');
    showError('');
  });
})();
