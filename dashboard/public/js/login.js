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
  const versionEl = document.getElementById('stat-version');
  if (serversEl) animateCount(serversEl, stats.servers || 0);
  if (usersEl) animateCount(usersEl, stats.totalUsers || 0);
  if (versionEl) versionEl.textContent = stats.botVersion ? `v${esc(stats.botVersion)}` : '—';

  const f = stats.features || {};
  renderDonut(document.getElementById('donut-leveling'), f.leveling?.percent ?? 0, '--green');
  renderDonut(document.getElementById('donut-welcome'), f.welcome?.percent ?? 0, '--blurple');
  renderDonut(document.getElementById('donut-reactions'), f.autoReactions?.percent ?? 0, '--yellow');
  renderDonut(document.getElementById('donut-broadcasts'), f.broadcasts?.percent ?? 0, '--gold');
  renderDonut(document.getElementById('donut-automod'), f.automod?.percent ?? 0, '--red');
  renderDonut(document.getElementById('donut-tickets'), f.tickets?.percent ?? 0, '--blurple');
}

loadLoginStats();

/* ── Invisible Cloudflare Turnstile gate on "Login with Discord" ────────────
 * When the server rendered a site key (window.__TURNSTILE_SITE_KEY__), the
 * invisible widget starts AS SOON AS THE PAGE LOADS (not on button click), so
 * by the time the user presses Login a token is usually already cached and the
 * click navigates straight to /auth/discord — no visible wait. The issued
 * token rides along to /auth/discord, which verifies it with Cloudflare before
 * starting the Discord OAuth2 redirect. If the challenge is still in flight on
 * click, the click waits for it (pending) and the callback navigates then.
 * Expired tokens (~5 min lifetime) are refreshed in the background so the
 * cache stays warm while the user sits on the page. Without a site key the
 * button stays a plain link.
 */
(function initTurnstile() {
  const siteKey = window.__TURNSTILE_SITE_KEY__;
  const btn = document.getElementById('login-discord-btn');
  if (!siteKey || !btn) return;

  const errEl = document.getElementById('turnstile-error');
  let widgetId = null;
  let token = null;    // cached token from the eager page-load execution
  let pending = false; // a click is waiting for a fresh token

  function showError(msg) {
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.hidden = false;
  }

  function navigate() {
    pending = false;
    window.location.href = '/auth/discord?cf-turnstile-response=' + encodeURIComponent(token);
  }

  function renderWidget() {
    if (widgetId !== null) return true;
    if (!window.turnstile) return false; // api.js still loading
    widgetId = window.turnstile.render('#cf-turnstile-widget', {
      sitekey: siteKey,
      size: 'invisible',
      callback(newToken) {
        token = newToken;
        if (pending) navigate();
      },
      'error-callback'() {
        token = null;
        pending = false;
        showError('Security check failed to load. Please try again.');
        if (widgetId !== null) window.turnstile.reset(widgetId);
      },
      'expired-callback'() {
        token = null;
        warmExecute(); // refresh the cache so the next click is instant again
      },
    });
    return true;
  }

  // reset() is required before execute() once a challenge completed, otherwise
  // execute() is a no-op.
  function warmExecute() {
    if (widgetId === null) return;
    try { window.turnstile.reset(widgetId); } catch { /* not yet run */ }
    window.turnstile.execute(widgetId);
  }

  // Kick the challenge off on page load, retrying until Cloudflare's api.js
  // (loaded async/defer) is ready. Gives up after ~15s and lets the click
  // handler surface a loading error instead.
  if (renderWidget()) {
    warmExecute();
  } else {
    const poll = setInterval(() => {
      if (!renderWidget()) return;
      clearInterval(poll);
      warmExecute();
    }, 100);
    setTimeout(() => clearInterval(poll), 15000);
  }

  btn.addEventListener('click', (e) => {
    e.preventDefault();
    if (pending) return;
    if (errEl) errEl.hidden = true;
    if (token) {
      pending = true;
      navigate();
      return;
    }
    if (!renderWidget()) {
      showError('Security check is still loading — please try again in a moment.');
      return;
    }
    pending = true;
    warmExecute();
  });
})();
