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
  const bannersEl = document.getElementById('stat-banners');
  const versionEl = document.getElementById('stat-version');
  if (serversEl) animateCount(serversEl, stats.servers || 0);
  if (bannersEl) animateCount(bannersEl, stats.welcomeBanners || 0);
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
 * login button executes the invisible widget instead of navigating directly;
 * the issued token rides along to /auth/discord, which verifies it with
 * Cloudflare before starting the Discord OAuth2 redirect. Without a site key
 * the button stays a plain link.
 */
(function initTurnstile() {
  const siteKey = window.__TURNSTILE_SITE_KEY__;
  const btn = document.getElementById('login-discord-btn');
  if (!siteKey || !btn) return;

  const errEl = document.getElementById('turnstile-error');
  let widgetId = null;
  let pending = false;

  function showError(msg) {
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.hidden = false;
  }

  function renderWidget() {
    if (widgetId !== null) return true;
    if (!window.turnstile) return false; // api.js still loading
    widgetId = window.turnstile.render('#cf-turnstile-widget', {
      sitekey: siteKey,
      size: 'invisible',
      callback(token) {
        pending = false;
        window.location.href = '/auth/discord?cf-turnstile-response=' + encodeURIComponent(token);
      },
      'error-callback'() {
        pending = false;
        showError('Security check failed to load. Please try again.');
        if (widgetId !== null) window.turnstile.reset(widgetId);
      },
      'expired-callback'() {
        if (widgetId !== null) window.turnstile.reset(widgetId);
      },
    });
    return true;
  }

  btn.addEventListener('click', (e) => {
    e.preventDefault();
    if (pending) return;
    if (!renderWidget()) {
      showError('Security check is still loading — please try again in a moment.');
      return;
    }
    if (errEl) errEl.hidden = true;
    pending = true;
    window.turnstile.execute(widgetId);
  });
})();
