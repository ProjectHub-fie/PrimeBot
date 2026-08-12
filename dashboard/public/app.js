/* PrimeBot Dashboard — client-side SPA logic */

const app = document.getElementById('app');
const toastEl = document.getElementById('toast');

// ── Helpers ────────────────────────────────────────────────────────────────

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });
  let body = null;
  const text = await res.text();
  if (text) { try { body = JSON.parse(text); } catch { body = text; } }
  if (!res.ok) {
    const msg = (body && body.error) || `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function toast(message, type = 'success') {
  toastEl.textContent = message;
  toastEl.className = `toast ${type}`;
  toastEl.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toastEl.classList.add('hidden'), 2600);
}

function esc(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function guildIconUrl(guild) {
  if (guild && guild.icon) {
    return `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png?size=96`;
  }
  return null;
}

function guildInitial(name) {
  if (!name) return '?';
  const words = name.trim().split(/\s+/);
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

function guildIconHTML(guild, sizeClass = '') {
  const url = guildIconUrl(guild);
  if (url) return `<img src="${esc(url)}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${esc(guildInitial(guild.name))}'}))" />`;
  return esc(guildInitial(guild.name));
}

function userAvatarUrl(user) {
  if (user && user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`;
  }
  return null;
}

function renderUserMenu(user) {
  const menu = document.getElementById('user-menu');
  if (!user) { menu.classList.add('hidden'); return; }
  menu.classList.remove('hidden');
  const url = userAvatarUrl(user);
  const avatarHTML = url
    ? `<img class="user-avatar" src="${esc(url)}" alt="" />`
    : `<span class="user-avatar">${esc((user.username || '?')[0].toUpperCase())}</span>`;
  menu.innerHTML = `
    ${avatarHTML}
    <span class="user-name">${esc(user.globalName || user.username || 'User')}</span>
    <button class="logout-btn" id="logout-btn">Log out</button>
  `;
  document.getElementById('logout-btn').addEventListener('click', () => {
    window.location.href = '/logout';
  });
}

// ── Router ─────────────────────────────────────────────────────────────────

const routes = [
  { match: /^\/(dashboard)?\/?$/, view: renderOverview },
  { match: /^\/docs\/?$/, view: renderDocs },
  { match: /^\/guild\/(\d+)(?:\/(\w+))?$/, view: renderGuildSettings },
];

async function router() {
  const path = window.location.pathname;
  for (const route of routes) {
    const m = path.match(route.match);
    if (m) {
      app.innerHTML = '<div class="splash"><div class="spinner"></div><p>Loading…</p></div>';
      try {
        await route.view(m);
      } catch (err) {
        console.error('Route error:', err);
        if (err.status === 401) { window.location.href = '/login'; return; }
        app.innerHTML = `<div class="card"><div class="alert alert-error">${esc(err.message || 'Something went wrong.')}</div></div>`;
      }
      return;
    }
  }
  app.innerHTML = '<div class="card"><h2>Page not found</h2><p>The page you requested does not exist.</p><p><a href="/" data-link>← Back to dashboard</a></p></div>';
}

document.addEventListener('click', (e) => {
  const link = e.target.closest('a[data-link]');
  if (!link) return;
  const href = link.getAttribute('href');
  if (!href || href.startsWith('http') || href.startsWith('#')) return;
  e.preventDefault();
  history.pushState({}, '', href);
  router();
});

window.addEventListener('popstate', router);

// ── Boot ───────────────────────────────────────────────────────────────────

async function boot() {
  try {
    const me = await api('/api/me');
    renderUserMenu(me.user);
    if (me.clientId) window.__clientId = me.clientId;
  } catch (err) {
    if (err.status === 401) { renderLogin(); return; }
  }
  router();
}

// Render the login screen. If the server bounced us back to /login?error=...,
// show a human-readable reason so the failure isn't silent (the most common
// cause is the session store not persisting on Vercel — e.g. Postgres SSL).
const LOGIN_ERRORS = {
  missing_code: 'Authorization code was missing from the Discord callback.',
  auth_failed: 'Discord sign-in failed. Please try again.',
  session_failed: 'Signed in to Discord, but the server could not save your session. This usually means the database connection is failing on Vercel (check DATABASE_URL / SSL and that the primebot_dashboard_session table is reachable).',
};

// ── Login screen ───────────────────────────────────────────────────────────

// Count up from 0 → target with an ease-out curve.
function animateCount(el, target, duration = 1200) {
  const start = performance.now();
  const from = 0;
  const tick = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
    el.textContent = Math.round(from + (target - from) * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// Render a conic-gradient donut (no canvas needed) inside an element.
function renderDonut(el, percent, colorVar) {
  const pct = Math.max(0, Math.min(100, percent));
  el.style.background = `conic-gradient(var(${colorVar}) ${pct * 3.6}deg, var(--border) 0deg)`;
  el.querySelector('.donut-pct').textContent = `${pct}%`;
}

function renderLogin() {
  document.querySelector('.topnav').style.display = 'none';
  const params = new URLSearchParams(window.location.search);
  const errorKey = params.get('error');
  const errorMsg = errorKey && LOGIN_ERRORS[errorKey];
  const errorHTML = errorMsg
    ? `<div class="alert alert-error" style="margin:0 0 16px;text-align:left">${esc(errorMsg)}</div>`
    : '';
  app.innerHTML = `
    <div class="login-wrap">
      <div class="login-hero">⚡</div>
      <h1 class="login-title">PrimeBot Dashboard</h1>
      ${errorHTML}
      <p class="login-sub">Sign in with Discord to configure PrimeBot for the servers you manage — welcome messages, leveling, prefixes, auto-reactions and more, all in one place.</p>
      <a href="/login" class="btn btn-discord">🚪 Login with Discord</a>
      <a href="/docs" class="btn btn-secondary" data-link>📖 Documentation</a>

      <div class="stats-band" id="stats-band" aria-live="polite">
        <div class="stats-band-head">
          <span class="stats-band-title">Live across the platform</span>
          <span class="stats-band-sub" id="stats-sub">Loading live stats…</span>
        </div>
        <div class="stats-cards" id="stats-cards">
          <div class="stat-card stat-primary">
            <div class="stat-icon">🏰</div>
            <div class="stat-value" id="stat-servers" data-target="0">0</div>
            <div class="stat-label">Servers configured</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">🖼️</div>
            <div class="stat-value" id="stat-banners" data-target="0">0</div>
            <div class="stat-label">Custom welcome banners</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">🤖</div>
            <div class="stat-value" id="stat-version">—</div>
            <div class="stat-label">Bot version</div>
          </div>
        </div>
        <div class="stats-chart-wrap">
          <div class="stats-chart-head">Feature adoption</div>
          <div class="donut-grid">
            <div class="donut-item">
              <div class="donut" id="donut-leveling"><span class="donut-pct">0%</span></div>
              <div class="donut-label">📈 Leveling</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-welcome"><span class="donut-pct">0%</span></div>
              <div class="donut-label">👋 Welcome</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-reactions"><span class="donut-pct">0%</span></div>
              <div class="donut-label">🔁 Auto-reactions</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-broadcasts"><span class="donut-pct">0%</span></div>
              <div class="donut-label">📢 Broadcasts</div>
            </div>
          </div>
        </div>
      </div>

      <div class="feature-grid">
        <div class="feature"><div class="fi">👋</div><div class="ft">Welcome system</div><div class="fd">Custom messages, banners, DMs and channel routing.</div></div>
        <div class="feature"><div class="fi">📈</div><div class="ft">Leveling &amp; XP</div><div class="fd">Tune multipliers, cooldowns and level-up channels.</div></div>
        <div class="feature"><div class="fi">⚡</div><div class="ft">Command prefix</div><div class="fd">Set a per-server prefix instead of the default.</div></div>
        <div class="feature"><div class="fi">🔁</div><div class="ft">Auto-reactions</div><div class="fd">Trigger emojis on matching messages automatically.</div></div>
      </div>
    </div>
  `;
  loadLoginStats();
}

// Fetch /api/stats and populate the login graphic. Fully optional — if the
// request fails (e.g. cold DB on Vercel) the page stays usable with zeros.
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
  if (versionEl) versionEl.textContent = stats.botVersion ? `v${stats.botVersion}` : '—';

  const f = stats.features || {};
  renderDonut(document.getElementById('donut-leveling'), f.leveling?.percent ?? 0, '--green');
  renderDonut(document.getElementById('donut-welcome'), f.welcome?.percent ?? 0, '--blurple');
  renderDonut(document.getElementById('donut-reactions'), f.autoReactions?.percent ?? 0, '--yellow');
  renderDonut(document.getElementById('donut-broadcasts'), f.broadcasts?.percent ?? 0, '--gold');
}

// ── Documentation page ─────────────────────────────────────────────────────

function renderDocs() {
  // Show the nav on the docs page (login hides it).
  document.querySelector('.topnav').style.display = '';

  const clientId = esc(window.__clientId || '');
  const inviteUrl = clientId
    ? `https://discord.com/oauth2/authorize?client_id=${clientId}&scope=bot&permissions=8`
    : 'https://discord.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&scope=bot&permissions=8';

  app.innerHTML = `
    <div class="docs">
      <div class="docs-hero">
        <div class="docs-hero-icon">📖</div>
        <h1 class="docs-title">PrimeBot Documentation</h1>
        <p class="docs-lead">Everything you need to set up, configure and manage PrimeBot for your Discord server — from inviting the bot to tuning welcome messages, leveling and auto-reactions.</p>
      </div>

      <nav class="docs-toc">
        <h3>On this page</h3>
        <ul>
          <li><a href="#getting-started" data-link>Getting started</a></li>
          <li><a href="#login" data-link>Logging in</a></li>
          <li><a href="#servers" data-link>Your servers</a></li>
          <li><a href="#welcome" data-link>Welcome system</a></li>
          <li><a href="#leveling" data-link>Leveling &amp; XP</a></li>
          <li><a href="#prefix" data-link>Command prefix</a></li>
          <li><a href="#reactions" data-link>Auto-reactions</a></li>
          <li><a href="#broadcast" data-link>Broadcasts</a></li>
          <li><a href="#commands" data-link>Command reference</a></li>
          <li><a href="#faq" data-link>FAQ &amp; troubleshooting</a></li>
        </ul>
      </nav>

      <section id="getting-started" class="docs-section">
        <h2>1 · Getting started</h2>
        <p>PrimeBot is a community engagement bot with welcome messages, an XP-based leveling system, polls, giveaways, ticketing, moderation and more. To use it in your server you first need to invite it.</p>
        <ol class="docs-steps">
          <li>
            <strong>Invite PrimeBot to your server.</strong><br />
            Use the official invite link with administrator permissions so all features work out of the box:
            <div class="docs-code-row"><code class="docs-code">${inviteUrl}</code><a class="btn btn-primary btn-sm" href="${inviteUrl}" target="_blank" rel="noopener">Open invite</a></div>
          </li>
          <li><strong>Make sure you have permissions.</strong> You need the <em>Manage Server</em> permission (or be the server owner) to configure PrimeBot through this dashboard.</li>
          <li><strong>Log in below.</strong> The dashboard uses Discord OAuth2, so you sign in with the same Discord account you use to manage your server.</li>
        </ol>
      </section>

      <section id="login" class="docs-section">
        <h2>2 · Logging in</h2>
        <p>Click <strong>Login with Discord</strong> on the home screen. You'll be sent to Discord to authorize the dashboard to read your username and the list of servers you manage. We never see your password, and you can revoke access at any time from <em>Discord → Settings → Authorized Apps</em>.</p>
        <div class="docs-callout docs-callout-info">
          <strong>Privacy:</strong> The dashboard only requests the <code>identify</code> and <code>guilds</code> scopes. Your access token is stored in a server-side session tied to a secure cookie — it is never exposed to the browser or shared with third parties.
        </div>
      </section>

      <section id="servers" class="docs-section">
        <h2>3 · Your servers</h2>
        <p>After logging in you'll land on the <strong>Servers</strong> overview. It lists every server where you have <em>Manage Server</em> rights, and shows whether PrimeBot is present. Click any server with the green “PrimeBot is here” badge to open its configuration.</p>
        <p>Servers where the bot isn't a member are shown separately with an <strong>Invite</strong> button — use it to add PrimeBot, then refresh the list.</p>
      </section>

      <section id="welcome" class="docs-section">
        <h2>4 · Welcome system</h2>
        <p>Greet new members with a custom message, an auto-generated banner, and an optional DM. Configure:</p>
        <ul class="docs-list">
          <li><strong>Enabled</strong> — turn the whole welcome system on or off.</li>
          <li><strong>Channel</strong> — where welcome messages are posted (leave empty to DM only).</li>
          <li><strong>Message</strong> — supports placeholders such as <code>{user}</code> (mention) and <code>{server}</code> (server name).</li>
          <li><strong>Color</strong> — the accent color of the welcome card, as a hex code (e.g. <code>#5865F2</code>).</li>
          <li><strong>Banner URL</strong> — an optional image shown at the top of the card.</li>
          <li><strong>DM enabled + DM message</strong> — send a private welcome message to the new member.</li>
          <li><strong>Member count / join date / account age</strong> — toggle extra stats on the welcome card.</li>
        </ul>
      </section>

      <section id="leveling" class="docs-section">
        <h2>5 · Leveling &amp; XP</h2>
        <p>Members earn XP by chatting. Tune the system per server:</p>
        <ul class="docs-list">
          <li><strong>Enabled</strong> — turn leveling on or off.</li>
          <li><strong>XP multiplier</strong> — scales how fast members earn XP (0–5). <code>1.0</code> is default.</li>
          <li><strong>XP cooldown</strong> — minimum seconds between XP awards (5–300s) to prevent spam.</li>
          <li><strong>Level-up channel</strong> — where level-up announcements are posted (leave empty to disable announcements).</li>
        </ul>
      </section>

      <section id="prefix" class="docs-section">
        <h2>6 · Command prefix</h2>
        <p>PrimeBot responds to both slash commands and a text prefix. Set a per-server prefix here (the default is <code>$</code>). Prefixes can be 1–5 characters and must not contain spaces.</p>
      </section>

      <section id="reactions" class="docs-section">
        <h2>7 · Auto-reactions</h2>
        <p>Have PrimeBot automatically react to messages that match keywords. Enable the feature, then add keyword → emoji pairs. When a message contains a matching keyword, the bot adds the configured emoji reaction.</p>
      </section>

      <section id="broadcast" class="docs-section">
        <h2>8 · Broadcasts</h2>
        <p>Opt a server into receiving bot-wide broadcast announcements. Toggle <strong>Receive broadcasts</strong> and pick a <strong>broadcast channel</strong>. Messages sent by the bot owner are delivered to every opted-in server's chosen channel.</p>
      </section>

      <section id="commands" class="docs-section">
        <h2>9 · Command reference</h2>
        <p>PrimeBot ships with 40+ commands. Here are the main categories. Slash commands use <code>/</code>; prefix commands use your server's prefix (default <code>$</code>).</p>
        <div class="docs-cmd-grid">
          <div class="docs-cmd-card">
            <h4>🛡️ Moderation</h4>
            <ul><li><code>ban</code> / <code>kick</code> — remove members</li><li><code>purge</code> — bulk-delete messages</li><li><code>lock</code> / <code>unlock</code> — lock channels</li><li><code>nuke</code> — clear &amp; recreate a channel</li><li><code>hide</code> / <code>unhide</code> — hide channels</li><li><code>move</code> — move members</li><li><code>role</code> — assign roles</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>🎉 Engagement</h4>
            <ul><li><code>poll</code> / <code>endpoll</code> — simple polls</li><li><code>lpoll</code> / <code>endgame</code> — live polls</li><li><code>giveaway</code> / <code>reroll</code> / <code>end</code> — giveaways</li><li><code>counting</code> — counting game</li><li><code>tictactoe</code> — play tic-tac-toe</li><li><code>truthdare</code> — truth or dare</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>🎫 Tickets &amp; Support</h4>
            <ul><li><code>createticket</code> / <code>ticket</code> — open tickets</li><li><code>tickethistory</code> — view past tickets</li><li><code>categories</code> — manage ticket categories</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>🎂 Community</h4>
            <ul><li><code>birthday</code> — set birthdays</li><li><code>leveling</code> — view XP/rank</li><li><code>welcomeconfig</code> — quick welcome setup</li><li><code>about</code> — bot info</li><li><code>help</code> — command help</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>📣 Broadcasting</h4>
            <ul><li><code>broadcast</code> — send a broadcast</li><li><code>broadcastsettings</code> — configure reception</li><li><code>updates</code> — bot update notes</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>🧰 Utility</h4>
            <ul><li><code>echo</code> — repeat text</li><li><code>snipe</code> — recover deleted messages</li><li><code>sync</code> — sync server settings</li><li><code>np</code> — now playing</li><li><code>rm</code> / <code>ses</code> — session tools</li><li><code>beta</code> / <code>betaserver</code> — beta features</li></ul>
          </div>
        </div>
      </section>

      <section id="faq" class="docs-section">
        <h2>10 · FAQ &amp; troubleshooting</h2>
        <div class="docs-faq">
          <details>
            <summary>My server isn't showing up in the list.</summary>
            <p>You need the <strong>Manage Server</strong> permission in that server. Ask an admin to grant it, or have them log in and configure the bot. Discord also caches the guild list briefly — try logging out and back in if you just got promoted.</p>
          </details>
          <details>
            <summary>A server shows “PrimeBot is not here”.</summary>
            <p>Click the <strong>Invite</strong> button on that server's card to add PrimeBot. After the bot joins, refresh the servers list.</p>
          </details>
          <details>
            <summary>My changes don't seem to take effect.</summary>
            <p>PrimeBot reads its configuration from the database on every command and event, so changes are effective immediately. If something still looks wrong, make sure you clicked <strong>Save</strong> on the settings panel and saw the success toast.</p>
          </details>
          <details>
            <summary>I got logged out / my session expired.</summary>
            <p>Sessions last 7 days. If you're prompted to log in again, just click <strong>Login with Discord</strong>. This can happen after the bot's OAuth credentials are rotated.</p>
          </details>
          <details>
            <summary>Is my data safe?</summary>
            <p>The dashboard only reads your Discord identity and guild list. Configuration changes are written to the same PostgreSQL database the bot uses. No messages are logged through the dashboard.</p>
          </details>
        </div>
      </section>

      <div class="docs-cta">
        <h3>Ready to configure your server?</h3>
        <p>Log in with Discord to manage PrimeBot across all your servers.</p>
        <a href="/login" class="btn btn-discord">🚪 Login with Discord</a>
        <a href="/" class="btn btn-secondary" data-link>← Back to dashboard</a>
      </div>
    </div>
  `;
}

// ── Overview (server list) ─────────────────────────────────────────────────

async function renderOverview() {
  const data = await api('/api/guilds');
  const guilds = data.guilds || [];
  const manageable = guilds.filter(g => g.botPresent);
  const absent = guilds.filter(g => !g.botPresent);

  const statsHTML = `
    <div class="stats">
      <div class="stat"><div class="sv">${guilds.length}</div><div class="sl">Servers you manage</div></div>
      <div class="stat"><div class="sv">${manageable.length}</div><div class="sl">With PrimeBot</div></div>
      <div class="stat"><div class="sv">${manageable.filter(g => g.welcomeEnabled).length}</div><div class="sl">Welcome enabled</div></div>
      <div class="stat"><div class="sv">${manageable.filter(g => g.levelingEnabled).length}</div><div class="sl">Leveling enabled</div></div>
    </div>
  `;

  let listHTML = '';
  if (manageable.length === 0 && absent.length === 0) {
    listHTML = `
      <div class="guild-empty">
        <p style="font-size:40px;margin:0 0 8px">🔍</p>
        <p>You don't manage any servers yet, or PrimeBot isn't in any of them.</p>
        <p style="margin-top:12px"><a class="btn btn-secondary" href="https://discord.com/oauth2/authorize?client_id=${esc(window.__clientId||'')}&scope=bot&permissions=8" target="_blank" rel="noopener">Invite PrimeBot to a server</a></p>
      </div>
    `;
  } else {
    if (manageable.length) {
      listHTML += `<div class="guild-grid">` + manageable.map(g => guildCardHTML(g, true)).join('') + `</div>`;
    }
    if (absent.length) {
      listHTML += `
        <h3 style="margin:28px 0 12px;font-size:15px;color:var(--text-dim)">PrimeBot not yet added</h3>
        <div class="guild-grid">` + absent.map(g => guildCardHTML(g, false)).join('') + `</div>
      `;
    }
  }

  app.innerHTML = `
    <div class="page-head">
      <h1>Your servers</h1>
      <p>Pick a server to configure PrimeBot. Only servers where you have <strong>Manage Server</strong> permission are shown.</p>
    </div>
    ${statsHTML}
    ${listHTML}
  `;

  app.querySelectorAll('.guild-card[data-guild]').forEach(card => {
    card.addEventListener('click', () => {
      history.pushState({}, '', `/guild/${card.dataset.guild}`);
      router();
    });
  });
}

function guildCardHTML(g, present) {
  const tags = [];
  tags.push(`<span class="tag prefix">${esc(g.prefix || '$')} prefix</span>`);
  if (present) {
    tags.push(g.welcomeEnabled ? `<span class="tag on">👋 Welcome</span>` : `<span class="tag off">Welcome off</span>`);
    tags.push(g.levelingEnabled ? `<span class="tag on">📈 Leveling</span>` : `<span class="tag off">Leveling off</span>`);
  } else {
    tags.push(`<span class="tag absent">Bot not added</span>`);
  }

  const iconHTML = guildIconHTML(g);
  const members = g.approximate_member_count != null
    ? `${Number(g.approximate_member_count).toLocaleString()} members`
    : '';

  return `
    <div class="guild-card" data-guild="${esc(g.id)}">
      <div class="guild-head">
        <div class="guild-icon">${iconHTML}</div>
        <div>
          <div class="guild-name">${esc(g.name)}</div>
          <div class="guild-meta">${members}${g.owner ? ' · Owner' : ''}</div>
        </div>
      </div>
      <div class="guild-tags">${tags.join('')}</div>
    </div>
  `;
}

// ── Guild settings page ────────────────────────────────────────────────────

let guildState = null; // { guild, config, channels }

async function renderGuildSettings(match) {
  const guildId = match[1];
  const initialTab = match[2] || 'welcome';

  let data;
  try {
    data = await api(`/api/guilds/${guildId}/config`);
  } catch (err) {
    if (err.status === 403) {
      app.innerHTML = `<div class="card"><div class="alert alert-error">${esc(err.message)}</div><p><a href="/" data-link>← Back to servers</a></p></div>`;
      return;
    }
    if (err.status === 404) {
      app.innerHTML = `
        <div class="card">
          <div class="alert alert-warn">PrimeBot is not in this server.</div>
          <p>To configure PrimeBot here, add it to your server first.</p>
          <p style="margin-top:16px"><a class="btn btn-primary" href="https://discord.com/oauth2/authorize?client_id=${esc(window.__clientId||'')}&scope=bot&permissions=8" target="_blank" rel="noopener">Invite PrimeBot</a></p>
          <p style="margin-top:12px"><a href="/" data-link>← Back to servers</a></p>
        </div>
      `;
      return;
    }
    if (err.status === 503) {
      app.innerHTML = `
        <div class="card">
          <div class="alert alert-error">${esc(err.message)}</div>
          <p>The dashboard server could not reach Discord as PrimeBot. An admin needs to set <code>DISCORD_TOKEN</code> (or <code>DASHBOARD_BOT_TOKEN</code>) in this Vercel project's Environment Variables, then redeploy.</p>
          <p style="margin-top:12px"><a href="/" data-link>← Back to servers</a></p>
        </div>
      `;
      return;
    }
    throw err;
  }

  guildState = { guild: data.guild, config: data.config, channels: [] };

  // Lazy-load channels for selectors.
  api(`/api/guilds/${guildId}/channels`)
    .then(d => {
      guildState.channels = d.channels || [];
      populateChannelSelects();
    })
    .catch(() => { /* surfaced via empty selectors */ });

  app.innerHTML = `
    <div class="breadcrumb"><a href="/" data-link>Servers</a> <span>/</span> <span>${esc(data.guild.name)}</span></div>
    <div class="guild-header-card card">
      <div class="guild-icon">${guildIconHTML(data.guild)}</div>
      <div>
        <h1>${esc(data.guild.name)}</h1>
        <div class="meta">${data.guild.approximate_member_count != null ? Number(data.guild.approximate_member_count).toLocaleString() + ' members' : ''}${data.guild.userIsOwner ? ' · You are the owner' : ''}</div>
      </div>
    </div>

    <div class="tabs">
      <button class="tab" data-tab="welcome">👋 Welcome</button>
      <button class="tab" data-tab="leveling">📈 Leveling</button>
      <button class="tab" data-tab="prefix">⚡ Prefix</button>
      <button class="tab" data-tab="reactions">🔁 Auto-Reactions</button>
      <button class="tab" data-tab="broadcast">📢 Broadcasts</button>
    </div>

    <div id="tab-welcome" class="tab-panel">${welcomePanelHTML(data.config.welcome)}</div>
    <div id="tab-leveling" class="tab-panel">${levelingPanelHTML(data.config.server)}</div>
    <div id="tab-prefix" class="tab-panel">${prefixPanelHTML(data.config.server)}</div>
    <div id="tab-reactions" class="tab-panel">${reactionsPanelHTML(data.config.server)}</div>
    <div id="tab-broadcast" class="tab-panel">${broadcastPanelHTML(data.config.server)}</div>
  `;

  selectTab(initialTab);
  bindSettingsEvents(guildId);
}

function selectTab(name) {
  app.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  app.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));
  const url = `/guild/${guildState.guild.id}/${name}`;
  if (window.location.pathname !== url) history.replaceState({}, '', url);
}

function populateChannelSelects() {
  if (!guildState) return;
  const opts = guildState.channels.map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
  app.querySelectorAll('select[data-channel-select]').forEach(sel => {
    const current = sel.value;
    sel.innerHTML = `<option value="">— None / default —</option>` + opts;
    if (current) sel.value = current;
  });
}

// ── Panel templates ────────────────────────────────────────────────────────

function welcomePanelHTML(w) {
  const s = w || {};
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">👋</span> Welcome messages</span></div>
      <p class="card-desc">Greet new members with a customizable message, banner and optional DM.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable welcome messages</div>
          <div class="sl-desc">Send a welcome message when a member joins the server.</div>
        </div>
        <label class="switch"><input type="checkbox" id="welcome-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="welcome-channel">Welcome channel</label>
        <select id="welcome-channel" data-channel-select><option value="">— Default (system channel) —</option></select>
        <div class="field-hint">Where the welcome message is posted.</div>
      </div>

      <div class="field">
        <label class="field-label" for="welcome-message">Welcome message</label>
        <textarea id="welcome-message" placeholder="Welcome to the server, {member}! Enjoy your stay!">${esc(s.message || '')}</textarea>
        <div class="field-hint">Placeholders: <code>{member}</code>, <code>{username}</code>, <code>{server}</code></div>
      </div>

      <div class="field">
        <label class="field-label" for="welcome-banner">Banner image URL</label>
        <input type="url" id="welcome-banner" value="${esc(s.bannerUrl || '')}" placeholder="https://…/banner.png" />
        <div class="field-hint">Optional image shown on the welcome embed.</div>
      </div>

      <div class="field">
        <label class="field-label">Embed color</label>
        <div class="color-field">
          <input type="color" id="welcome-color" value="${esc(s.color || '#5865F2')}" />
          <input type="text" id="welcome-color-text" value="${esc(s.color || '#5865F2')}" style="flex:1" />
        </div>
      </div>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Send a welcome DM</div>
          <div class="sl-desc">Privately message new members with a custom onboarding note.</div>
        </div>
        <label class="switch"><input type="checkbox" id="welcome-dm-enabled" ${s.dmEnabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="welcome-dm-message">DM message</label>
        <textarea id="welcome-dm-message" placeholder="Hey {username}! Welcome to **{server}**!">${esc(s.dmMessage || '')}</textarea>
      </div>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Show member count</div></div>
        <label class="switch"><input type="checkbox" id="welcome-show-count" ${s.showMemberCount ? 'checked' : ''}/><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Show join date</div></div>
        <label class="switch"><input type="checkbox" id="welcome-show-join" ${s.showJoinDate ? 'checked' : ''}/><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Show account age</div></div>
        <label class="switch"><input type="checkbox" id="welcome-show-age" ${s.showAccountAge ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="welcome-title">Custom title (optional)</label>
        <input type="text" id="welcome-title" value="${esc(s.customTitle || '')}" placeholder="Welcome!" />
      </div>
      <div class="field">
        <label class="field-label" for="welcome-footer">Custom footer (optional)</label>
        <input type="text" id="welcome-footer" value="${esc(s.customFooter || '')}" placeholder="Powered by PrimeBot" />
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="welcome">Save welcome settings</button>
      </div>
    </div>
  `;
}

function levelingPanelHTML(server) {
  const lev = server?.leveling || {};
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">📈</span> Leveling &amp; XP</span></div>
      <p class="card-desc">Reward members with XP for chatting and earn badges as they level up.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable leveling</div>
          <div class="sl-desc">Track XP and levels for members in this server.</div>
        </div>
        <label class="switch"><input type="checkbox" id="leveling-enabled" ${lev.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="leveling-channel">Level-up announcement channel</label>
        <select id="leveling-channel" data-channel-select><option value="">— Same channel as the message —</option></select>
        <div class="field-hint">Where level-up messages are sent.</div>
      </div>

      <div class="field">
        <label class="field-label" for="leveling-multiplier">XP multiplier</label>
        <input type="number" id="leveling-multiplier" min="0.1" max="5" step="0.1" value="${esc(lev.xpMultiplier ?? 1)}" />
        <div class="field-hint">Multiply earned XP by this factor (0.1 – 5.0). Default is 1.</div>
      </div>

      <div class="field">
        <label class="field-label" for="leveling-cooldown">XP cooldown (seconds)</label>
        <input type="number" id="leveling-cooldown" min="5" max="300" step="1" value="${esc(lev.xpCooldown ? lev.xpCooldown / 1000 : 60)}" />
        <div class="field-hint">Time between XP gains per user (5 – 300 seconds).</div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="leveling">Save leveling settings</button>
      </div>
    </div>
  `;
}

function prefixPanelHTML(server) {
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">⚡</span> Command prefix</span></div>
      <p class="card-desc">Set a custom prefix for text commands in this server (max 3 characters, no spaces).</p>
      <div class="field">
        <label class="field-label" for="prefix-value">Prefix</label>
        <input type="text" id="prefix-value" maxlength="3" value="${esc(server?.prefix || '$')}" style="max-width:120px" />
        <div class="field-hint">Members will type this before text commands, e.g. <code>${esc(server?.prefix || '$')}help</code></div>
      </div>
      <div class="form-actions">
        <button class="btn btn-primary" data-save="prefix">Save prefix</button>
      </div>
    </div>
  `;
}

function reactionsPanelHTML(server) {
  const ar = server?.autoReactions || { enabled: false, reactions: [] };
  const rows = (ar.reactions || []).map((r, i) => reactionRowHTML(r, i)).join('');
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">🔁</span> Auto-reactions</span></div>
      <p class="card-desc">Automatically react to messages containing a trigger word with an emoji.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable auto-reactions</div>
          <div class="sl-desc">Master switch for all trigger rules below.</div>
        </div>
        <label class="switch"><input type="checkbox" id="reactions-enabled" ${ar.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label">Reaction rules</label>
        <div class="reactions-list" id="reactions-list">${rows}</div>
        <button class="btn btn-secondary" id="reaction-add">+ Add rule</button>
        <div class="field-hint">Trigger is matched as a substring of the message.</div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="reactions">Save auto-reactions</button>
      </div>
    </div>
  `;
}

function reactionRowHTML(r, i) {
  return `
    <div class="reaction-row" data-index="${i}">
      <input type="text" class="r-trigger" value="${esc(r.trigger || '')}" placeholder="trigger word" />
      <input type="text" class="r-emoji" value="${esc(r.emoji || '')}" placeholder="🎉" maxlength="30" />
      <button class="reaction-remove" type="button">✕</button>
    </div>
  `;
}

function broadcastPanelHTML(server) {
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">📢</span> Broadcasts</span></div>
      <p class="card-desc">Choose whether this server receives official PrimeBot broadcast announcements.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Receive broadcasts</div>
          <div class="sl-desc">Allow PrimeBot announcements to be posted in this server.</div>
        </div>
        <label class="switch"><input type="checkbox" id="broadcast-enabled" ${server?.receiveBroadcasts ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="broadcast-channel">Broadcast channel</label>
        <select id="broadcast-channel" data-channel-select><option value="">— None —</option></select>
        <div class="field-hint">Where broadcast messages are posted.</div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="broadcast">Save broadcast settings</button>
      </div>
    </div>
  `;
}

// ── Event binding ──────────────────────────────────────────────────────────

function bindSettingsEvents(guildId) {
  app.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => selectTab(t.dataset.tab));
  });

  // Sync color picker + text input.
  const colorPicker = app.querySelector('#welcome-color');
  const colorText = app.querySelector('#welcome-color-text');
  if (colorPicker && colorText) {
    colorPicker.addEventListener('input', () => { colorText.value = colorPicker.value; });
    colorText.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(colorText.value)) colorPicker.value = colorText.value;
    });
  }

  // Add/remove reaction rows.
  const list = app.querySelector('#reactions-list');
  app.querySelector('#reaction-add')?.addEventListener('click', () => {
    if (!list) return;
    const idx = list.children.length;
    list.insertAdjacentHTML('beforeend', reactionRowHTML({}, idx));
    bindReactionRemovals();
  });
  bindReactionRemovals();

  // Save buttons.
  app.querySelectorAll('[data-save]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const kind = btn.dataset.save;
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = 'Saving…';
      try {
        await saveSettings(guildId, kind);
        toast('Saved successfully', 'success');
      } catch (err) {
        toast(err.message || 'Failed to save', 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  });
}

function bindReactionRemovals() {
  app.querySelectorAll('.reaction-remove').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => {
      btn.closest('.reaction-row')?.remove();
    });
  });
}

async function saveSettings(guildId, kind) {
  if (kind === 'welcome') {
    const body = {
      enabled: app.querySelector('#welcome-enabled').checked,
      channelId: app.querySelector('#welcome-channel').value || null,
      message: app.querySelector('#welcome-message').value,
      bannerUrl: app.querySelector('#welcome-banner').value || null,
      color: app.querySelector('#welcome-color').value,
      dmEnabled: app.querySelector('#welcome-dm-enabled').checked,
      dmMessage: app.querySelector('#welcome-dm-message').value,
      showMemberCount: app.querySelector('#welcome-show-count').checked,
      showJoinDate: app.querySelector('#welcome-show-join').checked,
      showAccountAge: app.querySelector('#welcome-show-age').checked,
      customTitle: app.querySelector('#welcome-title').value || null,
      customFooter: app.querySelector('#welcome-footer').value || null,
    };
    await api(`/api/guilds/${guildId}/welcome`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'leveling') {
    const body = {
      leveling: {
        enabled: app.querySelector('#leveling-enabled').checked,
        levelUpChannelId: app.querySelector('#leveling-channel').value || null,
        xpMultiplier: Number(app.querySelector('#leveling-multiplier').value),
        xpCooldown: Number(app.querySelector('#leveling-cooldown').value),
      },
    };
    await api(`/api/guilds/${guildId}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'prefix') {
    const prefix = app.querySelector('#prefix-value').value.trim();
    if (!prefix) throw new Error('Prefix cannot be empty.');
    await api(`/api/guilds/${guildId}/server`, { method: 'PATCH', body: JSON.stringify({ prefix }) });
  } else if (kind === 'reactions') {
    const reactions = [];
    app.querySelectorAll('#reactions-list .reaction-row').forEach(row => {
      const trigger = row.querySelector('.r-trigger').value.trim();
      const emoji = row.querySelector('.r-emoji').value.trim();
      if (trigger && emoji) reactions.push({ trigger, emoji, caseSensitive: false });
    });
    const body = {
      autoReactions: {
        enabled: app.querySelector('#reactions-enabled').checked,
        reactions,
      },
    };
    await api(`/api/guilds/${guildId}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'broadcast') {
    const body = {
      receiveBroadcasts: app.querySelector('#broadcast-enabled').checked,
      broadcastChannelId: app.querySelector('#broadcast-channel').value || null,
    };
    await api(`/api/guilds/${guildId}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  }
}

// ── Go ─────────────────────────────────────────────────────────────────────

boot();
