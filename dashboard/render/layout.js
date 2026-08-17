/**
 * Server-side HTML rendering for the PrimeBot dashboard.
 *
 * The dashboard used to be a single-page app (one index.html + one app.js with
 * client-side pushState routing). It is now a multi-page app: each route is a
 * real HTML page rendered on the server by Express. This module holds the
 * shared HTML shell (doctype, header/nav, footer) plus the small set of pure
 * helpers every page reuses (escaping, guild/channel/role markup). The
 * per-page renderers in dashboard/render/pages/*.js build the <main> content.
 *
 * All /api/* JSON routes in server.js are unchanged — the page scripts just
 * POST/PATCH to them instead of the old SPA fetching config + rendering.
 */

const constants = require('../constants');
const { svgIcon } = require('../public/js/icons');

function esc(str) {
    if (str == null) return '';
    return String(str).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
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

function guildIconHTML(guild) {
    const url = guildIconUrl(guild);
    if (url) {
        const fallback = esc(guildInitial(guild && guild.name));
        return `<img src="${esc(url)}" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{textContent:'${fallback}'}))" />`;
    }
    return esc(guildInitial(guild && guild.name));
}

function userAvatarUrl(user) {
    if (user && user.avatar) {
        return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`;
    }
    return null;
}

// <option> list for a channel <select>. `selected` is the currently chosen id.
function channelOptions(channels, selected) {
    const opts = channels.map((c) =>
        `<option value="${esc(c.id)}"${String(selected) === String(c.id) ? ' selected' : ''}>${esc(c.name)}</option>`
    ).join('');
    return `<option value="">— None / default —</option>${opts}`;
}

// <option> list for a role <select>.
function roleOptions(roles, selected) {
    const opts = roles.map((r) =>
        `<option value="${esc(r.id)}"${String(selected) === String(r.id) ? ' selected' : ''}>${esc(r.name)}</option>`
    ).join('');
    return `<option value="">— None —</option>${opts}`;
}

// Top navigation. `active` highlights the matching link. Hidden on the login
// page (pass `login: true`). The back button (←) is hidden on the server
// selection page (`hideBack: true`) since there's nowhere meaningful to go
// back to from the dashboard root — it would just dump the user out of the app.
function navHTML({ active, user, login, hideBack }) {
    if (login) return '';
    const link = (href, label, key) =>
        `<a href="${esc(href)}" class="${active === key ? 'active' : ''}">${esc(label)}</a>`;
    let userMenu = '';
    if (user) {
        const url = userAvatarUrl(user);
        const avatar = url
            ? `<img class="user-avatar" src="${esc(url)}" alt="" />`
            : `<span class="user-avatar">${esc((user.username || '?')[0].toUpperCase())}</span>`;
        userMenu = `
      <span class="user-menu">
        ${avatar}
        <span class="user-name">${esc(user.globalName || user.username || 'User')}</span>
        <button class="logout-btn" id="logout-btn">Log out</button>
      </span>`;
    }
    const backBtn = hideBack ? '' : `<a href="javascript:history.back()" class="back-btn" aria-label="Go back to previous page" title="Go back to previous page">${svgIcon('arrowLeft', 'back-symbol')}</a>`;
    return `
    <header class="topbar">
      <div class="topbar-inner">
        ${backBtn}
        <a href="/" class="brand">
          <span class="brand-mark">${svgIcon('zap')}</span>
          <span class="brand-name">PrimeBot</span>
          <span class="brand-sub">Dashboard</span>
        </a>
        <nav class="topnav">
          ${link('/', 'Servers', 'servers')}
          ${link('/dashboard', 'Overview', 'overview')}
          ${link('/stats', 'Stats', 'stats')}
          ${link('/docs', 'Docs', 'docs')}
          ${userMenu}
        </nav>
      </div>
    </header>`;
}

/**
 * Wrap page body HTML in the full document shell.
 * @param {object} opts
 * @param {string} opts.title   <title> text
 * @param {string} opts.body    inner HTML for <main id="app">
 * @param {string} [opts.active] nav highlight key
 * @param {object} [opts.user]   logged-in user (for the nav menu)
 * @param {boolean} [opts.login] render the login variant (no nav)
 * @param {string[]} [opts.scripts] extra <script src> paths to include
 * @param {object} [opts.locals] extra top-level locals (botVersion etc.)
 */
function render(opts) {
    const {
        title = 'PrimeBot Dashboard',
        body = '',
        active,
        user,
        login = false,
        hideBack = false,
        scripts = [],
        locals = {},
    } = opts;

    const version = locals.botVersion || constants.BOT_VERSION;
    const scriptTags = scripts
        .map((s) => `<script src="${esc(s)}"></script>`)
        .join('\n  ');
    const logoutScript = login ? '' : `<script>document.getElementById('logout-btn')?.addEventListener('click',()=>{window.location.href='/logout'});</script>`;
    // Idle auto-logout: only on authenticated pages (the login page has no
    // session). Injects the configured window (SESSION_IDLE_TIMEOUT_MS) and
    // loads session-timeout.js, which drives the Page-Visibility countdown +
    // heartbeat. See dashboard/public/js/session-timeout.js.
    const idleTimeoutMs = parseInt(locals.idleTimeoutMs, 10) || constants.SESSION_IDLE_TIMEOUT_MS;
    const idleScript = login ? '' : `<script>window.__PRIMEBOT_IDLE_TIMEOUT_MS__=${idleTimeoutMs};</script>\n  <script src="/js/session-timeout.js"></script>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <meta name="theme-color" content="#0a0b10" />
  <meta name="color-scheme" content="dark" />
  <title>${esc(title)}</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%235865f2' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'/%3E%3C/svg%3E" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=Hanken+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  ${navHTML({ active, user, login, hideBack })}
  <main id="app" class="container">
    ${body}
  </main>
  <footer class="footer">
    <span>PrimeBot <span id="bot-version">${esc(version)}</span> · Control panel for server admins</span>
  </footer>
  <div id="toast" class="toast toast-hidden"></div>
  <script src="/js/icons.js"></script>
  <script src="/js/common.js"></script>
  ${scriptTags}
  ${idleScript}
  ${logoutScript}
</body>
</html>`;
}

module.exports = {
    esc,
    guildIconUrl,
    guildInitial,
    guildIconHTML,
    userAvatarUrl,
    channelOptions,
    roleOptions,
    navHTML,
    render,
    svgIcon,
};
