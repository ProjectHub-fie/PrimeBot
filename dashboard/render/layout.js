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
// page (pass `login: true`).
function navHTML({ active, user, login }) {
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
    return `
    <header class="topbar">
      <div class="topbar-inner">
        <a href="/" class="brand">
          <span class="brand-mark">⚡</span>
          <span class="brand-name">PrimeBot</span>
          <span class="brand-sub">Dashboard</span>
        </a>
        <nav class="topnav">
          ${link('/', 'Servers', 'servers')}
          ${link('/dashboard', 'Overview', 'overview')}
          ${link('/stats', 'Stats', 'stats')}
          ${link('/live/polls', 'Live Polls', 'live-polls')}
          ${link('/live/giveaways', 'Live Giveaways', 'live-giveaways')}
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
        scripts = [],
        locals = {},
    } = opts;

    const version = locals.botVersion || constants.BOT_VERSION;
    const scriptTags = scripts
        .map((s) => `<script src="${esc(s)}"></script>`)
        .join('\n  ');
    const logoutScript = login ? '' : `<script>document.getElementById('logout-btn')?.addEventListener('click',()=>{window.location.href='/logout'});</script>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(title)}</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%E2%9A%99%EF%B8%8F%3C/text%3E%3C/svg%3E" />
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  ${navHTML({ active, user, login })}
  <main id="app" class="container">
    ${body}
  </main>
  <footer class="footer">
    <span>PrimeBot <span id="bot-version">${esc(version)}</span> · Control panel for server admins</span>
  </footer>
  <div id="toast" class="toast hidden"></div>
  <script src="/js/common.js"></script>
  ${scriptTags}
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
};
