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

// Inline SVG icons for the top nav. Kept here so the nav is self-contained
// (no extra HTTP requests) and stays crisp at any DPI.
const NAV_ICONS = {
    servers: '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 5h18v4H3zm0 6h18v4H3zm0 6h18v4H3z"/><circle cx="6" cy="7" r="1" fill="currentColor"/><circle cx="6" cy="13" r="1" fill="currentColor"/><circle cx="6" cy="19" r="1" fill="currentColor"/></svg>',
    overview: '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h6V4H4v9zm0 7h6v-5H4v5zm10 0h6V11h-6v9zm0-16v5h6V4h-6z"/></svg>',
    live: '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M5.5 5.5a9 9 0 0 0 0 13M18.5 5.5a9 9 0 0 1 0 13M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7"/></svg>',
    docs: '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6H6zm8 1.5V8h4.5L14 3.5zM8 13h8v1.5H8V13zm0 3h8v1.5H8V16z"/></svg>',
    website: '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.93 6h-2.95a15.6 15.6 0 0 0-1.38-3.2A8.03 8.03 0 0 1 18.93 8zM12 4.04c.83 1.2 1.48 2.53 1.91 3.96h-3.82c.43-1.43 1.08-2.76 1.91-3.96zM4.26 14a7.96 7.96 0 0 1 0-4h3.38a16.5 16.5 0 0 0-.14 2c0 .68.05 1.35.14 2H4.26zm.81 2h2.95c.32 1.16.78 2.24 1.38 3.2A8.03 8.03 0 0 1 5.07 16zm2.95-8H5.07a8.03 8.03 0 0 1 4.33-3.2A15.6 15.6 0 0 0 8.02 8zM12 19.96c-.83-1.2-1.48-2.53-1.91-3.96h3.82c-.43 1.43-1.08 2.76-1.91 3.96zM14.34 14H9.66a14.6 14.6 0 0 1-.16-2c0-.68.06-1.35.16-2h4.68c.1.65.16 1.32.16 2 0 .68-.06 1.35-.16 2zm.25 5.2c.6-.96 1.06-2.04 1.38-3.2h2.95a8.03 8.03 0 0 1-4.33 3.2zm1.77-5.2c.09-.65.14-1.32.14-2 0-.68-.05-1.35-.14-2h3.38a7.96 7.96 0 0 1 0 4h-3.38z"/></svg>',
};

// Top navigation. `active` highlights the matching link. Hidden on the login
// page (pass `login: true`).
function navHTML({ active, user, login }) {
    if (login) return '';
    const link = (href, label, key, { icon = '', external = false } = {}) => {
        const cls = active === key ? 'active' : '';
        const extra = external ? ' target="_blank" rel="noopener"' : '';
        return `<a href="${esc(href)}" class="${cls}"${extra}>${icon}${esc(label)}</a>`;
    };
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
          ${link('/', 'Servers', 'servers', { icon: NAV_ICONS.servers })}
          ${link('/dashboard', 'Overview', 'overview', { icon: NAV_ICONS.overview })}
          ${link('/live', 'Live', 'live', { icon: NAV_ICONS.live })}
          ${link('/docs', 'Docs', 'docs', { icon: NAV_ICONS.docs })}
          ${link(constants.BOT_WEBSITE, 'Website', 'website', { icon: NAV_ICONS.website, external: true })}
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
