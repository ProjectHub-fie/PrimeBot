/* PrimeBot Dashboard — client-side SPA logic */

const app = document.getElementById('app');
const toastEl = document.getElementById('toast');

// Loggable event types. Kept in sync with utils/logEvents.js (shared by the bot).
const LOG_EVENTS = [
  { key: 'memberJoin',    label: 'Member joined',          icon: 'userPlus', category: 'Members' },
  { key: 'memberLeave',   label: 'Member left',            icon: 'userMinus', category: 'Members' },
  { key: 'memberBan',     label: 'Member banned',          icon: 'ban', category: 'Members' },
  { key: 'memberUnban',   label: 'Member unbanned',        icon: 'userCheck', category: 'Members' },
  { key: 'memberUpdate',  label: 'Member updated (roles / nickname)', icon: 'pencil', category: 'Members' },
  { key: 'messageDelete', label: 'Message deleted',        icon: 'trash', category: 'Messages' },
  { key: 'messageUpdate', label: 'Message edited',         icon: 'pencil', category: 'Messages' },
  { key: 'commandUse',    label: 'Slash command used',     icon: 'terminal', category: 'Activity' },
];

// Automod rule types + actions. Kept in sync with utils/automodRules.js.
const AUTOMOD_RULES = [
  { key: 'blockedWords', label: 'Blocked words',       icon: 'ban', category: 'Content', params: ['words'] },
  { key: 'invites',      label: 'Discord invites',     icon: 'envelope', category: 'Content', params: [] },
  { key: 'links',        label: 'All links',           icon: 'link', category: 'Content', params: [] },
  { key: 'badLinks',     label: 'Bad / phishing links',icon: 'linkOff', category: 'Content', params: ['words'] },
  { key: 'nsfw',         label: 'NSFW content',        icon: 'eyeOff', category: 'Content', params: ['words'] },
  { key: 'repeatedChars',label: 'Repeated characters', icon: 'repeat', category: 'Spam',    params: ['threshold'] },
  { key: 'newAccount',   label: 'New / alt account',   icon: 'userClock', category: 'Spam',    params: ['threshold'] },
  { key: 'mentions',     label: 'Mass mentions',       icon: 'at',  category: 'Spam',    params: ['threshold'] },
  { key: 'spam',         label: 'Duplicate / rapid spam', icon: 'alertTriangle', category: 'Spam',  params: ['threshold','seconds'] },
  { key: 'caps',         label: 'Excessive caps',      icon: 'type', category: 'Content', params: ['threshold'] },
  { key: 'emojiSpam',    label: 'Emoji spam',         icon: 'smile', category: 'Content', params: ['threshold'] },
  { key: 'newlines',     label: 'Wall of text / newlines', icon: 'alignLeft', category: 'Content', params: ['threshold'] },
  { key: 'zalgo',        label: 'Zalgo / glitch text', icon: 'zap', category: 'Content', params: [] },
];
const AUTOMOD_ACTIONS = [
  { key: 'delete',  label: 'Delete message', icon: 'trash' },
  { key: 'warn',    label: 'Warn member',   icon: 'alertTriangle' },
  { key: 'timeout', label: 'Timeout (mute)', icon: 'clock' },
  { key: 'kick',    label: 'Kick',          icon: 'userX' },
  { key: 'ban',     label: 'Ban',           icon: 'ban' },
];
// Actions valid for warn escalation (no delete).
const AUTOMOD_WARN_ACTIONS = AUTOMOD_ACTIONS.filter(a => ['warn','timeout','kick','ban'].includes(a.key));
const AUTOMOD_DM_KEYS = ['delete','warn','timeout','kick','ban','escalation'];

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

// ── Inline SVG icon system ────────────────────────────────────────────────
// Stroke-based, 24x24 viewBox, currentColor. Replaces emoji iconography.
const ICONS = {
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  hand: '<path d="M18 11V6a1.5 1.5 0 0 0-3 0v4"/><path d="M15 11V5a1.5 1.5 0 0 0-3 0v6"/><path d="M12 11V7a1.5 1.5 0 0 0-3 0v6"/><path d="M9 11V9a1.5 1.5 0 0 0-3 0v7a8 8 0 0 0 8 8h1a8 8 0 0 0 7-4l2-3.5a1.5 1.5 0 0 0-2.5-1.6L18 14"/>',
  trendingUp: '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
  hash: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
  repeat: '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
  tag: '<path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/>',
  megaphone: '<path d="m3 11 18-5v12L3 14v-3z"/><path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>',
  fileText: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  ticket: '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2z"/><path d="M13 5v2"/><path d="M13 17v2"/><path d="M13 11v2"/>',
  calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
  server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><line x1="7" y1="7" x2="7.01" y2="7"/><line x1="7" y1="17" x2="7.01" y2="17"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.5-3.5L9 20"/>',
  robot: '<rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><line x1="2" y1="14" x2="4" y2="14"/><line x1="20" y1="14" x2="22" y2="14"/><line x1="9" y1="14" x2="9" y2="18"/><line x1="15" y1="14" x2="15" y2="18"/>',
  arrowRight: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  trophy: '<path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2z"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  chart: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  gift: '<rect x="3" y="8" width="18" height="4" rx="1"/><path d="M12 8v13"/><path d="M19 12v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-7"/><path d="M7.5 8a2.5 2.5 0 0 1 0-5C11 3 12 8 12 8s1-5 4.5-5a2.5 2.5 0 0 1 0 5"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  alertTriangle: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  ban: '<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  userPlus: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/>',
  userMinus: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/>',
  userCheck: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/>',
  userX: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="11" x2="23" y2="17"/><line x1="23" y1="11" x2="17" y2="17"/>',
  userClock: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M22 10v6"/><path d="m19 12.5 2 1.5 2-1.5"/>',
  pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  linkOff: '<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/>',
  envelope: '<rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 7 12 13 21 7"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  unlock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  type: '<polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/>',
  smile: '<circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>',
  alignLeft: '<line x1="17" y1="10" x2="3" y2="10"/><line x1="21" y1="6" x2="3" y2="6"/><line x1="21" y1="14" x2="3" y2="14"/><line x1="17" y1="18" x2="3" y2="18"/>',
  shieldAlert: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  at: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/>',
  info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
};

function svgIcon(name, cls = '') {
  const body = ICONS[name] || '';
  const c = cls ? ` ${cls}` : '';
  return `<svg class="ico${c}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

// Smooth entrance for dynamically rendered card lists.
function animateCards(container) {
  if (!container) return;
  const cards = container.querySelectorAll('.card, .guild-card, .live-card, .rr-menu-card, .ev-card');
  cards.forEach((card, i) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(6px)';
    card.style.transition = 'opacity 220ms ease, transform 220ms ease';
    setTimeout(() => {
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    }, 50 * i);
  });
}

// Polished empty state for list containers.
function emptyState(container, message, icon = '') {
  if (!container) return;
  const iconHTML = icon || svgIcon('inbox');
  container.innerHTML = `
    <div style="text-align:center;padding:36px 20px;color:var(--text-dim)">
      <div class="empty-ico" style="justify-content:center;margin-bottom:10px">${iconHTML}</div>
      <div style="font-size:14px;font-weight:600">${esc(message)}</div>
    </div>
  `;
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
  { match: /^\/live\/?$/, view: renderLive },
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
      <div class="login-hero">${svgIcon('zap')}</div>
      <h1 class="login-title">PrimeBot Dashboard</h1>
      <p class="login-tagline">Premium features in free</p>
      ${errorHTML}
      <p class="login-sub">Sign in with Discord to configure PrimeBot for the servers you manage — welcome messages, leveling, prefixes, auto-reactions and more, all in one place.</p>
      <a href="/login" class="btn btn-discord">${svgIcon('arrowRight')} Login with Discord</a>
      <a href="/docs" class="btn btn-secondary" data-link>${svgIcon('book')} Documentation</a>

      <div class="stats-band" id="stats-band" aria-live="polite">
        <div class="stats-band-head">
          <span class="stats-band-title">Live across the platform</span>
          <span class="stats-band-sub" id="stats-sub">Loading live stats…</span>
        </div>
        <div class="stats-cards" id="stats-cards">
          <div class="stat-card stat-primary">
            <div class="stat-icon">${svgIcon('server')}</div>
            <div class="stat-value" id="stat-servers" data-target="0">0</div>
            <div class="stat-label">Servers configured</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">${svgIcon('image')}</div>
            <div class="stat-value" id="stat-banners" data-target="0">0</div>
            <div class="stat-label">Custom welcome banners</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">${svgIcon('robot')}</div>
            <div class="stat-value" id="stat-version">—</div>
            <div class="stat-label">Bot version</div>
          </div>
        </div>
        <div class="stats-chart-wrap">
          <div class="stats-chart-head">Feature adoption</div>
          <div class="donut-grid">
            <div class="donut-item">
              <div class="donut" id="donut-leveling"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('trendingUp')} Leveling</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-welcome"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('hand')} Welcome</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-reactions"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('repeat')} Auto-reactions</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-broadcasts"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('megaphone')} Broadcasts</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-automod"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('shield')} Automod</div>
            </div>
            <div class="donut-item">
              <div class="donut" id="donut-tickets"><span class="donut-pct">0%</span></div>
              <div class="donut-label">${svgIcon('ticket')} Tickets</div>
            </div>
          </div>
        </div>
      </div>

      <div class="feature-grid">
        <div class="feature"><div class="fi">${svgIcon('hand')}</div><div class="ft">Welcome system</div><div class="fd">Custom messages, banners, DMs and channel routing.</div></div>
        <div class="feature"><div class="fi">${svgIcon('trendingUp')}</div><div class="ft">Leveling &amp; XP</div><div class="fd">Tune multipliers, cooldowns and level-up channels.</div></div>
        <div class="feature"><div class="fi">${svgIcon('hash')}</div><div class="ft">Command prefix</div><div class="fd">Set a per-server prefix instead of the default.</div></div>
        <div class="feature"><div class="fi">${svgIcon('repeat')}</div><div class="ft">Auto-reactions</div><div class="fd">Trigger emojis on matching messages automatically.</div></div>
        <div class="feature"><div class="fi">${svgIcon('shield')}</div><div class="ft">Premium Automod</div><div class="fd">Auto-mod with warnings, escalation, spam &amp; word filters — free.</div></div>
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
  renderDonut(document.getElementById('donut-automod'), f.automod?.percent ?? 0, '--red');
  renderDonut(document.getElementById('donut-tickets'), f.tickets?.percent ?? 0, '--blurple');
}

// ── Documentation page ─────────────────────────────────────────────────────

function renderDocs() {
  // Show the nav on the docs page (login hides it).
  document.querySelector('.topnav').style.display = '';

  const clientId = esc(window.__clientId || '');
  const inviteUrl = clientId
    ? `https://discord.com/oauth2/authorize?client_id=${clientId}&permissions=8&integration_type=0&scope=bot%20applications.commands`
    : 'https://discord.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&permissions=8&integration_type=0&scope=bot%20applications.commands';

  app.innerHTML = `
    <div class="docs">
        <div class="docs-hero">
        <div class="docs-hero-icon">${svgIcon('book')}</div>
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
            <h4>${svgIcon('shield')} Moderation</h4>
            <ul><li><code>ban</code> / <code>kick</code> — remove members</li><li><code>purge</code> — bulk-delete messages</li><li><code>lock</code> / <code>unlock</code> — lock channels</li><li><code>nuke</code> — clear &amp; recreate a channel</li><li><code>hide</code> / <code>unhide</code> — hide channels</li><li><code>move</code> — move members</li><li><code>role</code> — assign roles</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>${svgIcon('gift')} Engagement</h4>
            <ul><li><code>poll</code> / <code>endpoll</code> — simple polls</li><li><code>lpoll</code> / <code>endgame</code> — live polls</li><li><code>giveaway</code> / <code>reroll</code> / <code>end</code> — giveaways</li><li><code>counting</code> — counting game</li><li><code>tictactoe</code> — play tic-tac-toe</li><li><code>truthdare</code> — truth or dare</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>${svgIcon('ticket')} Tickets &amp; Support</h4>
            <ul><li><code>createticket</code> / <code>ticket</code> — open tickets</li><li><code>tickethistory</code> — view past tickets</li><li><code>categories</code> — manage ticket categories</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>${svgIcon('smile')} Community</h4>
            <ul><li><code>birthday</code> — set birthdays</li><li><code>leveling</code> — view XP/rank</li><li><code>welcomeconfig</code> — quick welcome setup</li><li><code>about</code> — bot info</li><li><code>help</code> — command help</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>${svgIcon('megaphone')} Broadcasting</h4>
            <ul><li><code>broadcast</code> — send a broadcast</li><li><code>broadcastsettings</code> — configure reception</li><li><code>updates</code> — bot update notes</li></ul>
          </div>
          <div class="docs-cmd-card">
            <h4>${svgIcon('terminal')} Utility</h4>
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
        <a href="/login" class="btn btn-discord">${svgIcon('arrowRight')} Login with Discord</a>
        <a href="/" class="btn btn-secondary" data-link>← Back to dashboard</a>
      </div>
    </div>
  `;
}

// ── Overview (server list) ─────────────────────────────────────────────────

// ── Live page (live polls + live giveaways) ────────────────────────────────
//
// Two panels: Live Polls and Live Giveaways. Each shows a "Running" list and a
// separate "Ended" list. Running items show a Join button that opens a
// floating window (modal) explaining how to join via the bot commands
// (`$lpoll join <key>` / `$lgiveway join <key>`). Ended items only show winners.

const LIVE_PREFIX = '$';

async function renderLive() {
  app.innerHTML = `
    <div class="page-head">
      <h1>Live</h1>
      <p>Running and ended cross-server live polls and live giveaways. Create them with <code>${esc(LIVE_PREFIX)}lpoll</code> / <code>${esc(LIVE_PREFIX)}lgiveway</code> in Discord.</p>
      <button class="btn btn-secondary" id="live-refresh">${svgIcon('refresh')} Refresh</button>
    </div>
    <div id="live-root"><div class="splash"><div class="spinner"></div><p>Loading live data…</p></div></div>
    <div id="live-join-modal" class="modal-overlay hidden"></div>
  `;
  await loadLive();
  app.querySelector('#live-refresh')?.addEventListener('click', loadLive);
}

async function loadLive() {
  const root = app.querySelector('#live-root');
  if (!root) return;
  try {
    const data = await api('/api/live');
    root.innerHTML = `
      <div class="live-grid">
        ${livePanelHTML('polls', data.runningPolls || [], data.endedPolls || [], 'poll')}
        ${livePanelHTML('giveaways', data.runningGiveaways || [], data.endedGiveaways || [], 'giveaway')}
      </div>
    `;
    bindLiveEvents();
    animateCards(root);
  } catch (err) {
    if (err.status === 401) { window.location.href = '/login'; return; }
    root.innerHTML = `<div class="card"><div class="alert alert-error">${esc(err.message || 'Failed to load live data.')}</div></div>`;
  }
}

function livePanelHTML(title, running, ended, kind) {
  const titleIcon = kind === 'poll' ? 'chart' : 'gift';
  return `
    <div class="card live-panel">
      <h2>${svgIcon(titleIcon)} ${esc(title === 'polls' ? 'Live Polls' : 'Live Giveaways')}</h2>
      <h3 class="live-section-head"><span class="status-dot live"></span> Running</h3>
      <div class="live-list" data-live-running="${kind}">
        ${running.length ? running.map(item => liveRunningCardHTML(item, kind)).join('') : '<p class="live-empty">No running items.</p>'}
      </div>
      <h3 class="live-section-head"><span class="status-dot ended"></span> Ended</h3>
      <div class="live-list" data-live-ended="${kind}">
        ${ended.length ? ended.map(item => liveEndedCardHTML(item, kind)).join('') : '<p class="live-empty">No ended items.</p>'}
      </div>
    </div>
  `;
}

function liveRunningCardHTML(item, kind) {
  const key = kind === 'poll' ? (item.passCode || item.pollId) : (item.passCode || item.giveawayId);
  const title = kind === 'poll' ? esc(item.question || '') : `Prize: ${esc(item.prize || '')}`;
  const meta = kind === 'poll'
    ? `${item.totalVotes ?? 0} votes`
    : `${item.entries ?? 0} entries • ${item.winnerCount ?? 1} winner(s)`;
  const expires = item.expiresAt || item.endsAt
    ? `<span class="live-meta">${svgIcon('clock')} ends ${esc(new Date(item.expiresAt || item.endsAt).toLocaleString())}</span>`
    : `<span class="live-meta">${svgIcon('clock')} permanent</span>`;
  return `
    <div class="live-card" data-key="${esc(key)}" data-kind="${kind}">
      <div class="live-card-title">${title}</div>
      <div class="live-card-meta">${esc(meta)} ${expires}</div>
      <div class="live-card-code">${svgIcon('key')} Pass code: <code>${esc(key)}</code></div>
      <button class="btn btn-primary live-join-btn" data-key="${esc(key)}" data-kind="${kind}">Join</button>
    </div>
  `;
}

function liveEndedCardHTML(item, kind) {
  if (kind === 'poll') {
    const winners = (item.winners || []).map(w => esc(w)).join(', ') || '—';
    const opts = (item.options || []).map(o => `${esc(o.text)}: ${o.votes}`).join(' · ');
    return `
      <div class="live-card live-ended">
        <div class="live-card-title">${esc(item.question || '')}</div>
        <div class="live-card-meta">${esc((item.options || []).reduce((s, o) => s + o.votes, 0))} votes</div>
        ${opts ? `<div class="live-card-opts">${esc(opts)}</div>` : ''}
        <div class="live-winners">${svgIcon('trophy')} Winner(s): ${winners}</div>
      </div>
    `;
  }
  const winners = (item.winners || []).map(w => `<code>${esc(w)}</code>`).join(', ') || '—';
  return `
    <div class="live-card live-ended">
      <div class="live-card-title">Prize: ${esc(item.prize || '')}</div>
      <div class="live-winners">${svgIcon('trophy')} Winner(s): ${winners}</div>
    </div>
  `;
}

function bindLiveEvents() {
  app.querySelectorAll('.live-join-btn').forEach(btn => {
    btn.addEventListener('click', () => openJoinModal(btn.dataset.key, btn.dataset.kind));
  });
}

function openJoinModal(key, kind) {
  const modal = app.querySelector('#live-join-modal');
  if (!modal) return;
  const command = kind === 'poll' ? `lpoll join ${key}` : `lgiveway join ${key}`;
  modal.innerHTML = `
    <div class="modal floating-window">
      <div class="modal-head">
        <h3>${svgIcon(kind === 'poll' ? 'chart' : 'gift')} ${kind === 'poll' ? 'Join Live Poll' : 'Join Live Giveaway'}</h3>
        <button class="modal-close" id="live-join-close" aria-label="Close">${svgIcon('x')}</button>
      </div>
      <div class="modal-body">
        <p>Run this command in any Discord server where PrimeBot is present to join:</p>
        <div class="command-box"><code>${esc(LIVE_PREFIX)}${esc(command)}</code>
          <button class="btn btn-secondary btn-copy" id="live-join-copy">Copy</button>
        </div>
        <p class="live-modal-note">Key: <code>${esc(key)}</code></p>
        <div id="live-join-status"></div>
        <div class="live-join-actions">
          <button class="btn btn-primary" id="live-join-do">Join now</button>
        </div>
      </div>
    </div>
  `;
  modal.classList.remove('hidden');
  const close = () => modal.classList.add('hidden');
  modal.querySelector('#live-join-close').addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  modal.querySelector('#live-join-copy').addEventListener('click', async () => {
    const btn = modal.querySelector('#live-join-copy');
    const original = btn.textContent;
    try {
      await navigator.clipboard.writeText(`${LIVE_PREFIX}${command}`);
      btn.textContent = 'Copied!';
      setTimeout(() => (btn.textContent = original), 1200);
    } catch {
      toast('Copy failed', 'error');
    }
  });
  modal.querySelector('#live-join-do').addEventListener('click', async () => {
    const status = modal.querySelector('#live-join-status');
    status.innerHTML = `<div class="alert alert-warn">The dashboard can't join for you — run the command above in Discord to join the ${kind === 'poll' ? 'poll' : 'giveaway'}.</div>`;
  });
}

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
        <div class="empty-ico">${svgIcon('search')}</div>
        <p>You don't manage any servers yet, or PrimeBot isn't in any of them.</p>
        <p style="margin-top:12px"><a class="btn btn-secondary" href="https://discord.com/oauth2/authorize?client_id=${esc(window.__clientId||'')}&permissions=8&integration_type=0&scope=bot%20applications.commands" target="_blank" rel="noopener">Invite PrimeBot to a server</a></p>
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
    <div id="guild-list-root">${listHTML}</div>
  `;
  animateCards(app.querySelector('#guild-list-root'));

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
    tags.push(g.welcomeEnabled ? `<span class="tag on"><span class="dot"></span>Welcome</span>` : `<span class="tag off"><span class="dot"></span>Welcome off</span>`);
    tags.push(g.levelingEnabled ? `<span class="tag on"><span class="dot"></span>Leveling</span>` : `<span class="tag off"><span class="dot"></span>Leveling off</span>`);
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
          <p style="margin-top:16px"><a class="btn btn-primary" href="https://discord.com/oauth2/authorize?client_id=${esc(window.__clientId||'')}&permissions=8&integration_type=0&scope=bot%20applications.commands" target="_blank" rel="noopener">Invite PrimeBot</a></p>
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
      renderAmExemptLists();
    })
    .catch(() => { /* surfaced via empty selectors */ });
  // Lazy-load roles for reaction-role selectors.
  api(`/api/guilds/${guildId}/roles`)
    .then(d => {
      guildState.roles = d.roles || [];
      populateRoleSelects();
      renderAmExemptLists();
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

    <div class="settings-layout">
      <aside class="settings-nav">
        <div class="tabs">
          <button class="tab" data-tab="welcome"><span class="tab-ico">${svgIcon('hand')}</span> Welcome</button>
          <button class="tab" data-tab="leveling"><span class="tab-ico">${svgIcon('trendingUp')}</span> Leveling</button>
          <button class="tab" data-tab="prefix"><span class="tab-ico">${svgIcon('hash')}</span> Prefix</button>
          <button class="tab" data-tab="reactions"><span class="tab-ico">${svgIcon('repeat')}</span> Auto-Reactions</button>
          <button class="tab" data-tab="reactionroles"><span class="tab-ico">${svgIcon('tag')}</span> Reaction Roles</button>
          <button class="tab" data-tab="broadcast"><span class="tab-ico">${svgIcon('megaphone')}</span> Broadcasts</button>
          <button class="tab" data-tab="logging"><span class="tab-ico">${svgIcon('fileText')}</span> Logging</button>
          <button class="tab" data-tab="automod"><span class="tab-ico">${svgIcon('shield')}</span> Automod</button>
          <button class="tab" data-tab="tickets"><span class="tab-ico">${svgIcon('ticket')}</span> Tickets</button>
          <button class="tab" data-tab="events"><span class="tab-ico">${svgIcon('calendar')}</span> Events</button>
        </div>
      </aside>
      <div class="settings-content">
        <div id="tab-welcome" class="tab-panel">${welcomePanelHTML(data.config.welcome)}</div>
        <div id="tab-leveling" class="tab-panel">${levelingPanelHTML(data.config.server)}</div>
        <div id="tab-prefix" class="tab-panel">${prefixPanelHTML(data.config.server)}</div>
        <div id="tab-reactions" class="tab-panel">${reactionsPanelHTML(data.config.server)}</div>
        <div id="tab-reactionroles" class="tab-panel">${reactionRolesPanelHTML(data.config.reactionRoles)}</div>
        <div id="tab-broadcast" class="tab-panel">${broadcastPanelHTML(data.config.server)}</div>
        <div id="tab-logging" class="tab-panel">${loggingPanelHTML(data.config.logging)}</div>
        <div id="tab-automod" class="tab-panel">${automodPanelHTML(data.config.automod)}</div>
        <div id="tab-tickets" class="tab-panel">${ticketsPanelHTML(data.config.ticketPanels)}</div>
        <div id="tab-events" class="tab-panel">${eventsPanelHTML()}</div>
      </div>
    </div>
  `;

  selectTab(initialTab);
  bindSettingsEvents(guildId);
  // Lazy-load event schedules when the Events tab is opened.
  loadEventSchedules(guildId);
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

function populateRoleSelects() {
  if (!guildState) return;
  const opts = (guildState.roles || []).map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('');
  app.querySelectorAll('select[data-role-select]').forEach(sel => {
    const current = sel.value;
    const placeholder = sel.dataset.placeholder || '— None —';
    sel.innerHTML = `<option value="">${esc(placeholder)}</option>` + opts;
    if (current) sel.value = current;
  });
}

// ── Panel templates ────────────────────────────────────────────────────────

function welcomePanelHTML(w) {
  const s = w || {};
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('hand')}</span> Welcome messages</span></div>
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
      <div class="card-title"><span><span class="icon">${svgIcon('trendingUp')}</span> Leveling &amp; XP</span></div>
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
      <div class="card-title"><span><span class="icon">${svgIcon('hash')}</span> Command prefix</span></div>
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
      <div class="card-title"><span><span class="icon">${svgIcon('repeat')}</span> Auto-reactions</span></div>
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
      <button class="reaction-remove" type="button">${svgIcon('x')}</button>
    </div>
  `;
}

function broadcastPanelHTML(server) {
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('megaphone')}</span> Broadcasts</span></div>
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

// ── Reaction Roles (premium, free) ──────────────────────────────────────────
//
// Two creation flows surfaced in one tab:
//   • Bot-created: the dashboard posts a role embed and the bot watches it.
//   • Attach: attach emoji→role mappings to ANY existing message by id.
// Plus a list of existing menus with edit/delete. Premium modes (normal,
// sticky, verify, unique) and gating options are configurable per menu.

const RR_MODES = [
  { value: 'normal', label: 'Normal — toggle on/off' },
  { value: 'sticky', label: 'Sticky — one-click assign (no toggle-off)' },
  { value: 'verify', label: 'Verify — grant once, no remove' },
  { value: 'unique', label: 'Unique — only one role at a time' },
];

function rrMappingRowHTML(m = {}) {
  return `
    <div class="reaction-row" data-index="">
      <input type="text" class="r-emoji" value="${esc(m.emoji || '')}" placeholder="🎉 or <:name:id>" maxlength="100" />
      <select class="r-role" data-role-select data-placeholder="Role">${m.roleId ? `<option value="${esc(m.roleId)}" selected>Role</option>` : ''}</select>
      <input type="text" class="r-label" value="${esc(m.label || '')}" placeholder="label (optional)" maxlength="100" />
      <button class="reaction-remove" type="button">${svgIcon('x')}</button>
    </div>
  `;
}

function rrMenuCardHTML(menu) {
  const mappings = (menu.mappings || []).map(m => {
    const e = /^\w+:\d+$/.test(m.emoji) ? `<:${m.emoji}>` : esc(m.emoji);
    return `${e} → <@&${esc(m.roleId)}>${m.label ? ' — ' + esc(m.label) : ''}`;
  }).join('<br/>');
  return `
    <div class="card rr-menu-card" data-menu="${menu.id}">
      <div class="card-title">
        <span><span class="icon">${svgIcon('tag')}</span> ${esc(menu.title || 'Untitled menu')} <span class="tag ${menu.enabled ? 'on' : 'off'}">#${menu.id}</span></span>
        <button class="btn btn-secondary btn-sm rr-delete" data-menu="${menu.id}">Delete</button>
      </div>
      <div class="rr-meta">
        <span><strong>Channel:</strong> <#${esc(menu.channelId)}></span>
        <span><strong>Message:</strong> <code>${esc(menu.messageId)}</code></span>
        <span><strong>Mode:</strong> <code>${esc(menu.mode)}</code></span>
        <span><strong>Persistent:</strong> ${menu.persistent ? svgIcon('check') + ' Yes' : svgIcon('x') + ' No'}</span>
        <span><strong>Bot reactions:</strong> ${menu.includeBots ? svgIcon('check') + ' Yes' : svgIcon('x') + ' No'}</span>
      </div>
      <div class="rr-mappings">${mappings || '<em>No mappings</em>'}</div>
      ${menu.requiredRoleId ? `<div class="field-hint">Requires <@&${esc(menu.requiredRoleId)}></div>` : ''}
      ${menu.exclusiveRoleId ? `<div class="field-hint">Removes <@&${esc(menu.exclusiveRoleId)}> on assign</div>` : ''}
      <button class="btn btn-secondary btn-sm rr-edit" data-menu="${menu.id}" style="margin-top:8px">Edit</button>
    </div>
  `;
}

// ── Tickets tab: panel list + editor + clone/rename/send/update ──────────────

const TICKET_BUTTON_STYLES = [
  { value: 'Primary', label: 'Blurple (Primary)' },
  { value: 'Secondary', label: 'Grey (Secondary)' },
  { value: 'Success', label: 'Green (Success)' },
  { value: 'Danger', label: 'Red (Danger)' },
];
const TICKET_MESSAGE_TYPES = [
  { value: 'embed', label: 'Embed message' },
  { value: 'plain', label: 'Plain text message' },
];

function ticketPanelCardHTML(panel) {
  const supportRoles = (panel.supportRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const pingRoles = (panel.pingRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const msgType = panel.messageType === 'plain' ? 'Plain text' : 'Embed';
  return `
    <div class="card rr-menu-card" data-panel="${panel.id}">
      <div class="card-title">
        <span><span class="icon">${svgIcon('ticket')}</span> ${esc(panel.name)} <span class="tag ${panel.enabled ? 'on' : 'off'}">#${panel.id}</span></span>
        <span style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm tk-send" data-panel="${panel.id}">Send / Resend</button>
          <button class="btn btn-secondary btn-sm tk-update" data-panel="${panel.id}">Update message</button>
          <button class="btn btn-secondary btn-sm tk-rename" data-panel="${panel.id}">Rename</button>
          <button class="btn btn-secondary btn-sm tk-clone" data-panel="${panel.id}">Clone</button>
          <button class="btn btn-secondary btn-sm tk-edit" data-panel="${panel.id}">Edit</button>
          <button class="btn btn-secondary btn-sm tk-delete" data-panel="${panel.id}">Delete</button>
        </span>
      </div>
      <div class="rr-meta">
        <span><strong>Type:</strong> ${esc(msgType)}</span>
        <span><strong>Channel:</strong> ${panel.channelId ? `<#${esc(panel.channelId)}>` : 'not sent'}</span>
        <span><strong>Message:</strong> <code>${esc(panel.messageId || '—')}</code></span>
        <span><strong>Button:</strong> ${esc(panel.buttonEmoji || '')} ${esc(panel.buttonLabel)}</span>
        <span><strong>Max/user:</strong> ${esc(panel.maxOpenPerUser)}</span>
      </div>
      <div class="rr-mappings">
        <strong>Title:</strong> ${esc(panel.title || '—')}<br/>
        <strong>Support roles:</strong> ${supportRoles}<br/>
        <strong>Ping roles:</strong> ${pingRoles}
      </div>
      ${panel.claimButtonLabel ? `<div class="field-hint">Claim button: ${esc(panel.claimButtonLabel)}</div>` : ''}
    </div>
  `;
}

function ticketRoleRowHTML(selected = {}, prefix = 'tk-support') {
  return `
    <div class="reaction-row" data-index="">
      <select class="${prefix}-role" data-role-select data-placeholder="Role">${selected.roleId ? `<option value="${esc(selected.roleId)}" selected>Role</option>` : ''}</select>
      <button class="reaction-remove" type="button">${svgIcon('x')}</button>
    </div>
  `;
}

function ticketsPanelHTML(panels = []) {
  const listHTML = panels.length
    ? panels.map(ticketPanelCardHTML).join('')
    : `<div class="alert alert-warn">No ticket panels yet. Create one below — panels can only be configured from the dashboard.</div>`;
  const styleOpts = TICKET_BUTTON_STYLES.map(s => `<option value="${s.value}">${esc(s.label)}</option>`).join('');
  const typeOpts = TICKET_MESSAGE_TYPES.map(t => `<option value="${t.value}">${esc(t.label)}</option>`).join('');
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('ticket')}</span> Tickets</span></div>
      <p class="card-desc">Ticket panels are configurable <strong>only from the dashboard</strong> — slash and prefix ticket commands are disabled. Build a panel (embed or plain message, custom button, support/ping roles, claim button, per-user limits), then <strong>Send</strong> it to a channel and use <strong>Update message</strong> to re-render an existing message by id.</p>
      <div class="rr-list">${listHTML}</div>
    </div>

    <div class="card">
      <div class="card-title"><span>Create / edit a panel</span></div>
      <div class="field">
        <label class="field-label" for="tk-name">Panel name</label>
        <input type="text" id="tk-name" maxlength="100" placeholder="Support Ticket" />
        <div class="field-hint">Unique per server. Shown as the ticket title and in the dashboard list.</div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-message-type">Message type</label>
        <select id="tk-message-type">${typeOpts}</select>
        <div class="field-hint">Embed (rich) or plain text. The open-ticket button is always attached.</div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-title">Embed title</label>
        <input type="text" id="tk-title" maxlength="255" placeholder="🎫 Support Tickets" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-description">Embed description</label>
        <textarea id="tk-description" placeholder="Click the button below to open a support ticket."></textarea>
      </div>
      <div class="field">
        <label class="field-label" for="tk-content">Content / @mentions (above embed, or plain body)</label>
        <textarea id="tk-content" placeholder="Optional: @support or any text shown above the embed / as the plain body."></textarea>
      </div>
      <div class="field">
        <label class="field-label" for="tk-footer">Embed footer text</label>
        <input type="text" id="tk-footer" maxlength="255" placeholder="PrimeBot · Tickets" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-thumbnail">Thumbnail image URL</label>
        <input type="text" id="tk-thumbnail" placeholder="https://…/icon.png" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-image">Large image URL</label>
        <input type="text" id="tk-image" placeholder="https://…/banner.png" />
      </div>
      <div class="field">
        <label class="field-label">Embed color</label>
        <div class="color-field">
          <input type="color" id="tk-color" value="#5865F2" />
          <input type="text" id="tk-color-text" value="#5865F2" style="flex:1" />
        </div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-button-label">Open button label</label>
        <input type="text" id="tk-button-label" maxlength="80" value="Open Ticket" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-button-emoji">Open button emoji (optional)</label>
        <input type="text" id="tk-button-emoji" maxlength="100" placeholder="🎫" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-button-style">Open button style</label>
        <select id="tk-button-style">${styleOpts}</select>
      </div>
      <div class="field">
        <label class="field-label" for="tk-category">Ticket category label</label>
        <input type="text" id="tk-category" maxlength="50" value="general" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-ticket-name">Ticket channel name (optional)</label>
        <input type="text" id="tk-ticket-name" maxlength="100" placeholder="Defaults to ticket-username" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-open-name">Channel name when OPEN</label>
        <input type="text" id="tk-open-name" maxlength="100" placeholder="(open) {name}" />
        <div class="field-hint">Template applied when a ticket opens/reopens. Placeholders: {name} (ticket name or username), {username}, {id}, {panel}. Blank = no rename.</div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-claimed-name">Channel name when CLAIMED</label>
        <input type="text" id="tk-claimed-name" maxlength="100" placeholder="(solved) {name}" />
        <div class="field-hint">Template applied when support claims the ticket. Same placeholders. Blank = no rename.</div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-closed-name">Channel name when CLOSED</label>
        <input type="text" id="tk-closed-name" maxlength="100" placeholder="(closed) {name}" />
        <div class="field-hint">Template applied when the ticket is closed (visible for archived threads). Same placeholders. Blank = no rename.</div>
      </div>
      <div class="field">
        <label class="field-label">Support roles (can see tickets)</label>
        <div class="reactions-list" id="tk-support-list">${ticketRoleRowHTML({}, 'tk-support')}</div>
        <button class="btn btn-secondary" id="tk-support-add">+ Add role</button>
      </div>
      <div class="field">
        <label class="field-label">Ping roles (mentioned on open)</label>
        <div class="reactions-list" id="tk-ping-list">${ticketRoleRowHTML({}, 'tk-ping')}</div>
        <button class="btn btn-secondary" id="tk-ping-add">+ Add role</button>
      </div>
      <div class="field">
        <label class="field-label" for="tk-ticket-category-id">Discord channel category ID (optional)</label>
        <input type="text" id="tk-ticket-category-id" placeholder="123456789012345678" />
        <div class="field-hint">Created ticket channels open under this category. Leave blank to use the current channel / threads.</div>
      </div>
      <div class="field">
        <label class="field-label" for="tk-max-open">Max open tickets per user</label>
        <input type="number" id="tk-max-open" min="0" value="1" />
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Ask for reason on open</div><div class="sl-desc">Prompt the member for a reason (captured on the ticket). Note: requires a follow-up flow; the button still opens a ticket.</div></div>
        <label class="switch"><input type="checkbox" id="tk-ask-reason"/><span class="slider"></span></label>
      </div>
      <div class="field">
        <label class="field-label" for="tk-welcome">In-ticket welcome message</label>
        <textarea id="tk-welcome" placeholder="Welcome to your support ticket! Please describe your issue."></textarea>
      </div>
      <div class="field">
        <label class="field-label" for="tk-close-label">Close button label</label>
        <input type="text" id="tk-close-label" maxlength="80" value="Close Ticket" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-close-emoji">Close button emoji (optional)</label>
        <input type="text" id="tk-close-emoji" maxlength="100" value="🔒" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-claim-label">Claim button label (optional — leave blank for no claim button)</label>
        <input type="text" id="tk-claim-label" maxlength="80" placeholder="Claim" />
      </div>
      <div class="field">
        <label class="field-label" for="tk-claim-emoji">Claim button emoji (optional)</label>
        <input type="text" id="tk-claim-emoji" maxlength="100" placeholder="✋" />
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Enabled</div><div class="sl-desc">When off, the open button is disabled.</div></div>
        <label class="switch"><input type="checkbox" id="tk-enabled" checked/><span class="slider"></span></label>
      </div>
      <div class="form-actions">
        <input type="hidden" id="tk-edit-id" value="" />
        <button class="btn btn-primary" id="tk-save">Create panel</button>
        <button class="btn btn-secondary" id="tk-cancel-edit" style="display:none">Cancel edit</button>
      </div>
    </div>
  `;
}

function collectTicketRoles(listSelector, roleClass) {
  const out = [];
  app.querySelectorAll(`${listSelector} .${roleClass}`).forEach(sel => {
    const v = sel.value;
    if (v) out.push(v);
  });
  return out;
}

function readTicketForm() {
  return {
    name: app.querySelector('#tk-name').value.trim() || 'Support Ticket',
    messageType: app.querySelector('#tk-message-type').value || 'embed',
    title: app.querySelector('#tk-title').value.trim() || null,
    description: app.querySelector('#tk-description').value.trim() || null,
    content: app.querySelector('#tk-content').value.trim() || null,
    footerText: app.querySelector('#tk-footer').value.trim() || null,
    thumbnailUrl: app.querySelector('#tk-thumbnail').value.trim() || null,
    imageUrl: app.querySelector('#tk-image').value.trim() || null,
    color: app.querySelector('#tk-color').value || '#5865F2',
    buttonLabel: app.querySelector('#tk-button-label').value.trim() || 'Open Ticket',
    buttonEmoji: app.querySelector('#tk-button-emoji').value.trim() || null,
    buttonStyle: app.querySelector('#tk-button-style').value || 'Primary',
    category: app.querySelector('#tk-category').value.trim() || 'general',
    ticketName: app.querySelector('#tk-ticket-name').value.trim() || null,
    openNameTemplate: app.querySelector('#tk-open-name').value.trim() || null,
    claimedNameTemplate: app.querySelector('#tk-claimed-name').value.trim() || null,
    closedNameTemplate: app.querySelector('#tk-closed-name').value.trim() || null,
    supportRoleIds: collectTicketRoles('#tk-support-list', 'tk-support-role'),
    pingRoleIds: collectTicketRoles('#tk-ping-list', 'tk-ping-role'),
    ticketCategoryId: app.querySelector('#tk-ticket-category-id').value.trim() || null,
    maxOpenPerUser: parseInt(app.querySelector('#tk-max-open').value, 10) || 1,
    askReason: !!app.querySelector('#tk-ask-reason').checked,
    welcomeMessage: app.querySelector('#tk-welcome').value.trim() || null,
    closeButtonLabel: app.querySelector('#tk-close-label').value.trim() || 'Close Ticket',
    closeButtonEmoji: app.querySelector('#tk-close-emoji').value.trim() || null,
    claimButtonLabel: app.querySelector('#tk-claim-label').value.trim() || null,
    claimButtonEmoji: app.querySelector('#tk-claim-emoji').value.trim() || null,
    enabled: !!app.querySelector('#tk-enabled').checked,
  };
}

function fillTicketForm(panel) {
  app.querySelector('#tk-edit-id').value = panel.id || '';
  app.querySelector('#tk-name').value = panel.name || '';
  app.querySelector('#tk-message-type').value = panel.messageType || 'embed';
  app.querySelector('#tk-title').value = panel.title || '';
  app.querySelector('#tk-description').value = panel.description || '';
  app.querySelector('#tk-content').value = panel.content || '';
  app.querySelector('#tk-footer').value = panel.footerText || '';
  app.querySelector('#tk-thumbnail').value = panel.thumbnailUrl || '';
  app.querySelector('#tk-image').value = panel.imageUrl || '';
  app.querySelector('#tk-color').value = panel.color || '#5865F2';
  app.querySelector('#tk-color-text').value = panel.color || '#5865F2';
  app.querySelector('#tk-button-label').value = panel.buttonLabel || 'Open Ticket';
  app.querySelector('#tk-button-emoji').value = panel.buttonEmoji || '';
  app.querySelector('#tk-button-style').value = panel.buttonStyle || 'Primary';
  app.querySelector('#tk-category').value = panel.category || 'general';
  app.querySelector('#tk-ticket-name').value = panel.ticketName || '';
  app.querySelector('#tk-open-name').value = panel.openNameTemplate || '';
  app.querySelector('#tk-claimed-name').value = panel.claimedNameTemplate || '';
  app.querySelector('#tk-closed-name').value = panel.closedNameTemplate || '';
  app.querySelector('#tk-ticket-category-id').value = panel.ticketCategoryId || '';
  app.querySelector('#tk-max-open').value = panel.maxOpenPerUser != null ? panel.maxOpenPerUser : 1;
  app.querySelector('#tk-ask-reason').checked = !!panel.askReason;
  app.querySelector('#tk-welcome').value = panel.welcomeMessage || '';
  app.querySelector('#tk-close-label').value = panel.closeButtonLabel || 'Close Ticket';
  app.querySelector('#tk-close-emoji').value = panel.closeButtonEmoji || '';
  app.querySelector('#tk-claim-label').value = panel.claimButtonLabel || '';
  app.querySelector('#tk-claim-emoji').value = panel.claimButtonEmoji || '';
  app.querySelector('#tk-enabled').checked = panel.enabled !== false;
  // Support / ping role lists.
  const supList = app.querySelector('#tk-support-list');
  supList.innerHTML = (panel.supportRoleIds && panel.supportRoleIds.length
    ? panel.supportRoleIds : [null]
  ).map(id => ticketRoleRowHTML(id ? { roleId: id } : {}, 'tk-support')).join('');
  const pingList = app.querySelector('#tk-ping-list');
  pingList.innerHTML = (panel.pingRoleIds && panel.pingRoleIds.length
    ? panel.pingRoleIds : [null]
  ).map(id => ticketRoleRowHTML(id ? { roleId: id } : {}, 'tk-ping')).join('');
  populateRoleSelects();
  // Reflect edit mode.
  const saveBtn = app.querySelector('#tk-save');
  saveBtn.textContent = 'Save panel';
  app.querySelector('#tk-cancel-edit').style.display = '';
}

function clearTicketForm() {
  app.querySelector('#tk-edit-id').value = '';
  const saveBtn = app.querySelector('#tk-save');
  saveBtn.textContent = 'Create panel';
  app.querySelector('#tk-cancel-edit').style.display = 'none';
}

async function refreshTicketList(guildId) {
  try {
    const data = await api(`/api/guilds/${guildId}/tickets`);
    const listEl = app.querySelector('#tab-tickets .rr-list');
    if (listEl) {
      const panels = data.ticketPanels || [];
      listEl.innerHTML = panels.length
        ? panels.map(ticketPanelCardHTML).join('')
        : `<div class="alert alert-warn">No ticket panels yet. Create one below — panels can only be configured from the dashboard.</div>`;
      bindTicketCardActions(guildId);
      animateCards(listEl);
    }
  } catch (_) { /* surfaced via toast elsewhere */ }
}

function bindTicketCardActions(guildId) {
  const action = async (selector, fn) => {
    app.querySelectorAll(selector).forEach(btn => {
      if (btn.dataset.bound) return;
      btn.dataset.bound = '1';
      btn.addEventListener('click', () => fn(btn));
    });
  };

  action('.tk-delete', async (btn) => {
    const id = btn.dataset.panel;
    if (!confirm('Delete this ticket panel? The panel message will be removed if the bot sent it.')) return;
    try {
      await api(`/api/guilds/${guildId}/tickets/${id}`, { method: 'DELETE' });
      toast('Panel deleted', 'success');
      refreshTicketList(guildId);
    } catch (err) { toast(err.message || 'Failed to delete', 'error'); }
  });

  action('.tk-edit', async (btn) => {
    const id = btn.dataset.panel;
    const panels = (await api(`/api/guilds/${guildId}/tickets`).catch(() => ({}))).ticketPanels || [];
    const panel = panels.find(p => String(p.id) === String(id));
    if (!panel) { toast('Panel not found', 'error'); return; }
    fillTicketForm(panel);
    document.getElementById('tab-tickets')?.scrollIntoView({ behavior: 'smooth' });
  });

  action('.tk-clone', async (btn) => {
    const id = btn.dataset.panel;
    const name = prompt('Name for the cloned panel (leave blank for "<name> (copy)"):', '');
    if (name === null) return;
    try {
      await api(`/api/guilds/${guildId}/tickets/${id}/clone`, { method: 'POST', body: JSON.stringify({ name: name || undefined }) });
      toast('Panel cloned', 'success');
      refreshTicketList(guildId);
    } catch (err) { toast(err.message || 'Failed to clone', 'error'); }
  });

  action('.tk-rename', async (btn) => {
    const id = btn.dataset.panel;
    const panels = (await api(`/api/guilds/${guildId}/tickets`).catch(() => ({}))).ticketPanels || [];
    const panel = panels.find(p => String(p.id) === String(id));
    const name = prompt('New panel name:', panel ? panel.name : '');
    if (name === null || !name.trim()) return;
    try {
      await api(`/api/guilds/${guildId}/tickets/${id}/rename`, { method: 'POST', body: JSON.stringify({ name }) });
      toast('Panel renamed', 'success');
      refreshTicketList(guildId);
    } catch (err) { toast(err.message || 'Failed to rename', 'error'); }
  });

  action('.tk-send', async (btn) => {
    const id = btn.dataset.panel;
    const channelId = prompt('Channel ID to send the panel to (or the panel channel if blank):', '');
    if (channelId === null) return;
    try {
      const body = channelId.trim() ? { channelId: channelId.trim() } : {};
      await api(`/api/guilds/${guildId}/tickets/${id}/send`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel sent to channel', 'success');
      refreshTicketList(guildId);
    } catch (err) { toast(err.message || 'Failed to send', 'error'); }
  });

  action('.tk-update', async (btn) => {
    const id = btn.dataset.panel;
    const messageId = prompt('Message ID to update with this panel (leave blank to update the panel’s last sent message):', '');
    if (messageId === null) return;
    try {
      const body = messageId.trim() ? { messageId: messageId.trim() } : {};
      await api(`/api/guilds/${guildId}/tickets/${id}/update`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel message updated', 'success');
      refreshTicketList(guildId);
    } catch (err) { toast(err.message || 'Failed to update', 'error'); }
  });
}

function bindTicketEvents(guildId) {
  // Sync color picker + text.
  const tkColor = app.querySelector('#tk-color');
  const tkColorText = app.querySelector('#tk-color-text');
  if (tkColor && tkColorText) {
    tkColor.addEventListener('input', () => { tkColorText.value = tkColor.value; });
    tkColorText.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(tkColorText.value)) tkColor.value = tkColorText.value;
    });
  }

  // Add support / ping role rows.
  app.querySelector('#tk-support-add')?.addEventListener('click', () => {
    const ml = app.querySelector('#tk-support-list');
    if (!ml) return;
    ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML({}, 'tk-support'));
    bindReactionRemovals();
    populateRoleSelects();
  });
  app.querySelector('#tk-ping-add')?.addEventListener('click', () => {
    const ml = app.querySelector('#tk-ping-list');
    if (!ml) return;
    ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML({}, 'tk-ping'));
    bindReactionRemovals();
    populateRoleSelects();
  });
  bindReactionRemovals();

  // Save (create or update).
  app.querySelector('#tk-save')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const editId = app.querySelector('#tk-edit-id').value;
    const body = readTicketForm();
    if (!body.name.trim()) { toast('A panel name is required.', 'error'); return; }
    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = 'Saving…';
    try {
      if (editId) {
        await api(`/api/guilds/${guildId}/tickets/${editId}`, { method: 'PATCH', body: JSON.stringify(body) });
        toast('Panel saved', 'success');
      } else {
        await api(`/api/guilds/${guildId}/tickets`, { method: 'POST', body: JSON.stringify(body) });
        toast('Panel created', 'success');
      }
      clearTicketForm();
      refreshTicketList(guildId);
    } catch (err) {
      toast(err.message || 'Failed to save', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });

  app.querySelector('#tk-cancel-edit')?.addEventListener('click', () => {
    clearTicketForm();
  });

  bindTicketCardActions(guildId);
}

// ── Events tab (event management) ───────────────────────────────────────────
//
// Build per-guild event schedules from the dashboard. Each schedule has a name,
// a countdown (seconds to start), and a list of tasks. Each task runs at a
// relative offset (seconds from start) and performs one action:
// lock/unlock/hide/unhide channels, add/remove roles, or send a text/embed
// message. The bot's EventManager reads these tables and runs the tasks.

const EVENT_ACTIONS = [
  { key: 'lock',      label: 'Lock channels',        icon: 'lock', needs: 'channels' },
  { key: 'unlock',    label: 'Unlock channels',      icon: 'unlock', needs: 'channels' },
  { key: 'hide',      label: 'Hide channels',        icon: 'eyeOff', needs: 'channels' },
  { key: 'unhide',    label: 'Unhide channels',      icon: 'eye', needs: 'channels' },
  { key: 'addrole',   label: 'Add role to members',  icon: 'userPlus', needs: 'roles' },
  { key: 'removerole',label: 'Remove role from members', icon: 'userMinus', needs: 'roles' },
  { key: 'sendtext',  label: 'Send text message',    icon: 'message', needs: 'message' },
  { key: 'sendembed', label: 'Send embed message',   icon: 'image', needs: 'embed' },
];

function eventsPanelHTML() {
  return `
    <div class="card">
      <h2>${svgIcon('calendar')} Event Management</h2>
      <p>Schedule an event with a countdown and a list of timed tasks. The bot will lock/unlock or hide/unhide channels, add/remove roles, or send a text/embed message at the offsets you set (seconds from the event start).</p>
      <div class="ev-form" id="ev-form">
        <div class="form-row">
          <label>Event name<input type="text" id="ev-name" placeholder="e.g. Game Night" /></label>
          <label>Countdown (seconds)<input type="number" id="ev-countdown" min="0" value="0" /></label>
        </div>
        <label>Description <textarea id="ev-description" rows="2" placeholder="Optional description"></textarea></label>
        <h4 class="ev-tasks-head">Tasks</h4>
        <div id="ev-tasks-list"></div>
        <button class="btn btn-secondary" id="ev-add-task">+ Add task</button>
        <div class="form-actions">
          <button class="btn btn-primary" id="ev-save">Create event</button>
          <button class="btn btn-secondary" id="ev-clear">Clear</button>
        </div>
      </div>
      <h3 class="ev-list-head">Scheduled events</h3>
      <div id="ev-list"><p class="live-empty">Loading…</p></div>
    </div>
    <div id="ev-modal" class="modal-overlay hidden"></div>
  `;
}

function evTaskRowHTML(task = {}) {
  const a = EVENT_ACTIONS.find(x => x.key === task.action) || EVENT_ACTIONS[0];
  const actionOpts = EVENT_ACTIONS.map(x => `<option value="${x.key}" ${x.key === (task.action || 'sendtext') ? 'selected' : ''}>${esc(x.label)}</option>`).join('');
  const channelOpts = (guildState.channels || []).map(c => `<option value="${esc(c.id)}" ${String(c.id) === String(task.channelId) ? 'selected' : ''}>${esc(c.name)}</option>`).join('');
  const roleOpts = (guildState.roles || []).map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('');
  return `
    <div class="ev-task-row" data-ev-task>
      <label>Offset (s)<input type="number" min="0" class="ev-offset" value="${task.offsetSeconds ?? 0}" /></label>
      <label>Action<select class="ev-action">${actionOpts}</select></label>
      <div class="ev-target">
        <label class="ev-tg-channels">Target channels<select class="ev-target-channels" multiple>${channelOpts}</select></label>
        <label class="ev-tg-roles hidden">Target roles<select class="ev-target-roles" multiple>${roleOpts}</select></label>
        <label class="ev-tg-message hidden">Message text <textarea class="ev-message" rows="2">${esc(task.messageContent || '')}</textarea></label>
        <div class="ev-tg-embed hidden">
          <label>Embed title <input type="text" class="ev-embed-title" value="${esc(task.embedTitle || '')}" /></label>
          <label>Embed description <textarea class="ev-embed-desc" rows="2">${esc(task.embedDescription || '')}</textarea></label>
          <label>Embed color <input type="color" class="ev-embed-color" value="${task.embedColor || '#5865F2'}" /></label>
          <label>Embed image URL <input type="text" class="ev-embed-image" value="${esc(task.embedImageUrl || '')}" /></label>
          <label class="ev-tg-channels">Send to channel(s)<select class="ev-target-embed-channels" multiple>${channelOpts}</select></label>
        </div>
      </div>
      <button class="btn btn-secondary ev-remove-task" title="Remove task">${svgIcon('x')}</button>
    </div>
  `;
}

function bindEvTaskRow(row) {
  const updateVisibility = () => {
    const action = row.querySelector('.ev-action').value;
    const meta = EVENT_ACTIONS.find(x => x.key === action);
    const needs = meta ? meta.needs : 'channels';
    row.querySelector('.ev-tg-channels').classList.toggle('hidden', needs !== 'channels');
    row.querySelector('.ev-tg-roles').classList.toggle('hidden', needs !== 'roles');
    row.querySelector('.ev-tg-message').classList.toggle('hidden', needs !== 'message');
    row.querySelector('.ev-tg-embed').classList.toggle('hidden', needs !== 'embed');
  };
  row.querySelector('.ev-action').addEventListener('change', updateVisibility);
  row.querySelector('.ev-remove-task').addEventListener('click', () => row.remove());
  updateVisibility();
}

function readEventForm() {
  const tasks = [];
  app.querySelectorAll('#ev-tasks-list .ev-task-row').forEach(row => {
    const action = row.querySelector('.ev-action').value;
    const meta = EVENT_ACTIONS.find(x => x.key === action);
    const task = {
      offsetSeconds: parseInt(row.querySelector('.ev-offset').value, 10) || 0,
      action,
      targetType: meta && meta.needs === 'roles' ? 'role' : 'channel',
    };
    if (action === 'addrole' || action === 'removerole') {
      task.targetIds = Array.from(row.querySelector('.ev-target-roles').selectedOptions).map(o => o.value);
    } else if (action === 'sendtext') {
      task.messageContent = row.querySelector('.ev-message').value;
      task.targetIds = Array.from(row.querySelector('.ev-target-channels').selectedOptions).map(o => o.value);
    } else if (action === 'sendembed') {
      task.embedTitle = row.querySelector('.ev-embed-title').value;
      task.embedDescription = row.querySelector('.ev-embed-desc').value;
      task.embedColor = row.querySelector('.ev-embed-color').value;
      task.embedImageUrl = row.querySelector('.ev-embed-image').value;
      task.targetIds = Array.from(row.querySelector('.ev-target-embed-channels').selectedOptions).map(o => o.value);
    } else {
      task.targetIds = Array.from(row.querySelector('.ev-target-channels').selectedOptions).map(o => o.value);
    }
    tasks.push(task);
  });
  return {
    name: app.querySelector('#ev-name').value,
    countdownSeconds: parseInt(app.querySelector('#ev-countdown').value, 10) || 0,
    description: app.querySelector('#ev-description').value,
    tasks,
  };
}

function clearEventForm() {
  app.querySelector('#ev-name').value = '';
  app.querySelector('#ev-countdown').value = '0';
  app.querySelector('#ev-description').value = '';
  app.querySelector('#ev-tasks-list').innerHTML = '';
}

function eventStatusBadge(status) {
  const map = {
    scheduled: { c: 'tag off', t: 'Scheduled' },
    running: { c: 'tag on', t: 'Running' },
    completed: { c: 'tag prefix', t: 'Completed' },
    cancelled: { c: 'tag off', t: 'Cancelled' },
  };
  const m = map[status] || map.scheduled;
  return `<span class="${m.c}">${m.t}</span>`;
}

function eventScheduleCardHTML(s) {
  const tasksHTML = (s.tasks || []).map(t => {
    const meta = EVENT_ACTIONS.find(x => x.key === t.action) || {};
    return `<li>${meta.icon ? svgIcon(meta.icon) : ''} ${esc(meta.label || t.action)} @ +${t.offsetSeconds}s</li>`;
  }).join('');
  const start = s.startAt ? new Date(s.startAt).toLocaleString() : '—';
  return `
    <div class="live-card ev-card" data-ev-id="${s.id}">
      <div class="live-card-title">${esc(s.name)}</div>
      <div class="live-card-meta">${eventStatusBadge(s.status)} • countdown ${s.countdownSeconds}s • start ${esc(start)}</div>
      ${s.description ? `<div class="live-card-opts">${esc(s.description)}</div>` : ''}
      <div class="ev-tasks"><strong>Tasks:</strong><ul>${tasksHTML || '<li>none</li>'}</ul></div>
      <div class="ev-actions">
        <button class="btn btn-primary ev-start" data-id="${s.id}">Start now</button>
        <button class="btn btn-secondary ev-cancel" data-id="${s.id}">Cancel</button>
        <button class="btn btn-secondary ev-delete" data-id="${s.id}">Delete</button>
      </div>
    </div>
  `;
}

async function loadEventSchedules(guildId) {
  const list = app.querySelector('#ev-list');
  if (!list) return;
  try {
    const data = await api(`/api/guilds/${guildId}/events`);
    const schedules = data.schedules || [];
    list.innerHTML = schedules.length
      ? schedules.map(eventScheduleCardHTML).join('')
      : '<p class="live-empty">No events yet. Create one above.</p>';
    bindEventCardActions(guildId);
    animateCards(list);
  } catch (err) {
    list.innerHTML = `<div class="alert alert-error">${esc(err.message || 'Failed to load events.')}</div>`;
  }
}

function bindEventCardActions(guildId) {
  app.querySelectorAll('#ev-list .ev-start').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${guildId}/events/${btn.dataset.id}/start`, { method: 'POST' }); toast('Event started.'); loadEventSchedules(guildId); }
    catch (e) { toast(e.message, 'error'); }
  }));
  app.querySelectorAll('#ev-list .ev-cancel').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${guildId}/events/${btn.dataset.id}/cancel`, { method: 'POST' }); toast('Event cancelled.'); loadEventSchedules(guildId); }
    catch (e) { toast(e.message, 'error'); }
  }));
  app.querySelectorAll('#ev-list .ev-delete').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${guildId}/events/${btn.dataset.id}`, { method: 'DELETE' }); toast('Event deleted.'); loadEventSchedules(guildId); }
    catch (e) { toast(e.message, 'error'); }
  }));
}

function bindEventsTab(guildId) {
  app.querySelector('#ev-add-task')?.addEventListener('click', () => {
    const row = document.createElement('div');
    row.innerHTML = evTaskRowHTML({});
    const el = row.firstElementChild;
    app.querySelector('#ev-tasks-list').appendChild(el);
    bindEvTaskRow(el);
  });
  app.querySelector('#ev-clear')?.addEventListener('click', clearEventForm);
  app.querySelector('#ev-save')?.addEventListener('click', async () => {
    const body = readEventForm();
    if (!body.name.trim()) { toast('Event name is required.', 'error'); return; }
    try {
      await api(`/api/guilds/${guildId}/events`, { method: 'POST', body: JSON.stringify(body) });
      toast('Event created.');
      clearEventForm();
      loadEventSchedules(guildId);
    } catch (e) { toast(e.message, 'error'); }
  });
}

function reactionRolesPanelHTML(menus = []) {
  const listHTML = menus.length
    ? menus.map(rrMenuCardHTML).join('')
    : `<div class="alert alert-warn">No reaction-role menus yet. Create one below.</div>`;
  const modeOpts = RR_MODES.map(m => `<option value="${m.value}">${esc(m.label)}</option>`).join('');
  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('tag')}</span> Reaction Roles</span></div>
      <p class="card-desc">Let members self-assign roles by reacting. PrimeBot gives you premium modes for free: <strong>toggle</strong>, <strong>sticky</strong> (one-click assign), <strong>verify</strong> (grant once, e.g. rules gate), and <strong>unique</strong> (only one role at a time). Roles persist across bot restarts.</p>
      <div class="rr-list">${listHTML}</div>
    </div>

    <div class="card">
      <div class="card-title"><span>Create a new menu</span></div>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Attach to an existing message</div>
          <div class="sl-desc">When ON, the bot adds reactions to a message you already posted (by message ID). When OFF, the bot posts a fresh role embed.</div>
        </div>
        <label class="switch"><input type="checkbox" id="rr-attach"/><span class="slider"></span></label>
      </div>

      <div class="field" id="rr-message-field" style="display:none">
        <label class="field-label" for="rr-message-id">Message ID to attach to</label>
        <input type="text" id="rr-message-id" placeholder="123456789012345678" />
        <div class="field-hint">Right-click any message → Copy Message ID (enable Developer Mode in Discord settings).</div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-channel">Channel</label>
        <select id="rr-channel" data-channel-select><option value="">— Select channel —</option></select>
        <div class="field-hint">Where the role embed is posted (or where the target message lives).</div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-title">Embed title / menu label</label>
        <input type="text" id="rr-title" maxlength="255" placeholder="Pick your roles!" />
        <div class="field-hint">Shown as the embed title (bot-created) and as the menu label in the dashboard.</div>
      </div>

      <div class="field" id="rr-description-field">
        <label class="field-label" for="rr-description">Embed description</label>
        <textarea id="rr-description" placeholder="React below to give yourself a role!"></textarea>
        <div class="field-hint">Body text of the role embed (hidden when attaching to an existing message).</div>
      </div>

      <div class="field">
        <label class="field-label">Emoji → role mappings</label>
        <div class="reactions-list" id="rr-mappings-list">${rrMappingRowHTML()}</div>
        <button class="btn btn-secondary" id="rr-mapping-add">+ Add mapping</button>
        <div class="field-hint">Use a unicode emoji or a custom emoji reference like <code>&lt;:name:id&gt;</code>.</div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-mode">Behavior mode</label>
        <select id="rr-mode">${modeOpts}</select>
        <div class="field-hint">Premium modes — all free.</div>
      </div>

      <div class="field">
        <label class="field-label">Embed color</label>
        <div class="color-field">
          <input type="color" id="rr-color" value="#5865F2" />
          <input type="text" id="rr-color-text" value="#5865F2" style="flex:1" />
        </div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-required-role">Required role (optional)</label>
        <select id="rr-required-role" data-role-select data-placeholder="— Anyone —"></select>
        <div class="field-hint">Members must have this role to use the menu.</div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-exclusive-role">Exclusive role (optional)</label>
        <select id="rr-exclusive-role" data-role-select data-placeholder="— None —"></select>
        <div class="field-hint">Removed from a member when they take a role from this menu (cross-menu mutual exclusion).</div>
      </div>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Persistent</div><div class="sl-desc">Re-apply roles on bot restart by reading the message's reactions.</div></div>
        <label class="switch"><input type="checkbox" id="rr-persistent" checked/><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Allow bots</div><div class="sl-desc">Let bots trigger the menu too (off by default).</div></div>
        <label class="switch"><input type="checkbox" id="rr-include-bots"/><span class="slider"></span></label>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" id="rr-create">Create reaction-role menu</button>
      </div>
    </div>
  `;
}

function loggingPanelHTML(logging) {
  const s = logging || {};
  const enabled = new Set(Array.isArray(s.events) ? s.events : []);
  const categories = [...new Set(LOG_EVENTS.map(e => e.category))];
  const eventToggles = categories.map(cat => {
    const items = LOG_EVENTS.filter(e => e.category === cat)
      .map(e => `
        <label class="switch mini">
          <input type="checkbox" class="log-event" data-event="${esc(e.key)}" ${enabled.has(e.key) ? 'checked' : ''}/>
          <span class="slider"></span>
          <span class="switch-text">${e.icon} ${esc(e.label)}</span>
        </label>`).join('');
    return `<div class="event-group"><div class="event-group-title">${esc(cat)}</div>${items}</div>`;
  }).join('');

  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('fileText')}</span> Server logging</span></div>
      <p class="card-desc">Send rich embed logs of server events to a channel and/or a Discord webhook.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable logging</div>
          <div class="sl-desc">Master switch. When off, no log embeds are sent for this server.</div>
        </div>
        <label class="switch"><input type="checkbox" id="logging-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="logging-channel">Log channel</label>
        <select id="logging-channel" data-channel-select><option value="">— None —</option></select>
        <div class="field-hint">Channel where log embeds are posted as the bot. The bot needs View Channel + Send Messages here.</div>
      </div>

      <div class="field">
        <label class="field-label" for="logging-webhook">Webhook URL (optional)</label>
        <input type="url" id="logging-webhook" value="${esc(s.webhookUrl || '')}" placeholder="https://discord.com/api/webhooks/…" />
        <div class="field-hint">When set, logs are also posted via this webhook. Works in channels the bot can't see. <a href="https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks" target="_blank" rel="noopener">How to make one →</a></div>
      </div>

      <div class="field">
        <label class="field-label" for="logging-webhook-name">Webhook display name</label>
        <input type="text" id="logging-webhook-name" maxlength="100" value="${esc(s.webhookName || 'PrimeBot Logs')}" placeholder="PrimeBot Logs" />
        <div class="field-hint">Name shown on webhook-delivered logs.</div>
      </div>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Include bot activity</div>
          <div class="sl-desc">Also log actions performed by bots (off by default to reduce noise).</div>
        </div>
        <label class="switch"><input type="checkbox" id="logging-include-bots" ${s.includeBots ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label">Embed color</label>
        <div class="color-field">
          <input type="color" id="logging-color" value="${esc(s.color || '#5865F2')}" />
          <input type="text" id="logging-color-text" value="${esc(s.color || '#5865F2')}" style="flex:1" />
        </div>
        <div class="field-hint">Default color for log embeds (some event types override this).</div>
      </div>

      <div class="field">
        <label class="field-label">Logged events</label>
        <div class="event-grid">${eventToggles}</div>
        <div class="field-hint">Choose which event types generate a log embed.</div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="logging">Save logging settings</button>
      </div>
    </div>
  `;
}

// ── Automod panel ───────────────────────────────────────────────────────────
// Premium automod: per-guild rules (blocked words, invites, links, spam,
// mentions, caps, emoji, newlines, zalgo), each with a configurable action,
// plus a warning ledger with escalation. All free — PrimeBot's motto.

function automodRuleRowHTML(rule = {}) {
  const meta = AUTOMOD_RULES.find(r => r.key === rule.type) || AUTOMOD_RULES[0];
  const selected = Array.isArray(rule.actions) && rule.actions.length
    ? rule.actions
    : (rule.action ? [rule.action] : ['delete']);
  const actionChecks = AUTOMOD_ACTIONS.map(a =>
    `<label class="switch mini am-action-label"><input type="checkbox" class="am-action" value="${a.key}" ${selected.includes(a.key) ? 'checked' : ''}/><span class="switch-text">${svgIcon(a.icon)} ${esc(a.label)}</span></label>`
  ).join('');
  let extra = '';
  if (meta.params.includes('words')) {
    extra = `<input type="text" class="am-words" value="${esc((rule.words || []).join(', '))}" placeholder="extra domains/terms (comma-separated)" />`;
  }
  if (meta.params.includes('threshold')) {
    extra += `<input type="number" class="am-threshold" value="${rule.threshold ?? ''}" placeholder="threshold" min="1" style="width:96px" />`;
  }
  if (meta.params.includes('seconds')) {
    extra += `<input type="number" class="am-seconds" value="${rule.seconds ?? ''}" placeholder="seconds" min="1" max="3600" style="width:96px" />`;
  }
  return `
    <div class="reaction-row am-rule-row" data-type="${esc(meta.key)}">
      <label class="switch mini"><input type="checkbox" class="am-enabled" ${rule.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
      <span class="am-rule-label">${svgIcon(meta.icon)} ${esc(meta.label)}</span>
      <div class="am-actions-group">${actionChecks}</div>
      ${extra}
      <button class="reaction-remove am-remove" type="button">${svgIcon('x')}</button>
    </div>
  `;
}

function automodPanelHTML(automod) {
  const s = automod || {};
  const rules = Array.isArray(s.rules) ? s.rules : [];
  const ruleRows = rules.length ? rules.map(automodRuleRowHTML).join('') : '';
  const addTypeOpts = AUTOMOD_RULES.map(r => `<option value="${r.key}">${esc(r.label)}</option>`).join('');
  const warnActionChecks = AUTOMOD_WARN_ACTIONS.map(a =>
    `<label class="switch mini am-action-label"><input type="checkbox" class="am-warn-action" value="${a.key}" ${(s.warnActions || [s.warnAction || 'timeout']).includes(a.key) ? 'checked' : ''}/><span class="switch-text">${svgIcon(a.icon)} ${esc(a.label)}</span></label>`
  ).join('');
  const dmMessages = s.dmMessages || {};
  const dmRows = AUTOMOD_DM_KEYS.map(k => {
    const a = AUTOMOD_ACTIONS.find(x => x.key === k);
    const label = a ? `${svgIcon(a.icon)} ${a.label}` : (k === 'escalation' ? 'Escalation' : k);
    return `<div class="field-row"><label class="field-label" style="min-width:120px">${label}</label><input type="text" class="am-dm-message" data-key="${k}" value="${esc(dmMessages[k] || '')}" placeholder="(use default)" style="flex:1"/></div>`;
  }).join('');

  return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('shield')}</span> Premium Automod</span></div>
      <p class="card-desc">Automatic moderation that scans every message against your rules. Premium features for free: blocked words, invite/bad-link/NSFW filtering, spam &amp; mass-mention detection, caps/emoji/repeated-char/new-account filters, multi-action punishment, DM notifications, warning escalation, and appeals.</p>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Enable Automod</div><div class="sl-desc">Master switch. When off, no messages are scanned.</div></div>
        <label class="switch"><input type="checkbox" id="am-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="am-log-channel">Automod log channel (optional)</label>
        <select id="am-log-channel" data-channel-select><option value="">— None —</option>${s.logChannelId ? `<option value="${esc(s.logChannelId)}" selected>Channel</option>` : ''}</select>
        <div class="field-hint">Where automod actions are posted as the bot.</div>
      </div>

      <div class="field">
        <label class="field-label" for="am-mute-role">Mute role (optional)</label>
        <select id="am-mute-role" data-role-select data-placeholder="— None (use timeouts) —">${s.muteRoleId ? `<option value="${esc(s.muteRoleId)}" selected>Role</option>` : ''}</select>
        <div class="field-hint">Used for mutes when the bot can't apply a native timeout. Set this to enable indefinite mutes.</div>
      </div>

      <div class="field">
        <label class="field-label">Exempt roles</label>
        <div class="field-hint">Members with these roles (and admins) are never actioned.</div>
        <div class="rr-list" id="am-exempt-roles"></div>
      </div>

      <div class="field">
        <label class="field-label">Exempt channels</label>
        <div class="field-hint">Messages in these channels are never scanned.</div>
        <div class="rr-list" id="am-exempt-channels"></div>
      </div>

      <div class="field">
        <label class="field-label">Rules</label>
        <div class="reactions-list" id="am-rules-list">${ruleRows}</div>
        <div style="display:flex; gap:8px; align-items:center; margin-top:8px">
          <select id="am-add-type">${addTypeOpts}</select>
          <button class="btn btn-secondary" id="am-add-rule">+ Add rule</button>
        </div>
        <div class="field-hint">Select one or more actions per rule. "Delete" is always applied first when chosen.</div>
      </div>

      <div class="field">
        <label class="field-label">Warning escalation</label>
        <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap">
          <label>After <input type="number" id="am-warn-threshold" value="${s.warnThreshold ?? 3}" min="1" max="50" style="width:72px"/> warnings</label>
          <span>→ apply:</span>
        </div>
        <div class="am-actions-group" id="am-warn-actions-group" style="margin-top:6px">${warnActionChecks}</div>
        <div class="field-hint">When a member's total warnings reach the threshold, these actions apply automatically and their warnings are cleared. Select multiple to escalate through several punishments at once.</div>
      </div>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">DM punished members</div><div class="sl-desc">Send a direct message to members when an action is taken against them.</div></div>
        <label class="switch"><input type="checkbox" id="am-dm-enabled" ${s.dmEnabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label">Custom DM messages (optional)</label>
        <div class="field-hint">Override the default message sent for each action. Placeholders: {server}, {reason}, {action}, {threshold}. Leave blank to use the default.</div>
        <div class="field-rows" id="am-dm-messages">${dmRows}</div>
      </div>

      <div class="field">
        <label class="field-label" for="am-appeal-channel">Appeal channel (optional)</label>
        <select id="am-appeal-channel" data-channel-select><option value="">— None —</option>${s.appealChannelId ? `<option value="${esc(s.appealChannelId)}" selected>Channel</option>` : ''}</select>
        <div class="field-hint">New appeals filed via <code>/appeal</code> are posted here for moderators to review.</div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" data-save="automod">Save automod settings</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('alertTriangle')}</span> Warnings</span></div>
      <p class="card-desc">Live warning ledger for this server (automod + manual <code>/warn</code>). <a href="#" id="am-refresh-warnings">Refresh</a></p>
      <div id="am-warnings-list"><div class="field-hint">Loading…</div></div>
    </div>

    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('envelope')}</span> Appeals</span></div>
      <p class="card-desc">Punishment appeals filed by members. Approving an appeal reverses the action (unban/unmute) automatically. <a href="#" id="am-refresh-appeals">Refresh</a></p>
      <div id="am-appeals-list"><div class="field-hint">Loading…</div></div>
    </div>
  `;
}

// ── Event binding ──────────────────────────────────────────────────────────

function bindSettingsEvents(guildId) {
  app.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => selectTab(t.dataset.tab));
  });

  bindEventsTab(guildId);

  // Sync color picker + text input.
  const colorPicker = app.querySelector('#welcome-color');
  const colorText = app.querySelector('#welcome-color-text');
  if (colorPicker && colorText) {
    colorPicker.addEventListener('input', () => { colorText.value = colorPicker.value; });
    colorText.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(colorText.value)) colorPicker.value = colorText.value;
    });
  }

  // Sync logging color picker + text input.
  const logColorPicker = app.querySelector('#logging-color');
  const logColorText = app.querySelector('#logging-color-text');
  if (logColorPicker && logColorText) {
    logColorPicker.addEventListener('input', () => { logColorText.value = logColorPicker.value; });
    logColorText.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(logColorText.value)) logColorPicker.value = logColorText.value;
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

  // Reaction Roles tab bindings.
  bindReactionRolesEvents(guildId);

  // Automod tab bindings.
  bindAutomodEvents(guildId);

  // Tickets tab bindings.
  bindTicketEvents(guildId);

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

// ── Reaction Roles tab: bindings + create/edit/delete ───────────────────────

function collectRrMappings() {
  const out = [];
  app.querySelectorAll('#rr-mappings-list .reaction-row').forEach(row => {
    const emoji = row.querySelector('.r-emoji')?.value.trim();
    const roleId = row.querySelector('.r-role')?.value;
    const label = row.querySelector('.r-label')?.value.trim();
    if (emoji && roleId) out.push({ emoji, roleId, label: label || null });
  });
  return out;
}

async function refreshRrList(guildId) {
  try {
    const data = await api(`/api/guilds/${guildId}/reactionroles`);
    const listEl = app.querySelector('.rr-list');
    if (listEl) {
      const menus = data.reactionRoles || [];
      listEl.innerHTML = menus.length
        ? menus.map(rrMenuCardHTML).join('')
        : `<div class="alert alert-warn">No reaction-role menus yet. Create one below.</div>`;
      bindRrCardActions(guildId);
      animateCards(listEl);
    }
  } catch (_) { /* surfaced via toast elsewhere */ }
}

function bindRrCardActions(guildId) {
  app.querySelectorAll('.rr-delete').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const id = btn.dataset.menu;
      if (!confirm('Delete this reaction-role menu? The bot will stop watching the message. Roles already granted stay.')) return;
      try {
        await api(`/api/guilds/${guildId}/reactionroles/${id}`, { method: 'DELETE' });
        toast('Menu deleted', 'success');
        refreshRrList(guildId);
      } catch (err) {
        toast(err.message || 'Failed to delete', 'error');
      }
    });
  });
  app.querySelectorAll('.rr-edit').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const id = btn.dataset.menu;
      const card = btn.closest('.rr-menu-card');
      const menus = (await api(`/api/guilds/${guildId}/reactionroles`).catch(() => ({}))).reactionRoles || [];
      const menu = menus.find(m => String(m.id) === String(id));
      if (!menu) { toast('Menu not found', 'error'); return; }
      // Inline edit modal (simple prompt-based for the common cases).
      const nextTitle = prompt('Title (leave blank to keep):', menu.title || '');
      if (nextTitle !== null && nextTitle !== (menu.title || '')) {
        try {
          await api(`/api/guilds/${guildId}/reactionroles/${id}`, { method: 'PATCH', body: JSON.stringify({ title: nextTitle }) });
          toast('Updated', 'success');
          refreshRrList(guildId);
        } catch (err) { toast(err.message, 'error'); }
      }
    });
  });
}

function bindReactionRolesEvents(guildId) {
  // Toggle attach vs bot-created visibility.
  const attachToggle = app.querySelector('#rr-attach');
  if (attachToggle) {
    const sync = () => {
      const attach = attachToggle.checked;
      const msgField = app.querySelector('#rr-message-field');
      const descField = app.querySelector('#rr-description-field');
      if (msgField) msgField.style.display = attach ? '' : 'none';
      if (descField) descField.style.display = attach ? 'none' : '';
    };
    attachToggle.addEventListener('change', sync);
    sync();
  }

  // Sync color picker + text.
  const rrColor = app.querySelector('#rr-color');
  const rrColorText = app.querySelector('#rr-color-text');
  if (rrColor && rrColorText) {
    rrColor.addEventListener('input', () => { rrColorText.value = rrColor.value; });
    rrColorText.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(rrColorText.value)) rrColor.value = rrColorText.value;
    });
  }

  // Add/remove mapping rows.
  app.querySelector('#rr-mapping-add')?.addEventListener('click', () => {
    const ml = app.querySelector('#rr-mappings-list');
    if (!ml) return;
    ml.insertAdjacentHTML('beforeend', rrMappingRowHTML());
    bindReactionRemovals();
    populateRoleSelects();
  });
  bindReactionRemovals();

  // Create button.
  app.querySelector('#rr-create')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const attach = !!app.querySelector('#rr-attach')?.checked;
    const channelId = app.querySelector('#rr-channel')?.value;
    const messageId = app.querySelector('#rr-message-id')?.value.trim();
    const mappings = collectRrMappings();
    if (mappings.length === 0) { toast('Add at least one emoji→role mapping.', 'error'); return; }
    if (!channelId) { toast('Select a channel.', 'error'); return; }
    if (attach && !messageId) { toast('Enter the message ID to attach to.', 'error'); return; }
    const body = {
      attach,
      channelId,
      messageId: attach ? messageId : undefined,
      title: app.querySelector('#rr-title')?.value.trim() || null,
      description: app.querySelector('#rr-description')?.value || null,
      color: app.querySelector('#rr-color')?.value || '#5865F2',
      mode: app.querySelector('#rr-mode')?.value || 'normal',
      persistent: app.querySelector('#rr-persistent')?.checked !== false,
      includeBots: !!app.querySelector('#rr-include-bots')?.checked,
      requiredRoleId: app.querySelector('#rr-required-role')?.value || null,
      exclusiveRoleId: app.querySelector('#rr-exclusive-role')?.value || null,
      mappings,
    };
    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = 'Creating…';
    try {
      await api(`/api/guilds/${guildId}/reactionroles`, { method: 'POST', body: JSON.stringify(body) });
      toast('Reaction-role menu created', 'success');
      refreshRrList(guildId);
      // Clear the create form.
      app.querySelector('#rr-title').value = '';
      app.querySelector('#rr-description').value = '';
      app.querySelector('#rr-message-id').value = '';
      const ml = app.querySelector('#rr-mappings-list');
      if (ml) ml.innerHTML = rrMappingRowHTML();
      bindReactionRemovals();
      populateRoleSelects();
    } catch (err) {
      toast(err.message || 'Failed to create', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });

  bindRrCardActions(guildId);
}

// ── Automod tab: bindings + warnings ─────────────────────────────────────────

function renderAmExemptLists() {
  const s = guildState?.config?.automod || {};
  const roleSet = new Set(s.exemptRoleIds || []);
  const chanSet = new Set(s.exemptChannelIds || []);
  const roles = (guildState.roles || []).map(r =>
    `<label class="switch mini"><input type="checkbox" class="am-exempt-role" value="${esc(r.id)}" ${roleSet.has(r.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(r.name)}</span></label>`
  ).join('') || '<div class="field-hint">No roles loaded.</div>';
  const channels = (guildState.channels || []).map(c =>
    `<label class="switch mini"><input type="checkbox" class="am-exempt-channel" value="${esc(c.id)}" ${chanSet.has(c.id) ? 'checked' : ''}/><span class="slider"></span><span class="switch-text">${esc(c.name)}</span></label>`
  ).join('') || '<div class="field-hint">No channels loaded.</div>';
  const rolesEl = app.querySelector('#am-exempt-roles');
  const chanEl = app.querySelector('#am-exempt-channels');
  if (rolesEl) rolesEl.innerHTML = roles;
  if (chanEl) chanEl.innerHTML = channels;
}

function collectAmRules() {
  const out = [];
  app.querySelectorAll('#am-rules-list .am-rule-row').forEach(row => {
    const type = row.dataset.type;
    if (!type) return;
    const actions = [];
    row.querySelectorAll('.am-action').forEach(cb => { if (cb.checked) actions.push(cb.value); });
    const rule = {
      type,
      enabled: row.querySelector('.am-enabled')?.checked !== false,
      actions: actions.length ? actions : ['delete'],
    };
    const words = row.querySelector('.am-words')?.value.trim();
    if (words) rule.words = words.split(',').map(w => w.trim().toLowerCase()).filter(Boolean);
    const threshold = parseInt(row.querySelector('.am-threshold')?.value, 10);
    if (Number.isFinite(threshold)) rule.threshold = threshold;
    const seconds = parseInt(row.querySelector('.am-seconds')?.value, 10);
    if (Number.isFinite(seconds)) rule.seconds = seconds;
    out.push(rule);
  });
  return out;
}

async function refreshAmWarnings(guildId) {
  const el = app.querySelector('#am-warnings-list');
  if (!el) return;
  el.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api(`/api/guilds/${guildId}/automod/warnings`);
    const warnings = data.warnings || [];
    if (warnings.length === 0) {
      el.innerHTML = '<div class="field-hint">No warnings recorded.</div>';
      return;
    }
    el.innerHTML = warnings.slice(0, 50).map(w => {
      const when = new Date(w.createdAt).toLocaleString();
      const who = w.userId ? `<@${esc(w.userId)}>` : 'unknown';
      const by = w.moderatorId ? (w.moderatorId === 'automod' ? 'Automod' : `<@${esc(w.moderatorId)}>`) : 'Automod';
      return `<div class="rr-menu-card"><div class="card-title"><span>${esc(w.ruleType || 'manual')} · ${esc(w.reason || '')}</span></div><div class="rr-meta"><span><strong>User:</strong> ${who}</span><span><strong>By:</strong> ${by}</span><span><strong>When:</strong> ${esc(when)}</span></div></div>`;
    }).join('');
  } catch (err) {
    el.innerHTML = '<div class="field-hint">Failed to load warnings.</div>';
  }
}

async function refreshAmAppeals(guildId) {
  const el = app.querySelector('#am-appeals-list');
  if (!el) return;
  el.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api(`/api/guilds/${guildId}/automod/appeals`);
    const appeals = data.appeals || [];
    if (appeals.length === 0) {
      el.innerHTML = '<div class="field-hint">No appeals filed.</div>';
      return;
    }
    el.innerHTML = appeals.slice(0, 50).map(a => {
      const when = new Date(a.createdAt).toLocaleString();
      const who = a.userId ? `<@${esc(a.userId)}>` : 'unknown';
      const statusBadge = a.status === 'pending'
        ? '<span style="color:var(--warn)">pending</span>'
        : (a.status === 'approved' ? '<span style="color:var(--green)">approved</span>' : '<span style="color:var(--red)">denied</span>');
      const decide = a.status === 'pending'
        ? `<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
             <input type="text" class="am-appeal-note" data-id="${a.id}" placeholder="note (optional)" style="flex:1;min-width:160px"/>
             <button class="btn btn-primary am-appeal-approve" data-id="${a.id}">Approve</button>
             <button class="btn btn-secondary am-appeal-deny" data-id="${a.id}">Deny</button>
           </div>`
        : `<div class="field-hint">Decided by ${esc(a.decidedBy || 'moderator')}${a.decisionNote ? ': ' + esc(a.decisionNote) : ''}${a.reversed ? ' · action reversed' : ''}</div>`;
      return `<div class="rr-menu-card"><div class="card-title"><span>${esc(a.action)} · ${esc(a.reason || '')}</span></div><div class="rr-meta"><span><strong>User:</strong> ${who}</span><span><strong>Status:</strong> ${statusBadge}</span><span><strong>When:</strong> ${esc(when)}</span></div>${decide}</div>`;
    }).join('');
    // Wire approve/deny buttons.
    el.querySelectorAll('.am-appeal-approve').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const note = el.querySelector(`.am-appeal-note[data-id="${id}"]`)?.value || '';
        btn.disabled = true;
        await api(`/api/guilds/${guildId}/automod/appeals/${id}`, { method: 'PATCH', body: JSON.stringify({ approved: true, note }) });
        await refreshAmAppeals(guildId);
      });
    });
    el.querySelectorAll('.am-appeal-deny').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const note = el.querySelector(`.am-appeal-note[data-id="${id}"]`)?.value || '';
        btn.disabled = true;
        await api(`/api/guilds/${guildId}/automod/appeals/${id}`, { method: 'PATCH', body: JSON.stringify({ approved: false, note }) });
        await refreshAmAppeals(guildId);
      });
    });
  } catch (err) {
    el.innerHTML = '<div class="field-hint">Failed to load appeals.</div>';
  }
}

function bindAutomodEvents(guildId) {
  renderAmExemptLists();
  bindReactionRemovals(); // also binds .am-remove via .reaction-remove

  app.querySelector('#am-add-rule')?.addEventListener('click', () => {
    const type = app.querySelector('#am-add-type')?.value || 'invites';
    const list = app.querySelector('#am-rules-list');
    if (!list) return;
    list.insertAdjacentHTML('beforeend', automodRuleRowHTML({ type, enabled: true, actions: ['delete'] }));
    bindReactionRemovals();
  });

  app.querySelector('#am-refresh-warnings')?.addEventListener('click', (e) => {
    e.preventDefault();
    refreshAmWarnings(guildId);
  });

  app.querySelector('#am-refresh-appeals')?.addEventListener('click', (e) => {
    e.preventDefault();
    refreshAmAppeals(guildId);
  });

  refreshAmWarnings(guildId);
  refreshAmAppeals(guildId);
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
  } else if (kind === 'logging') {
    const events = [];
    app.querySelectorAll('.log-event').forEach(cb => {
      if (cb.checked) events.push(cb.dataset.event);
    });
    const webhookUrl = app.querySelector('#logging-webhook').value.trim();
    if (webhookUrl && !/^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i.test(webhookUrl)) {
      throw new Error('Webhook URL must be a valid Discord webhook URL.');
    }
    const body = {
      enabled: app.querySelector('#logging-enabled').checked,
      channelId: app.querySelector('#logging-channel').value || null,
      webhookUrl: webhookUrl || null,
      webhookName: app.querySelector('#logging-webhook-name').value.trim() || 'PrimeBot Logs',
      events,
      includeBots: app.querySelector('#logging-include-bots').checked,
      color: app.querySelector('#logging-color').value,
    };
    await api(`/api/guilds/${guildId}/logging`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'automod') {
    const exemptRoleIds = [];
    app.querySelectorAll('.am-exempt-role').forEach(cb => { if (cb.checked) exemptRoleIds.push(cb.value); });
    const exemptChannelIds = [];
    app.querySelectorAll('.am-exempt-channel').forEach(cb => { if (cb.checked) exemptChannelIds.push(cb.value); });
    const warnActions = [];
    app.querySelectorAll('.am-warn-action').forEach(cb => { if (cb.checked) warnActions.push(cb.value); });
    const dmMessages = {};
    app.querySelectorAll('.am-dm-message').forEach(inp => {
      const key = inp.dataset.key;
      const val = inp.value.trim();
      if (key && val) dmMessages[key] = val;
    });
    const body = {
      enabled: app.querySelector('#am-enabled').checked,
      logChannelId: app.querySelector('#am-log-channel').value || null,
      muteRoleId: app.querySelector('#am-mute-role').value || null,
      exemptRoleIds,
      exemptChannelIds,
      rules: collectAmRules(),
      warnThreshold: parseInt(app.querySelector('#am-warn-threshold').value, 10) || 3,
      warnActions: warnActions.length ? warnActions : ['timeout'],
      dmEnabled: app.querySelector('#am-dm-enabled').checked,
      dmMessages,
      appealChannelId: app.querySelector('#am-appeal-channel').value || null,
    };
    await api(`/api/guilds/${guildId}/automod`, { method: 'PATCH', body: JSON.stringify(body) });
  }
}

// ── Go ─────────────────────────────────────────────────────────────────────

boot();
