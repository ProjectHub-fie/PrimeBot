/**
 * Server-rendered guild settings page helpers.
 *
 * Each settings tab is its own HTML page at /guild/:guildId/<tab>. They share a
 * header card (guild icon + name + member count) and a tab navigation bar that
 * is a row of real links. This module renders both, plus the small JSON blob
 * (#guild-data) the per-page client scripts read to populate channel/role
 * <select>s without an extra API round-trip.
 */

const { esc, guildIconHTML, svgIcon } = require('./layout');

// Each settings tab is a sidebar menu entry. `icon` is the SVG icon name (see
// dashboard/public/js/icons.js). `beta` flags the feature as a beta release —
// the menu + page render a "BETA" badge next to its label. `upcoming` flags a
// feature as not-yet-released — the menu renders a "SOON" badge and the page
// renders a "Coming Soon" overlay (upcoming takes priority over beta when both
// are set).
const TABS = [
  { key: 'prefix',         label: 'General',         icon: 'settings' },
  { key: 'welcome',        label: 'Welcome',         icon: 'hand' },
  { key: 'leveling',       label: 'Leveling',        icon: 'trendingUp' },
  { key: 'badges',         label: 'Badges',          icon: 'award',     beta: true },
  { key: 'rolerewards',    label: 'Role Rewards',    icon: 'gift',      beta: true },
  { key: 'autoresponder',  label: 'Auto-Responder',  icon: 'message' },
  { key: 'reactions',      label: 'Auto-Reactions',  icon: 'repeat' },
  { key: 'reactionroles',  label: 'Reaction Roles',  icon: 'smile' },
  { key: 'broadcast',      label: 'Broadcasts',      icon: 'megaphone' },
  { key: 'birthdays',      label: 'Birthdays',       icon: 'cake' },
  { key: 'logging',        label: 'Logging',         icon: 'scroll' },
  { key: 'automod',        label: 'Automod',         icon: 'shield' },
  { key: 'tickets',        label: 'Tickets',         icon: 'ticket' },
  { key: 'live/polls',     label: 'Live Polls',      icon: 'barChart' },
  { key: 'live/giveaways', label: 'Live Giveaways',  icon: 'gift' },
  { key: 'events',         label: 'Events',          icon: 'calendar',  upcoming: true },
];

// The inlined channel/role <option> data + guild id. Pages embed this so the
// client can populate selects immediately.
function guildDataScript({ guildId, channels = [], roles = [], extra = {} }) {
  const data = JSON.stringify({ guildId, channels, roles, ...extra })
      .replace(/</g, '\\u003c');
  return `<script type="application/json" id="guild-data">${data}</script>`;
}

function guildHeaderHTML(guild) {
  const members = guild && guild.approximate_member_count != null
    ? `${Number(guild.approximate_member_count).toLocaleString()} members`
    : '';
  const owner = guild && guild.userIsOwner ? ' · You are the owner' : '';
  return `
    <div class="breadcrumb"><a href="/">Servers</a> <span>/</span> <span>${esc(guild.name)}</span></div>
    <div class="guild-header-card card">
      <div class="guild-icon">${guildIconHTML(guild)}</div>
      <div>
        <h1>${esc(guild.name)}</h1>
        <div class="meta">${members}${owner}</div>
      </div>
    </div>`;
}

// Sidebar menu ("turn left" slide-in). A button toggles a drawer that slides in
// from the left edge. Each tab is a real link; the active one is highlighted.
function tabNavHTML(guildId, active) {
  const links = TABS.map(t => {
    // Upcoming takes priority over beta when both are set.
    const badge = t.upcoming
      ? ' <span class="soon-badge">SOON</span>'
      : (t.beta ? ' <span class="beta-badge">BETA</span>' : '');
    const ico = t.icon ? `<span class="tab-ico">${svgIcon(t.icon)}</span>` : '';
    return `<a class="menu-item${t.key === active ? ' active' : ''}" href="/guild/${esc(guildId)}/${t.key}">${ico}<span class="menu-item-label">${esc(t.label)}</span>${badge}</a>`;
  }).join('');
  const activeTab = TABS.find(t => t.key === active);
  const activeIcon = activeTab && activeTab.icon ? svgIcon(activeTab.icon) : '';
  const activeLabel = activeTab ? activeTab.label : 'Menu';
  return `
    <div class="menu-bar">
      <button class="menu-toggle" id="menu-toggle" aria-label="Open menu" aria-expanded="false">
        <span class="menu-hamburger"><span></span><span></span><span></span></span>
        <span class="menu-bar-label">${activeIcon}${esc(activeLabel)}</span>
      </button>
    </div>
    <div class="menu-backdrop" id="menu-backdrop"></div>
    <aside class="side-menu" id="side-menu" aria-hidden="true">
      <div class="side-menu-head">
        <span class="side-menu-title">Server features</span>
        <button class="side-menu-close" id="side-menu-close" aria-label="Close menu">${svgIcon('x')}</button>
      </div>
      <nav class="side-menu-nav">${links}</nav>
    </aside>`;
}

module.exports = { TABS, guildDataScript, guildHeaderHTML, tabNavHTML };
