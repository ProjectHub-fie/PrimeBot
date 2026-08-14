/**
 * Server-rendered guild settings page helpers.
 *
 * Each settings tab is its own HTML page at /guild/:guildId/<tab>. They share a
 * header card (guild icon + name + member count) and a tab navigation bar that
 * is a row of real links. This module renders both, plus the small JSON blob
 * (#guild-data) the per-page client scripts read to populate channel/role
 * <select>s without an extra API round-trip.
 */

const { esc, guildIconHTML } = require('./layout');

const TABS = [
  { key: 'welcome',        label: '👋 Welcome' },
  { key: 'leveling',       label: '📈 Leveling' },
  { key: 'prefix',         label: '⚡ Prefix' },
  { key: 'reactions',      label: '🔁 Auto-Reactions' },
  { key: 'reactionroles',  label: '🎭 Reaction Roles' },
  { key: 'broadcast',      label: '📢 Broadcasts' },
  { key: 'logging',        label: '📜 Logging' },
  { key: 'automod',        label: '🛡️ Automod' },
  { key: 'tickets',        label: '🎫 Tickets' },
  { key: 'events',         label: '📅 Events' },
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

function tabNavHTML(guildId, active) {
  const links = TABS.map(t =>
    `<a class="tab${t.key === active ? ' active' : ''}" href="/guild/${esc(guildId)}/${t.key}">${esc(t.label)}</a>`
  ).join('');
  return `<div class="tabs">${links}</div>`;
}

module.exports = { TABS, guildDataScript, guildHeaderHTML, tabNavHTML };
