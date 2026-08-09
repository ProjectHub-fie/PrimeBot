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

// ── Login screen ───────────────────────────────────────────────────────────

function renderLogin() {
  document.querySelector('.topnav').style.display = 'none';
  app.innerHTML = `
    <div class="login-wrap">
      <div class="login-hero">⚡</div>
      <h1 class="login-title">PrimeBot Dashboard</h1>
      <p class="login-sub">Sign in with Discord to configure PrimeBot for the servers you manage — welcome messages, leveling, prefixes, auto-reactions and more, all in one place.</p>
      <a href="/login" class="btn btn-discord">🚪 Login with Discord</a>
      <div class="feature-grid">
        <div class="feature"><div class="fi">👋</div><div class="ft">Welcome system</div><div class="fd">Custom messages, banners, DMs and channel routing.</div></div>
        <div class="feature"><div class="fi">📈</div><div class="ft">Leveling &amp; XP</div><div class="fd">Tune multipliers, cooldowns and level-up channels.</div></div>
        <div class="feature"><div class="fi">⚡</div><div class="ft">Command prefix</div><div class="fd">Set a per-server prefix instead of the default.</div></div>
        <div class="feature"><div class="fi">🔁</div><div class="ft">Auto-reactions</div><div class="fd">Trigger emojis on matching messages automatically.</div></div>
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
