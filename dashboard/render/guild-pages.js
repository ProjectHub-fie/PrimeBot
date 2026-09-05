/**
 * Server-rendered guild settings tab pages.
 *
 * Each tab is a real HTML page at /guild/:guildId/<tab>. They share the guild
 * header + tab nav (from render/guild.js) and embed the channel/role data blob
 * the per-page client scripts read. Settings forms are pre-populated from the
 * server-fetched config, so the page is usable before any JS runs; the JS only
 * adds interactivity (color sync, dynamic rows, save → PATCH /api).
 */

const constants = require('../constants');
const { esc, channelOptions, roleOptions, render, svgIcon } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML, TABS } = require('./guild');

const { LOG_EVENTS, AUTOMOD_RULES, AUTOMOD_ACTIONS, BADGE_CATALOG } = constants;

// Wrap guild-tab body in the shared shell (header + tabs + data blob + page JS).
function guildTab({ guild, active, panelHTML, scripts, title, user }) {
    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, active)}
    ${panelHTML}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels || [], roles: guild._roles || [] })}`;
    return render({
        title: title || `PrimeBot · ${guild.name}`,
        body,
        active: 'servers',
        scripts,
        user,
    });
}

// ── "Upcoming feature" overlay ─────────────────────────────────────────────
// A page marked `upcoming: true` (in render/guild.js TABS) is not yet released.
// The page body is blurred and a "Coming Soon......" overlay with a graphic
// covers it, so the tab stays discoverable in the sidebar but is unusable.
// Upcoming takes PRIORITY over beta: a tab with both flags shows the Coming
// Soon overlay even for beta servers (the feature simply isn't shipped yet).
const UPCOMING_SUPPORT_URL = 'https://discord.gg/gd7UNSfX86';
function upcomingOverlayWrap(innerPanelHTML, { icon = 'flask', title = 'Coming Soon' } = {}) {
    const iconHTML = svgIcon(icon);
    return `
    <div class="card upcoming-locked-card">
      <div class="upcoming-locked-wrap locked">
        ${innerPanelHTML}
      </div>
      <div class="upcoming-locked-overlay">
        <div class="upcoming-locked-box">
          <div class="upcoming-graphic" aria-hidden="true">
            <div class="upcoming-orb"></div>
            <div class="upcoming-dots"><span></span><span></span><span></span></div>
          </div>
          <div class="upcoming-icon">${iconHTML}</div>
          <div class="upcoming-title">${esc(title)}……</div>
          <div class="upcoming-text">This feature is still in the workshop. We're putting the finishing touches on it — check back soon!</div>
          <a class="btn btn-discord" href="${UPCOMING_SUPPORT_URL}" target="_blank" rel="noopener">${svgIcon('logIn')} Follow updates on Discord</a>
        </div>
      </div>
    </div>`;
}

// ── Welcome ─────────────────────────────────────────────────────────────────

function welcomePanelHTML(w, channels) {
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
        <select id="welcome-channel" data-channel-select>${channelOptions(channels, s.channelId)}</select>
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
    </div>`;
}

function welcomePage({ guild, user }) {
    return guildTab({
        guild, user, active: 'welcome',
        panelHTML: welcomePanelHTML(guild._config.welcome, guild._channels),
        scripts: ['/js/guild-common.js', '/js/settings-basic.js'],
    });
}

// ── Leveling ────────────────────────────────────────────────────────────────

function levelingPage({ guild, user }) {
    const lev = guild._config.server?.leveling || {};
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('trendingUp')}</span> Leveling &amp; XP</span></div>
      <p class="card-desc">Reward members with XP for chatting and earn badges as they level up. Role rewards now have their own <a href="/guild/${esc(guild.id)}/rolerewards">${svgIcon('gift')} Role Rewards</a> tab.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable leveling</div>
          <div class="sl-desc">Track XP and levels for members in this server.</div>
        </div>
        <label class="switch"><input type="checkbox" id="leveling-enabled" ${lev.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="leveling-channel">Level-up announcement channel</label>
        <select id="leveling-channel" data-channel-select>${channelOptions(guild._channels, lev.levelUpChannelId)}</select>
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
    </div>`;
    return guildTab({ guild, user, active: 'leveling', panelHTML, scripts: ['/js/guild-common.js', '/js/settings-basic.js'] });
}

function levelingRewardRowHTML(r = {}, roles = []) {
    const opts = (roles || []).map(role => `<option value="${esc(role.id)}"${String(role.id) === String(r.roleId) ? ' selected' : ''}>${esc(role.name)}</option>`).join('');
    return `
    <div class="reaction-row lev-reward-row">
      <label style="display:flex;align-items:center;gap:6px">Level <input type="number" class="lev-reward-level" min="1" max="200" value="${esc(r.level ?? '')}" style="width:80px" /></label>
      <select class="lev-reward-role" data-role-select data-placeholder="— Role —">${opts ? `<option value="">— Role —</option>${opts}` : '<option value="">No assignable roles</option>'}</select>
      <button class="reaction-remove lev-reward-remove" type="button">✕</button>
    </div>`;
}

// ── Badges (beta) ───────────────────────────────────────────────────────────
//
// A dedicated beta-gated page for the leveling badge system. The bot's
// LevelingManager awards level badges automatically on level-up; achievement
// and special badges are awardable here by server admins. The page shows the
// badge catalog (level / achievement / special) and a live "awarded badges"
// ledger fetched from /api/guilds/:id/badges. Non-beta servers see the
// standard locked overlay.

const BADGES_BETA_MSG = 'This server isn’t a beta server yet. Join support server to gain beta access';

function badgeCardHTML(b, { awardable = false } = {}) {
    const typeLabel = b.type === 'level'
        ? `Level ${b.level} badge`
        : (b.type === 'achievement' ? 'Achievement badge' : 'Special badge');
    const awardAttr = awardable
        ? `data-badge-id="${esc(b.id)}" data-badge-type="${esc(b.type)}"`
        : '';
    const awardBtn = awardable
        ? `<button class="btn btn-secondary btn-sm badge-award-btn" ${awardAttr}>Award to member…</button>`
        : `<span class="badge-locked-tag">Auto-awarded on level-up</span>`;
    return `
    <div class="badge-card badge-type-${esc(b.type)}">
      <div class="badge-emoji">${esc(b.emoji)}</div>
      <div class="badge-info">
        <div class="badge-name">${esc(b.name)}</div>
        <div class="badge-desc">${esc(b.description)}</div>
        <div class="badge-meta">${esc(typeLabel)}</div>
      </div>
      <div class="badge-action">${awardBtn}</div>
    </div>`;
}

function badgesPage({ guild, user }) {
    const catalog = BADGE_CATALOG || { levelBadges: [], achievementBadges: [], specialBadges: [] };
    const levelCards = (catalog.levelBadges || [])
        .map(b => badgeCardHTML({ ...b, type: 'level' }, { awardable: false })).join('');
    const achievementCards = (catalog.achievementBadges || [])
        .map(b => badgeCardHTML({ ...b, type: 'achievement' }, { awardable: true })).join('');
    const specialCards = (catalog.specialBadges || [])
        .map(b => badgeCardHTML({ ...b, type: 'special' }, { awardable: true })).join('');

    const innerPanelHTML = `
      <div class="card-title"><span><span class="icon">${svgIcon('award')}</span> Badges <span class="beta-badge">BETA</span></span></div>
      <div class="beta-banner">${svgIcon('flask')} This feature is in beta — expect changes. Please report any issues.</div>
      <p class="card-desc">Members earn level badges automatically as they level up. Server admins can award achievement and special badges to recognize community contributions.</p>

      <h3 class="badge-section-head">${svgIcon('trendingUp')} Level badges</h3>
      <p class="card-hint">Awarded automatically when a member reaches the level.</p>
      <div class="badge-grid">${levelCards || '<p class="live-empty">No level badges configured.</p>'}</div>

      <h3 class="badge-section-head">${svgIcon('userCheck')} Achievement badges</h3>
      <p class="card-hint">Award these manually to recognize members.</p>
      <div class="badge-grid">${achievementCards || '<p class="live-empty">No achievement badges configured.</p>'}</div>

      <h3 class="badge-section-head">${svgIcon('star')} Special badges</h3>
      <p class="card-hint">Rare, manually-awarded badges for exceptional members.</p>
      <div class="badge-grid">${specialCards || '<p class="live-empty">No special badges configured.</p>'}</div>

      <h3 class="badge-section-head">${svgIcon('list')} Awarded badges</h3>
      <p class="card-desc">Live ledger of badges awarded in this server. <a href="#" id="badges-refresh">Refresh</a></p>
      <div id="badges-list"><p class="live-empty">Loading…</p></div>`;

    const panelHTML = `
    <div class="card${guild._beta ? '' : ' beta-locked-card'}">
      <div class="beta-locked-wrap${guild._beta ? '' : ' locked'}">
        ${innerPanelHTML}
      </div>
      ${guild._beta ? '' : `
        <div class="beta-locked-overlay">
          <div class="beta-locked-box">
            <div class="beta-locked-icon">${svgIcon('lock')}</div>
            <div class="beta-locked-text">${esc(BADGES_BETA_MSG)}</div>
            <a class="btn btn-discord" href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener">Join support server</a>
          </div>
        </div>`}
    </div>
    <div id="badge-modal" class="modal-overlay hidden"></div>`;

    return guildTab({
        guild, user, active: 'badges', panelHTML,
        scripts: ['/js/guild-common.js', '/js/badges.js'],
    });
}

// ── Prefix / General ────────────────────────────────────────────────────────
//
// The "General" tab (top of the server features menu) hosts the command prefix
// editor and the audit log table side by side. The audit log is an
// audit trail of dashboard admin actions for this server (sl no, admin
// username, content, time) fetched from /api/guilds/:id/logs/website.

function prefixPage({ guild, user }) {
    const prefix = guild._config.server?.prefix || '$';
    const panelHTML = `
    <div class="general-grid">
      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('zap')}</span> Command prefix</span></div>
        <p class="card-desc">Set a custom prefix for text commands in this server (max 3 characters, no spaces).</p>
        <div class="field">
          <label class="field-label" for="prefix-value">Prefix</label>
          <input type="text" id="prefix-value" maxlength="3" value="${esc(prefix)}" style="max-width:120px" />
          <div class="field-hint">Members will type this before text commands, e.g. <code>${esc(prefix)}help</code></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><span><span class="icon">${svgIcon('receipt')}</span> Audit log</span></div>
        <p class="card-desc">Dashboard actions performed for this server.</p>
        <div class="wlog-wrap">
          <table class="wlog-table">
            <thead>
              <tr><th>#</th><th>Admin</th><th>Content</th><th>Time</th></tr>
            </thead>
            <tbody id="wlog-body"><tr><td colspan="4" class="wlog-empty">Loading…</td></tr></tbody>
          </table>
        </div>
        <div class="wlog-pagination" id="wlog-pagination"></div>
      </div>
    </div>`;
    return guildTab({ guild, user, active: 'prefix', panelHTML, scripts: ['/js/guild-common.js', '/js/settings-basic.js', '/js/general.js'] });
}

// ── Role Rewards (beta) ─────────────────────────────────────────────────────
//
// A dedicated beta-gated page for the leveling role-rewards editor (the same
// editor that used to live inside the Leveling page). Non-beta servers see the
// standard locked overlay so they can discover the feature but can't use it.

const ROLE_REWARDS_BETA_MSG = 'This server isn’t a beta server yet. Join support server to gain beta access';

function roleRewardsPage({ guild, user }) {
    const lev = guild._config.server?.leveling || {};
    const roleRewards = (lev.roleRewards || []).slice().sort((a, b) => a.level - b.level);
    const rewardRows = roleRewards.map(r => levelingRewardRowHTML(r, guild._roles)).join('');
    const panelHTML = `
    <div class="card${guild._beta ? '' : ' beta-locked-card'}">
      <div class="card-title"><span><span class="icon">${svgIcon('gift')}</span> Role Rewards <span class="beta-badge">BETA</span></span></div>
      <div class="beta-banner">${svgIcon('flask')} This feature is in beta — expect changes. Please report any issues.</div>
      <div class="beta-locked-wrap${guild._beta ? '' : ' locked'}">
        <p class="card-desc">Automatically grant a role when a member reaches a level. Roles are saved to the database and persist across bot restarts.</p>
        <div id="lev-rewards-list">${rewardRows}</div>
        <button class="btn btn-secondary" id="lev-reward-add" type="button">+ Add reward</button>
      </div>
      ${guild._beta ? '' : `
        <div class="beta-locked-overlay">
          <div class="beta-locked-box">
            <div class="beta-locked-icon">${svgIcon('lock')}</div>
            <div class="beta-locked-text">${esc(ROLE_REWARDS_BETA_MSG)}</div>
            <a class="btn btn-discord" href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener">Join support server</a>
          </div>
        </div>`}
    </div>`;
    return guildTab({ guild, user, active: 'rolerewards', panelHTML, scripts: ['/js/guild-common.js', '/js/settings-basic.js', '/js/leveling.js'] });
}

// ── Auto-responder ──────────────────────────────────────────────────────────
//
// Like auto-reactions, but replies with a configured text response instead of
// reacting. Each rule: { trigger, response, exactMatch }. exactMatch (the
// "Exact match" checkbox) makes the rule fire only when the message EQUALS the
// trigger; otherwise it fires on a substring (contains) match. Saved as the
// autoResponder sub-object via PATCH /api/guilds/:id/server.

function autoResponderRowHTML(r) {
    return `
    <div class="reaction-row ar-row" data-index="">
      <input type="text" class="ar-trigger" value="${esc(r.trigger || '')}" placeholder="trigger word or phrase" />
      <input type="text" class="ar-response" value="${esc(r.response || '')}" placeholder="reply text" />
      <label class="ar-exact-wrap" title="Only fire when the message exactly equals the trigger">
        <input type="checkbox" class="ar-exact" ${r.exactMatch ? 'checked' : ''}/> Exact
      </label>
      <button class="reaction-remove ar-remove" type="button">✕</button>
    </div>`;
}

function autoResponderPage({ guild, user }) {
    const ar = guild._config.server?.autoResponder || { enabled: false, responses: [] };
    const rows = (ar.responses || []).map(r => autoResponderRowHTML(r)).join('');
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('message')}</span> Auto-Responder</span></div>
      <p class="card-desc">Automatically reply with a text response when a message contains (or exactly matches) a trigger. Also configurable with <code>/autoresponder</code> or <code>$autoresponder</code>.</p>

      <div class="switch-row">
        <div class="switch-label">
          <div class="sl-title">Enable auto-responder</div>
          <div class="sl-desc">Master switch for all response rules below.</div>
        </div>
        <label class="switch"><input type="checkbox" id="ar-enabled" ${ar.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label">Response rules</label>
        <div class="reactions-list ar-list" id="ar-list">${rows}</div>
        <button class="btn btn-secondary" id="ar-add">+ Add response</button>
        <div class="field-hint">A rule fires when a message contains the trigger (unchecked) or exactly equals it (Exact checked). Replies are sent as a Discord reply to the triggering message.</div>
      </div>
    </div>`;
    return guildTab({ guild, user, active: 'autoresponder', panelHTML, scripts: ['/js/guild-common.js', '/js/autoresponder.js'] });
}

// ── Auto-reactions ──────────────────────────────────────────────────────────

function reactionRowHTML(r) {
    return `
    <div class="reaction-row" data-index="">
      <input type="text" class="r-trigger" value="${esc(r.trigger || '')}" placeholder="trigger word" />
      <input type="text" class="r-emoji" value="${esc(r.emoji || '')}" placeholder="🎉" maxlength="30" />
      <button class="reaction-remove" type="button">✕</button>
    </div>`;
}

function reactionsPage({ guild, user }) {
    const ar = guild._config.server?.autoReactions || { enabled: false, reactions: [] };
    const rows = (ar.reactions || []).map(r => reactionRowHTML(r)).join('');
    const panelHTML = `
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
    </div>`;
    return guildTab({ guild, user, active: 'reactions', panelHTML, scripts: ['/js/guild-common.js', '/js/settings-basic.js'] });
}

// ── Broadcasts ──────────────────────────────────────────────────────────────

function broadcastPage({ guild, user }) {
    const server = guild._config.server;
    const panelHTML = `
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
        <select id="broadcast-channel" data-channel-select>${channelOptions(guild._channels, server?.broadcastChannelId)}</select>
        <div class="field-hint">Where broadcast messages are posted.</div>
      </div>
    </div>`;
    return guildTab({ guild, user, active: 'broadcast', panelHTML, scripts: ['/js/guild-common.js', '/js/settings-basic.js'] });
}

// ── Birthdays ───────────────────────────────────────────────────────────────
//
// Admins can see every birthday registered in the server (sorted by next
// occurrence), add/remove entries, and configure the announcement channel,
// birthday role, and a custom image URL shown on every birthday embed. Data
// lives in the birthdays/birthdays_guilds tables (BIRTHDAY_DATABASE_URL pool);
// the bot re-reads them every ~5s so dashboard edits take effect live.

function birthdaysPage({ guild, user }) {
    const s = guild._config.birthdaySettings || { channelId: null, roleId: null, imageUrl: null };
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('cake')}</span> Birthdays</span></div>
      <p class="card-desc">Manage member birthdays and how the bot celebrates them. The bot announces each birthday in the channel below and can grant a temporary birthday role.</p>

      <div class="field">
        <label class="field-label" for="bd-channel">Announcement channel</label>
        <select id="bd-channel" data-channel-select>${channelOptions(guild._channels, s.channelId)}</select>
        <div class="field-hint">Where birthday announcements are posted.</div>
      </div>

      <div class="field">
        <label class="field-label" for="bd-role">Birthday role</label>
        <select id="bd-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles, s.roleId)}</select>
        <div class="field-hint">Granted to the member for 24 hours on their birthday.</div>
      </div>

      <div class="field">
        <label class="field-label" for="bd-image-url">Custom embed image URL</label>
        <input type="url" id="bd-image-url" value="${esc(s.imageUrl || '')}" placeholder="https://…/birthday-banner.png" />
        <div class="field-hint">Shown on <strong>every</strong> birthday celebration card <strong>and</strong> the birthday list embed, overriding the built-in images. Leave blank to use the default images.</div>
        <div id="bd-image-preview-wrap" class="bd-image-preview-wrap${s.imageUrl ? '' : ' hidden'}"><img id="bd-image-preview" src="${esc(s.imageUrl || '')}" alt="Birthday embed image preview" /></div>
      </div>

      <h3 class="badge-section-head">${svgIcon('calendar')} Registered birthdays</h3>
      <p class="card-desc">All birthdays set in this server, sorted by next occurrence. <a href="#" id="bd-refresh">Refresh</a></p>
      <div id="bd-list"><p class="live-empty">Loading…</p></div>

      <h3 class="badge-section-head">${svgIcon('userPlus')} Add a birthday</h3>
      <div class="bd-add-form">
        <input type="text" id="bd-add-userid" placeholder="Member user ID" />
        <select id="bd-add-month">
          <option value="">Month</option>
          ${['January','February','March','April','May','June','July','August','September','October','November','December'].map((m, i) => `<option value="${i + 1}">${m}</option>`).join('')}
        </select>
        <input type="number" id="bd-add-day" min="1" max="31" placeholder="Day" />
        <input type="number" id="bd-add-year" min="1900" placeholder="Year (optional)" />
        <button class="btn btn-primary" id="bd-add-btn" type="button">Add</button>
      </div>
      <div class="field-hint">Right-click a member in Discord → Copy User ID (enable Developer Mode first).</div>
    </div>`;
    return guildTab({ guild, user, active: 'birthdays', panelHTML, scripts: ['/js/guild-common.js', '/js/birthdays.js'] });
}

// ── Logging ─────────────────────────────────────────────────────────────────

function loggingPanelHTML(logging, channels) {
    const s = logging || {};
    const enabled = new Set(Array.isArray(s.events) ? s.events : []);
    const categories = [...new Set(LOG_EVENTS.map(e => e.category))];
    const eventToggles = categories.map(cat => {
        const items = LOG_EVENTS.filter(e => e.category === cat)
            .map(e => `
        <label class="switch mini">
          <input type="checkbox" class="log-event" data-event="${esc(e.key)}" ${enabled.has(e.key) ? 'checked' : ''}/>
          <span class="slider"></span>
          <span class="switch-text">${svgIcon(e.iconName)} ${esc(e.label)}</span>
        </label>`).join('');
        return `<div class="event-group"><div class="event-group-title">${esc(cat)}</div>${items}</div>`;
    }).join('');
    return `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('scroll')}</span> Server logging</span></div>
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
        <select id="logging-channel" data-channel-select>${channelOptions(channels, s.channelId)}</select>
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
    </div>`;
}

function loggingPage({ guild, user }) {
    return guildTab({
        guild, user, active: 'logging',
        panelHTML: loggingPanelHTML(guild._config.logging, guild._channels),
        scripts: ['/js/guild-common.js', '/js/settings-basic.js'],
    });
}

// ── Reaction Roles ──────────────────────────────────────────────────────────

const RR_MODES = [
    { value: 'normal', label: 'Normal — toggle on/off' },
    { value: 'sticky', label: 'Sticky — one-click assign (no toggle-off)' },
    { value: 'verify', label: 'Verify — grant once, no remove' },
    { value: 'unique', label: 'Unique — only one role at a time' },
];

function rrMappingRowHTML(m = {}) {
    const roleOpt = m.roleId ? `<option value="${esc(m.roleId)}" selected>Role</option>` : '';
    return `
    <div class="reaction-row" data-index="">
      <input type="text" class="r-emoji" value="${esc(m.emoji || '')}" placeholder="🎉 or <:name:id>" maxlength="100" />
      <select class="r-role" data-role-select data-placeholder="Role">${roleOpt}</select>
      <input type="text" class="r-label" value="${esc(m.label || '')}" placeholder="label (optional)" maxlength="100" />
      <button class="reaction-remove" type="button">✕</button>
    </div>`;
}

function rrMenuCardHTML(menu) {
    const mappings = (menu.mappings || []).map(m => {
        const e = /^\w+:\d+$/.test(m.emoji) ? `<:${m.emoji}>` : esc(m.emoji);
        return `${e} → <@&${esc(m.roleId)}>${m.label ? ' — ' + esc(m.label) : ''}`;
    }).join('<br/>');
    return `
    <div class="card rr-menu-card" data-menu="${menu.id}">
      <div class="card-title">
        <span><span class="icon">${svgIcon('smile')}</span> ${esc(menu.title || 'Untitled menu')} <span class="tag ${menu.enabled ? 'on' : 'off'}">#${menu.id}</span></span>
        <button class="btn btn-secondary btn-sm rr-delete" data-menu="${menu.id}">Delete</button>
      </div>
      <div class="rr-meta">
        <span><strong>Channel:</strong> <#${esc(menu.channelId)}></span>
        <span><strong>Message:</strong> <code>${esc(menu.messageId)}</code></span>
        <span><strong>Mode:</strong> <code>${esc(menu.mode)}</code></span>
        <span><strong>Persistent:</strong> ${menu.persistent ? '✅' : '⛔'}</span>
        <span><strong>Bot reactions:</strong> ${menu.includeBots ? '✅' : '⛔'}</span>
      </div>
      <div class="rr-mappings">${mappings || '<em>No mappings</em>'}</div>
      ${menu.requiredRoleId ? `<div class="field-hint">Requires <@&${esc(menu.requiredRoleId)}></div>` : ''}
      ${menu.exclusiveRoleId ? `<div class="field-hint">Removes <@&${esc(menu.exclusiveRoleId)}> on assign</div>` : ''}
      <button class="btn btn-secondary btn-sm rr-edit" data-menu="${menu.id}" style="margin-top:8px">Edit</button>
    </div>`;
}

function reactionRolesPage({ guild, user }) {
    const menus = guild._config.reactionRoles || [];
    const listHTML = menus.length
        ? menus.map(rrMenuCardHTML).join('')
        : `<div class="alert alert-warn">No reaction-role menus yet. Create one below.</div>`;
    const modeOpts = RR_MODES.map(m => `<option value="${m.value}">${esc(m.label)}</option>`).join('');
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('smile')}</span> Reaction Roles</span></div>
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
        <select id="rr-channel" data-channel-select>${channelOptions(guild._channels)}</select>
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
        <select id="rr-required-role" data-role-select data-placeholder="— Anyone —">${roleOptions(guild._roles)}</select>
        <div class="field-hint">Members must have this role to use the menu.</div>
      </div>

      <div class="field">
        <label class="field-label" for="rr-exclusive-role">Exclusive role (optional)</label>
        <select id="rr-exclusive-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles)}</select>
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
    </div>`;
    return guildTab({ guild, user, active: 'reactionroles', panelHTML, scripts: ['/js/guild-common.js', '/js/reactionroles.js'] });
}

// ── Tickets ─────────────────────────────────────────────────────────────────

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

function ticketRoleRowHTML(selected = {}, prefix = 'tk-support') {
    const roleOpt = selected.roleId ? `<option value="${esc(selected.roleId)}" selected>Role</option>` : '';
    return `
    <div class="reaction-row" data-index="">
      <select class="${prefix}-role" data-role-select data-placeholder="Role">${roleOpt}</select>
      <button class="reaction-remove" type="button">✕</button>
    </div>`;
}

function ticketsPage({ guild, user }) {
    const panels = guild._config.ticketPanels || [];
    const listHTML = panels.length
        ? '' // cards are rendered client-side after refresh; show a placeholder
        : `<div class="alert alert-warn">No ticket panels yet. Create one with the button below — panels can only be configured from the dashboard.</div>`;
    const styleOpts = TICKET_BUTTON_STYLES.map(s => `<option value="${s.value}">${esc(s.label)}</option>`).join('');
    const typeOpts = TICKET_MESSAGE_TYPES.map(t => `<option value="${t.value}">${esc(t.label)}</option>`).join('');
    // The editor form lives inside a modal — it only opens after clicking
    // "Create a panel" (create mode) or a panel card's "Edit" button (edit
    // mode). The page itself just lists existing panels.
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('ticket')}</span> Tickets</span></div>
      <p class="card-desc">Ticket panels are configurable <strong>only from the dashboard</strong> — slash and prefix ticket commands are disabled. Build a panel (embed or plain message, custom button, support/ping roles, claim button, per-user limits), then <strong>Send</strong> it to a channel and use <strong>Update message</strong> to re-render an existing message by id. Existing panels can be changed with <strong>Edit</strong>.</p>
      <div class="rr-list">${listHTML}</div>
      <div class="form-actions">
        <button class="btn btn-primary" id="tk-create-open">Create a panel</button>
      </div>
    </div>
    `;

        // Tickets is gated behind the "upcoming" (Coming Soon) feature gate —
    // it stays hidden/locked until the developer says to release it (TABS
    // upcoming: true). Developer/owner-role viewers bypass via _bypassUpcoming.
    const wrappedPanelHTML = guild._bypassUpcoming
        ? panelHTML
        : upcomingOverlayWrap(panelHTML, { icon: 'ticket', title: 'Tickets' });
    return guildTab({ guild, user, active: 'tickets', panelHTML: wrappedPanelHTML, scripts: ['/js/guild-common.js', '/js/tickets.js'] });
}

// ── Ticket panel full-page editor (horizontal SPA-style tabs) ─────────────
//
// Reached from:
//   - "Create a panel": the dashboard auto-creates an "Untitled-N" panel and
//     the client redirects here (/guild/:guildId/tickets/:id/edit)` so the admin
//     starts configuring immediately (there's no "edit before create" step).
//   - a panel card's "Edit" button:the same edit page.
//
// The editor is a real page (not a modal, like the old flow). It renders a
// horizontal tab bar — Panel, Buttons, Message, Permission, Logging,
// Animation, Transcript, Input — each tab holding a group of controls, SPA
// style (clicking a tab swaps the visible panel client-side, no page reload).
// The first six tabs mirror the old modal's fields; Logging + Animation are
// placeholders ("settings available soon") so the tab bar is future-proof.
//
// Quick actions (Send/Resend,, Update message,, Clone,, Rename,, Delete) live
// at the top of the page, beside the "Back to panels" link; each posts to its
// existing /api/... endpoint and refreshes the panel row client-side.

const TICKET_EDITOR_TABS = [
    { key: 'panel',       label: 'Panel',       icon: 'settings' },
    { key: 'buttons',      label: 'Buttons',      icon: 'sliders' },
    { key: 'message',      label: 'Message',      icon: 'message' },
    { key: 'permission',   label: 'Permission',   icon: 'shield' },
    { key: 'logging',       label: 'Logging',       icon: 'scroll' },
    { key: 'animation',     label: 'Animation',     icon: 'playCircle' },
    { key: 'transcript',   label: 'Transcript',   icon: 'receipt' },
    { key: 'input',         label: 'Input',         icon: 'type' },
];

function ticketField(label, forId, inner, hint = '') {
    return `
    <div class="field">
      <label class="field-label" for="${forId}">${label}</label>
      ${inner}
      ${hint ? `<div class="field-hint">${hint}</div>` : ''}
    </div>`;
}

function ticketEditorTabsHTML(panel) {
    const styleOpts = TICKET_BUTTON_STYLES.map(s => `<option value="${s.value}">${esc(s.label)}</option>`).join('');
    const typeOpts = TICKET_MESSAGE_TYPES.map(t => `<option value="${t.value}">${esc(t.label)}</option>`).join('');
    const p = panel || {};
    const cf = p.closeFlow || {};
    const val = (v, d = '') => v == null ? d : esc(String(v));
    const chk = (v) => v ? 'checked' : '';
    const roleRow = (list, cls) => {
        const ids = Array.isArray(list) && list.length ? list : [null];
        return ids.map(id => ticketRoleRowHTML(id ? { roleId: id } : {}, cls)).join('');
    };

    // Tab 1 — Panel: identity, enabled, message type, name templates.

    const panelTab = `
      ${ticketField('Panel name', 'tk-name', `<input type="text" id="tk-name" maxlength="100" value="${val(p.name, 'Support Ticket')}" placeholder="Support Ticket" />`, 'Unique per server. Shown as the ticket title and in the dashboard list.')}
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Enabled</div><div class="sl-desc">When off, the open ticket button on the panel message is disabled.</div></div>
        <label class="switch"><input type="checkbox" id="tk-enabled" ${chk(p.enabled !== false)}/><span class="slider"></span></label>
      </div>
      ${ticketField('Message type', 'tk-message-type', `<select id="tk-message-type">${typeOpts}</select>`, 'Embed (rich) or plain text. The open-ticket button is always attached.')}
      ${ticketField('Ticket category label', 'tk-category', `<input type="text" id="tk-category" maxlength="50" value="${val(p.category, 'general')}" placeholder="general" />`)}
    `;

    // Tab 2 — Buttons: open/close/claim + close-flow confirm + post-close..
    const btnRow = (keyprefix, labelText, defLabel, defEmoji, defStyle) => `
      <div class="field">
        <label class="field-label">${labelText}</label>
        <div class="reaction-row" style="display:flex;gap:6px;flex-wrap:wrap">
          <input type="text" id="${keyprefix}-label" maxlength="80" value="${val(cfButtonLabel(keyprefix, p, defLabel), defLabel)}" placeholder="${defLabel}" style="flex:2" />
          <input type="text" id="${keyprefix}-emoji" maxlength="100" value="${val(cfButtonEmoji(keyprefix, p, defEmoji), defEmoji)}" placeholder="${defEmoji}" style="flex:1" />
          <select id="${keyprefix}-style" style="flex:1">${styleOpts}</select>
        </div>
      </div>`;
    const buttonsTab = `
      <div class="card-title" style="margin-top:8px"><span>Open button</span></div>
      <p class="card-hint">The open-ticket button is edited directly on the panel embed — see the <strong>Message</strong> tab's embed builder.</p>
      <div class="card-title" style="margin-top:8px"><span>Close button</span></div>
      ${ticketField('Close button label', 'tk-close-label', `<input type="text" id="tk-close-label" maxlength="80" value="${val(p.closeButtonLabel, 'Close Ticket')}" />`)}
      ${ticketField('Close button emoji (optional)', 'tk-close-emoji', `<input type="text" id="tk-close-emoji" maxlength="100" value="${val(p.closeButtonEmoji, '🔒')}" />`)}
      ${ticketField('Close button colour', 'tk-close-style', `<select id="tk-close-style">${styleOpts}</select>`)}
      <div class="card-title" style="margin-top:8px"><span>Claim button (optional — leave blank for none)</span></div>
      ${ticketField('Claim button label', 'tk-claim-label', `<input type="text" id="tk-claim-label" maxlength="80" value="${val(p.claimButtonLabel)}" placeholder="Claim" />`)}
      ${ticketField('Claim button emoji (optional)', 'tk-claim-emoji', `<input type="text" id="tk-claim-emoji" maxlength="100" value="${val(p.claimButtonEmoji)}" placeholder="✋" />`)}
      <div class="card-title" style="margin-top:8px"><span>Close flow — Yes / No confirmation buttons</span></div>
      <p class="card-hint">When a member presses <strong>Close</strong>, a <strong>Yes / No</strong> confirmation row is shown. Customize both buttons below.</p>
      ${ticketField('Yes (confirm) button', '', `<div class="reaction-row" style="display:flex;gap:6px;flex-wrap:wrap">
          <input type="text" id="tk-cf-yes-label" maxlength="80" value="${val(cf.confirmYes?.label, 'Yes')}" placeholder="Yes" style="flex:2" />
          <input type="text" id="tk-cf-yes-emoji" maxlength="100" value="${val(cf.confirmYes?.emoji, '✅')}" placeholder="✅" style="flex:1" />
          <select id="tk-cf-yes-style" style="flex:1">${styleOpts}</select>
        </div>`)}
      ${ticketField('No (cancel) button', '', `<div class="reaction-row" style="display:flex;gap:6px;flex-wrap:wrap">
          <input type="text" id="tk-cf-no-label" maxlength="80" value="${val(cf.confirmNo?.label, 'No')}" placeholder="No" style="flex:2" />
          <input type="text" id="tk-cf-no-emoji" maxlength="100" value="${val(cf.confirmNo?.emoji, '✖️')}" placeholder="✖️" style="flex:1" />
          <select id="tk-cf-no-style" style="flex:1">${styleOpts}</select>
        </div>`)}
      <div class="card-title" style="margin-top:8px"><span>Post-close buttons (Transcript / Reopen / Delete)</span></div>
      <p class="card-hint">Revealed after the ticket is closed (next to the close embed). Every button label/emoji/colour is editable below.</p>
      ${['transcript', 'reopen', 'delete'].map((key, i) => {
          const labels = { transcript: 'Transcript', reopen: 'Reopen', delete: 'Delete' };
          const emojis = { transcript: '📝', reopen: '🔓', delete: '🗑️' };
          const b = cf.buttons?.[key] || {};
          return ticketField(`${labels[key]} button`, '', `<div class="reaction-row" style="display:flex;gap:6px;flex-wrap:wrap">
            <input type="text" id="tk-cf-btn-${key}-label" maxlength="80" value="${val(b.label, labels[key])}" placeholder="${labels[key]}" style="flex:2" />
            <input type="text" id="tk-cf-btn-${key}-emoji" maxlength="100" value="${val(b.emoji, emojis[key])}" placeholder="${emojis[key]}" style="flex:1" />
            <select id="tk-cf-btn-${key}-style" style="flex:1">${styleOpts}</select>
          </div>`);
      }).join('')}
    `;

    // Tab 3 — Message: panel embed builder (fields live on the embed.,
    // Ticket Tool "Panel Embed Settings" style) + in-ticket welcome message +
    // close embed along the bottom.
    const messageTab = `
      <div class="card-title"><span>Panel embed</span></div>
      <p class="card-hint">Edit the panel message directly on the embed — each embed region holds its own field(s), Ticket Tool style. Type and the builder updates the live Discord render inline.</p>
      ${ticketEmbedBuilderHTML(p, styleOpts)}
      <div class="card-title" style="margin-top:14px"><span>In-ticket messages</span></div>
      <p class="card-hint">Shown inside a ticket once opened (not on the panel message).</p>
      ${ticketField('In-ticket welcome message', 'tk-welcome', `<textarea id="tk-welcome" placeholder="Welcome to your support ticket! Please describe your issue.">${val(p.welcomeMessage)}</textarea>`)}
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Show a close embed</div><div class="sl-desc">Optional red embed shown after the ticket is closed (before the action buttons).</div></div>
        <label class="switch"><input type="checkbox" id="tk-cf-embed-enabled" ${chk(cf.closeEmbed?.enabled)}/><span class="slider"></span></label>
      </div>
      ${ticketField('Close embed title', 'tk-cf-embed-title', `<input type="text" id="tk-cf-embed-title" maxlength="255" value="${val(cf.closeEmbed?.title, '🔒 Ticket Closed')}" />`)}
      ${ticketField('Close embed description', 'tk-cf-embed-desc', `<textarea id="tk-cf-embed-desc" placeholder="This ticket was closed by {moderator} at {time}.">${val(cf.closeEmbed?.description)}</textarea>`, 'Placeholders: {time} {timestamp} {author} {moderator} {panel} {reason}. {timestamp} renders as a Discord relative-time tag.')}
      ${ticketField('Close embed footer text', 'tk-cf-embed-footer', `<input type="text" id="tk-cf-embed-footer" maxlength="255" value="${val(cf.closeEmbed?.footer, '{panel} · PrimeBot')}" />`)}
      ${ticketField('Close embed colour (default red)', '', `<div class="color-field">
          <input type="color" id="tk-cf-embed-color" value="${val(cf.closeEmbed?.color, '#ED4245')}" />
          <input type="text" id="tk-cf-embed-color-text" value="${val(cf.closeEmbed?.color, '#ED4245')}" style="flex:1" />
        </div>`)}
    `;

    // Tab 4 — Permission: support/ping roles, per-user limit, reason.,
    const permissionTab = `
      <div class="field">
        <label class="field-label">Support roles (can see tickets)</label>
        <div class="reactions-list" id="tk-support-list">${roleRow(p.supportRoleIds, 'tk-support')}</div>
        <button class="btn btn-secondary" id="tk-support-add">+ Add role</button>
      </div>
      <div class="field">
        <label class="field-label">Ping roles (mentioned on open)</label>
        <div class="reactions-list" id="tk-ping-list">${roleRow(p.pingRoleIds, 'tk-ping')}</div>
        <button class="btn btn-secondary" id="tk-ping-add">+ Add role</button>
      </div>
      ${ticketField('Max open tickets per user', 'tk-max-open', `<input type="number" id="tk-max-open" min="0" value="${val(p.maxOpenPerUser, '1')}" />`)}
      ${ticketField('Ticket category ID (Discord channel category, optional)', 'tk-ticket-category-id', `<input type="text" id="tk-ticket-category-id" value="${val(p.ticketCategoryId)}" placeholder="123456789012345678" />`, 'Created ticket channels open under this category. Leave blank to use the current channel / threads.')}
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Ask for reason on open</div><div class="sl-desc">Prompt the member for a reason (captured on the ticket).</div></div>
        <label class="switch"><input type="checkbox" id="tk-ask-reason" ${chk(p.askReason)}/><span class="slider"></span></label
      </div>
    `;

    // Tab 5 — Logging + Tab  ��� Animation.: placeholder "available soon".
    const comingSoonTab = (title) => `
      <div class="card-title"><span>${title}</span></div>
      <div class="alert alert-warn">${title} settings are coming soon. More bar tabs will be available here. Settings will be available soon.</div>
    `;
    const loggingTab = comingSoonTab('Logging');
    const animationTab = comingSoonTab('Animation');

    // Tab 7 — Transcript: transcript channel + toggles.

    const transcriptTab = `
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Save transcripts to a channel</div><div class="sl-desc">Optional. When the Transcript button is pressed, the ticket's messages are saved to this channel.</div></div>
        <label class="switch"><input type="checkbox" id="tk-cf-transcript-enabled" ${chk(cf.transcript?.enabled)}/><span class="slider"></span></label>
      </div>
      ${ticketField('Transcript channel ID', 'tk-cf-transcript-channel', `<input type="text" id="tk-cf-transcript-channel" value="${val(cf.transcript?.channelId)}" placeholder="123456789012345678" />`, 'Dashboard-only. The channel PrimeBot posts ticket transcripts to.')}
    `;

    // Tab 8 — Input: channel-name templates (open/claimed/closed) + ticket name.

    const inputTab = `
      ${ticketField('Ticket channel name (optional)', 'tk-ticket-name', `<input type="text" id="tk-ticket-name" maxlength="100" value="${val(p.ticketName)}" placeholder="Defaults to ticket-username" />`)}
      ${ticketField('Channel name when OPEN', 'tk-open-name', `<input type="text" id="tk-open-name" maxlength="100" value="${val(p.openNameTemplate)}" placeholder="(open) {name}" />`, 'Template applied when a ticket opens/reopens. Placeholders: {name} (ticket name or username), {username}, {id}, {panel}. Blank = no rename.')}
      ${ticketField('Channel name when CLAIMED', 'tk-claimed-name', `<input type="text" id="tk-claimed-name" maxlength="100" value="${val(p.claimedNameTemplate)}" placeholder="(solved) {name}" />`, 'Template applied when support claims the ticket. Same placeholders. Blank = no rename.')}
      ${ticketField('Channel name when CLOSED', 'tk-closed-name', `<input type="text" id="tk-closed-name" maxlength="100" value="${val(p.closedNameTemplate)}" placeholder="(closed) {name}" />`, 'Template applied when the ticket is closed. Same placeholders. Blank = no rename.')}
    `;

    const tabPanels = [
        { key: 'panel',       html: panelTab },
        { key: 'buttons',      html: buttonsTab },
        { key: 'message',      html: messageTab },
        { key: 'permission',   html: permissionTab },
        { key: 'logging',       html: loggingTab },
        { key: 'animation',     html: animationTab },
        { key: 'transcript',   html: transcriptTab },
        { key: 'input',         html: inputTab },
    ];

    const tabBar = `
    <div class="tk-editor-tabs" role="tablist">
      ${TICKET_EDITOR_TABS.map((t, i) => `
        <button type="button" class="tk-editor-tab${i === 0 ? ' active' : ''}" data-tab="${t.key}" role="tab" aria-selected="${i === 0 ? 'true' : 'false'}">
          ${svgIcon(t.icon)}<span>${esc(t.label)}</span>
        </button>`).join('')}
    </div>`;
    const tabContent = tabPanels.map((t, i) => `
      <section class="tab-panel${i === 0 ? ' active' : ''}" data-tab-panel="${t.key}">${t.html}</section>
    `).join('');

    return { tabBar, tabContent };
}

// Helper shortcuts for close-flow button defaults (server render).
function cfButtonLabel(key, panel, fallback) {
    const cf = (panel && panel.closeFlow) || {};
    if (key === 'transcript' || key === 'reopen' || key === 'delete') {
        const b = cf.buttons?.[key];
        if (b) return b.label || fallback;
        return fallback;
    }
    return fallback;
}
function cfButtonEmoji(key, panel, fallback) {
    const cf = (panel && panel.closeFlow) || {};
    if (key === 'transcript' || key === 'reopen' || key === 'delete') {
        const b = cf.buttons?.[key];
        if (b) return b.emoji || fallback;
        return fallback;
;
    }
    return fallback;
;
}

// ℹ️ Embed-builder markup — Ticket Tool "Panel Embed Settings" pattern.
// The panel embed's editing fields live ON the embed itself: each embed region
// (content, author, title, description, thumbnail, image, footer, color,
// open button) has its field label + input control(s) attached to that region, with a
// tiny Discord-styled live render of the region right below the input — so the editor
// "shows as the embed" instead of a detached live-preview pane. Mirrored by the
// client renderer in ticket-editor.js (renderTicketPreview), which updates only the
// live output nodes on input (preserving the input focus — inputs are never rebuilt).
function ticketEmbedBuilderHTML(p = {}, styleOpts) {
    const esca = (v, d = '') => v == null ? d : esc(String(v));
    const color = /^#[0-9a-fA-F]{6}$/.test(p.color || '') ? p.color : '#5865F2';
    const styleClass = (p.buttonStyle || 'Primary').toLowerCase();
    const btnEmoji = p.buttonEmoji ? `<span class="edb-btn-emoji">${esc(p.buttonEmoji)}</span>` : '';
    const authorIcon = p.authorIconUrl
        ? `<img id="edb-author-icon" class="edb-author-icon" src="${esc(p.authorIconUrl)}" alt="" />`
        : `<img id="edb-author-icon" class="edb-author-icon hidden" alt="" />`;
    const thumbHTML = p.thumbnailUrl
        ? `<img id="edb-thumb" class="edb-thumb" src="${esc(p.thumbnailUrl)}" alt="" />`
        : `<img id="edb-thumb" class="edb-thumb hidden" alt="" />`;
    const imageHTML = p.imageUrl
        ? `<img id="edb-image" class="edb-image" src="${esc(p.imageUrl)}" alt="" />`
        : `<img id="edb-image" class="edb-image hidden" alt="" />`;
    return `
    <div class="tk-embed-builder">
      <div class="edb-region edb-content">
        <div class="edb-field-head"><label class="edb-label" for="tk-content">Content (above the embed / plain body)</label></div>
        <textarea id="tk-content" placeholder="Optional: @support or any text shown above the embed / as the plain body.">${esca(p.content)}</textarea>
        <div class="edb-live edb-live-content" id="edb-content">${esca(p.content)}</div>
      </div>
      <div class="tk-preview-embed edb-preview-embed">
        <div class="tk-preview-embed-bar edb-region-color" id="edb-bar" style="background:${esc(color)}">
          <div class="edb-field-head"><label class="edb-label" for="tk-color">Embed color</label></div>
          <div class="color-field edb-color-fields">
            <input type="color" id="tk-color" value="${esc(color)}" />
            <input type="text" id="tk-color-text" value="${esc(color)}" style="flex:1" />
          </div>
        </div>
        <div class="tk-preview-embed-body">
          <div class="edb-region edb-author">
            <div class="edb-field-head"><label class="edb-label">Author</label></div>
            <div class="edb-duo">
              <input type="text" id="tk-author-name" maxlength="255" value="${esca(p.authorName)}" placeholder="Author name — e.g. the support team" />
              <input type="text" id="tk-author-icon" value="${esca(p.authorIconUrl)}" placeholder="Author icon URL" />
            </div>
            <div class="edb-live edb-live-author" id="edb-author">${authorIcon}<span id="edb-author-name">${esca(p.authorName)}</span></div>
          </div>
          <div class="edb-region edb-title">
            <div class="edb-field-head"><label class="edb-label" for="tk-title">Title</label></div>
            <input type="text" id="tk-title" maxlength="255" value="${esca(p.title)}" placeholder="🎫 Support Tickets" />
            <div class="edb-live edb-live-title" id="edb-title">${esca(p.title)}</div>
          </div>
          <div class="edb-region edb-desc">
            <div class="edb-field-head"><label class="edb-label" for="tk-description">Embed Text</label></div>
            <textarea id="tk-description" placeholder="Click the button below to open a support ticket.">${esca(p.description)}</textarea>
            <div class="edb-live edb-live-desc" id="edb-desc">${esca(p.description)}</div>
          </div>
          <div class="edb-region edb-thumb">
            <div class="edb-field-head"><label class="edb-label" for="tk-thumbnail">Thumbnail image URL</label></div>
            <input type="text" id="tk-thumbnail" value="${esca(p.thumbnailUrl)}" placeholder="https://…/icon.png" />
            <div class="edb-live edb-live-thumb">${thumbHTML}</div>
          </div>
          <div class="edb-region edb-image">
            <div class="edb-field-head"><label class="edb-label" for="tk-image">Large image URL</label></div>
            <input type="text" id="tk-image" value="${esca(p.imageUrl)}" placeholder="https://…/banner.png" />
            <div class="edb-live edb-live-image">${imageHTML}</div>
          </div>
          <div class="edb-region edb-footer">
            <div class="edb-field-head"><label class="edb-label" for="tk-footer">Embed footer text</label></div>
            <input type="text" id="tk-footer" maxlength="255" value="${esca(p.footerText)}" placeholder="PrimeBot · Tickets" />
            <div class="edb-live edb-live-footer" id="edb-footer"><span class="tk-preview-embed-footer-text">${esca(p.footerText)}</span><span class="tk-preview-embed-time">now</span></div>
          </div>
        </div>
      </div>
      <div class="edb-region edb-button">
        <div class="edb-field-head"><label class="edb-label">Open ticket button</label></div>
        <div class="edb-triple">
          <input type="text" id="tk-button-label" maxlength="80" value="${esca(p.buttonLabel, 'Open Ticket')}" placeholder="Open Ticket" />
          <input type="text" id="tk-button-emoji" maxlength="100" value="${esca(p.buttonEmoji)}" placeholder="🎫" />
          <select id="tk-button-style">${styleOpts}</select>
        </div>
        <div class="edb-live edb-live-button">
          <div class="tk-preview-button tk-preview-button-${esc(styleClass)}" id="edb-button">${btnEmoji}<span id="edb-button-label">${esca(p.buttonLabel, 'Open Ticket')}</span></div>
        </div>
      </div>
    </div>`;
}

function ticketEditPage({ guild, user }) {
    const panel = guild._ticketPanel;
    const { tabBar, tabContent } = ticketEditorTabsHTML(panel);
    const id = panel.id;
    const pageHTML = `
    <div class="ticket-editor-top">
      <a class="btn btn-secondary btn-sm" href="/guild/${esc(guild.id)}/tickets">← Back to panels</a>
      <div class="ticket-editor-actions">
        <button class="btn btn-secondary btn-sm tk-send" data-panel="${id}">Send / Resend</button>
        <button class="btn btn-secondary btn-sm tk-update" data-panel="${id}">Update message</button>
        <button class="btn btn-secondary btn-sm tk-clone" data-panel="${id}">Clone</button>
        <button class="btn btn-secondary btn-sm tk-rename" data-panel="${id}">Rename</button>
        <button class="btn btn-secondary btn-sm tk-delete" data-panel="${id}">Delete</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('ticket')}</span> ${esc(panel.name || 'Support Ticket')} <span class="tag ${panel.enabled ? 'on' : 'off'}">#${id}</span></span></div>
      <p class="card-desc">Editing ticket panel — the <strong>Message</strong> tab is an embed builder where each embed region holds its own editing fields (Ticket Tool style). Every tab saves with the <strong>Save changes</strong> bar.</p>
      ${tabBar}
      <div class="tk-editor-panels">${tabContent}</div>
    </div>`;
    return guildTab({ guild, user, active: 'tickets', panelHTML: pageHTML, scripts: ['/js/guild-common.js', '/js/ticket-editor.js'] });
}

// ── Automod ─────────────────────────────────────────────────────────────────

function automodPage({ guild, user }) {
    const s = guild._config.automod || {};
    const rules = Array.isArray(s.rules) ? s.rules : [];
    // Render existing rule rows server-side.
    const warnActions = AUTOMOD_ACTIONS.filter(a => ['warn', 'timeout', 'kick', 'ban'].includes(a.key));
    const dmKeys = ['delete', 'warn', 'timeout', 'kick', 'ban', 'escalation'];
    const dmMessages = s.dmMessages || {};
    const ruleRows = rules.map(rule => {
        const meta = AUTOMOD_RULES.find(r => r.key === rule.type) || AUTOMOD_RULES[0];
        const selected = Array.isArray(rule.actions) && rule.actions.length ? rule.actions : (rule.action ? [rule.action] : ['delete']);
        const actionChecks = AUTOMOD_ACTIONS.map(a =>
            `<label class="switch mini am-action-label"><input type="checkbox" class="am-action" value="${a.key}" ${selected.includes(a.key) ? 'checked' : ''}/><span class="switch-text">${svgIcon(a.iconName)} ${esc(a.label)}</span></label>`
        ).join('');
        let extra = '';
        if (meta.params.includes('words')) extra = `<input type="text" class="am-words" value="${esc((rule.words || []).join(', '))}" placeholder="extra domains/terms (comma-separated)" />`;
        if (meta.params.includes('threshold')) extra += `<input type="number" class="am-threshold" value="${rule.threshold ?? ''}" placeholder="threshold" min="1" style="width:96px" />`;
        if (meta.params.includes('seconds')) extra += `<input type="number" class="am-seconds" value="${rule.seconds ?? ''}" placeholder="seconds" min="1" max="3600" style="width:96px" />`;
        return `
      <div class="reaction-row am-rule-row" data-type="${esc(meta.key)}">
        <label class="switch mini"><input type="checkbox" class="am-enabled" ${rule.enabled !== false ? 'checked' : ''}/><span class="slider"></span></label>
        <span class="am-rule-label">${svgIcon(meta.iconName)} ${esc(meta.label)}</span>
        <div class="am-actions-group">${actionChecks}</div>
        ${extra}
        <button class="reaction-remove am-remove" type="button">${svgIcon('x')}</button>
      </div>`;
    }).join('');
    const addTypeOpts = AUTOMOD_RULES.map(r => `<option value="${r.key}">${svgIcon(r.iconName, 'am-opt-ico')} ${esc(r.label)}</option>`).join('');
    const warnActionChecks = warnActions.map(a =>
        `<label class="switch mini am-action-label"><input type="checkbox" class="am-warn-action" value="${a.key}" ${(s.warnActions || [s.warnAction || 'timeout']).includes(a.key) ? 'checked' : ''}/><span class="switch-text">${svgIcon(a.iconName)} ${esc(a.label)}</span></label>`
    ).join('');
    const dmRows = dmKeys.map(k => {
        const a = AUTOMOD_ACTIONS.find(x => x.key === k);
        const label = a ? `${svgIcon(a.iconName)} ${a.label}` : (k === 'escalation' ? `${svgIcon('octagonX')} Escalation` : k);
        return `<div class="field-row"><label class="field-label" style="min-width:120px">${label}</label><input type="text" class="am-dm-message" data-key="${k}" value="${esc(dmMessages[k] || '')}" placeholder="(use default)" style="flex:1"/></div>`;
    }).join('');

    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('shield')}</span> Premium Automod</span></div>
      <p class="card-desc">Automatic moderation that scans every message against your rules. Premium features for free: blocked words, invite/bad-link/NSFW filtering, spam &amp; mass-mention detection, caps/emoji/repeated-char/new-account filters, multi-action punishment, DM notifications, warning escalation, and appeals.</p>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Enable Automod</div><div class="sl-desc">Master switch. When off, no messages are scanned.</div></div>
        <label class="switch"><input type="checkbox" id="am-enabled" ${s.enabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label" for="am-log-channel">Automod log channel (optional)</label>
        <select id="am-log-channel" data-channel-select>${channelOptions(guild._channels, s.logChannelId)}</select>
        <div class="field-hint">Where automod actions are posted as the bot.</div>
      </div>

      <div class="field">
        <label class="field-label" for="am-mute-role">Mute role (optional)</label>
        <select id="am-mute-role" data-role-select data-placeholder="— None (use timeouts) —">${roleOptions(guild._roles, s.muteRoleId)}</select>
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
          <button class="btn btn-secondary" id="am-add-rule">${svgIcon('plus')} Add rule</button>
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

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">DM user</div><div class="sl-desc">Send the banned member a rich ban direct message with all available fields when they are banned.</div></div>
        <label class="switch"><input type="checkbox" id="am-dm-user" ${s.dmUser !== false ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Use appeal</div><div class="sl-desc">Attach an "Appeal ban" button to the ban DM so members can file an appeal from a floating Discord form.</div></div>
        <label class="switch"><input type="checkbox" id="am-use-appeal" ${s.useAppeal === true ? 'checked' : ''}/><span class="slider"></span></label>
      </div>

      <div class="field">
        <label class="field-label">Custom DM messages (optional)</label>
        <div class="field-hint">Override the default message sent for each action. Placeholders: {server}, {reason}, {action}, {threshold}. Leave blank to use the default.</div>
        <div class="field-rows" id="am-dm-messages">${dmRows}</div>
      </div>

      <div class="field">
        <label class="field-label" for="am-appeal-channel">Appeal channel (optional)</label>
        <select id="am-appeal-channel" data-channel-select>${channelOptions(guild._channels, s.appealChannelId)}</select>
        <div class="field-hint">New appeals filed via <code>/appeal</code> or the ban-DM form are posted here for moderators to review. If left unset, appeals fall back to the automod log channel (and you can set it anytime with <code>$appealchannel #channel</code> or <code>/automod set appeal_channel</code>).</div>
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
    </div>`;

    // Embed the automod settings + rule/action catalogs so the client script
    // can render exempt lists and add-rule rows without an extra fetch.
    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'automod')}
    ${panelHTML}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: { _automodSettings: s } })}
    <script>window.__AUTOMOD_RULES=${JSON.stringify(AUTOMOD_RULES)};window.__AUTOMOD_ACTIONS=${JSON.stringify(AUTOMOD_ACTIONS)};window.__AUTOMOD_SETTINGS=${JSON.stringify(s)};</script>`;
    return render({ title: `PrimeBot · ${guild.name} · Automod`, body, active: 'servers', scripts: ['/js/guild-common.js', '/js/automod.js'], user });
}

// ── Events ──────────────────────────────────────────────────────────────────
//
// Event Management is marked `upcoming: true` in render/guild.js TABS, so the
// page renders the "Coming Soon......" overlay for ALL servers (upcoming takes
// priority over beta). The underlying editor markup is kept (blurred) so the
// tab remains discoverable and the feature can be re-enabled by flipping the
// `upcoming` flag off — no markup rewrite needed when it ships.

function eventsPage({ guild, user }) {
    const innerPanelHTML = `
      <div class="card-title"><span><span class="icon">${svgIcon('calendar')}</span> Event Management <span class="soon-badge">SOON</span></span></div>
      <p>Schedule an event with a countdown and a list of timed tasks. The bot will lock/unlock or hide/unhide the channel(s) you choose (pick one, or hold Ctrl/Cmd to select several), add/remove roles, or send a text/embed message at the offsets you set (seconds from the event start).</p>
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
      <div id="ev-list"><p class="live-empty">Loading…</p></div>`;
    // Developer/owner-role viewers bypass the upcoming gate: render the real
    // editor (no "Coming Soon" overlay) so the feature can be exercised.
    const panelHTML = guild._bypassUpcoming
        ? innerPanelHTML
        : upcomingOverlayWrap(innerPanelHTML, { icon: 'calendar', title: 'Event Management' });
    return guildTab({ guild, user, active: 'events', panelHTML, scripts: ['/js/guild-common.js', '/js/events.js'] });
}

// ── Live Polls / Live Giveaways (per-server) ─────────────────────────────────
//
// Live polls & giveaways are inherently cross-server (joined via pass code from
// any server), so these tabs show the items CREATED in this server, plus a link
// to the global cross-server Live pages. The client (guild-live.js) fetches
// /api/guilds/:guildId/live/polls|giveaways and reuses the live-card markup.

function livePollsPage({ guild, user }) {
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('barChart')}</span> Live Polls</span><button class="btn btn-secondary live-refresh-btn" id="live-refresh">${svgIcon("refresh")} Refresh</button></div>
      <p class="card-desc">Live polls created in <strong>${esc(guild.name)}</strong> — running and recently ended. Live polls are cross-server: anyone can join with the pass code from any server where PrimeBot is present.</p>
      <p class="card-hint">Create one in Discord with <code>$lpoll</code>. See <a href="/live/polls">all live polls across PrimeBot →</a></p>
      <div id="live-content"><p class="live-empty">Loading live polls…</p></div>
    </div>
    <div id="live-join-modal" class="modal-overlay hidden"></div>`;
    return guildTab({
        guild, user, active: 'live/polls',
        panelHTML,
        scripts: ['/js/guild-common.js', '/js/guild-live.js'],
    });
}

function liveGiveawaysPage({ guild, user }) {
    const panelHTML = `
    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('gift')}</span> Live Giveaways</span><button class="btn btn-secondary live-refresh-btn" id="live-refresh">${svgIcon("refresh")} Refresh</button></div>
      <p class="card-desc">Live giveaways created in <strong>${esc(guild.name)}</strong> — running and recently ended. Live giveaways are cross-server: anyone can join with the pass code from any server where PrimeBot is present.</p>
      <p class="card-hint">Create one in Discord with <code>$lgiveway</code>. See <a href="/live/giveaways">all live giveaways across PrimeBot →</a></p>
      <div id="live-content"><p class="live-empty">Loading live giveaways…</p></div>
    </div>
    <div id="live-join-modal" class="modal-overlay hidden"></div>`;
    return guildTab({
        guild, user, active: 'live/giveaways',
        panelHTML,
        scripts: ['/js/guild-common.js', '/js/guild-live.js'],
    });
}

module.exports = {
    welcomePage, levelingPage, badgesPage, prefixPage, roleRewardsPage, autoResponderPage, reactionsPage, broadcastPage,
    birthdaysPage, loggingPage, reactionRolesPage, ticketsPage, ticketEditPage, automodPage, eventsPage,
    livePollsPage, liveGiveawaysPage,
    TABS,
};
