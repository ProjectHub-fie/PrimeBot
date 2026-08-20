/**
 * Server-rendered pages: login, docs, live, overview, and the 404 fallback.
 * Each exports a function returning the full HTML string (via layout.render).
 */

const constants = require('../constants');
const commandDocs = require('../commandDocs');
const { esc, guildIconHTML, render, svgIcon } = require('./layout');
const { LOG_EVENTS } = constants;

// ── Login ──────────────────────────────────────────────────────────────────

const LOGIN_ERRORS = {
    missing_code: 'Authorization code was missing from the Discord callback.',
    auth_failed: 'Discord sign-in failed. Please try again.',
    session_failed: 'Signed in to Discord, but the server could not save your session. This usually means the database connection is failing on Vercel (check DATABASE_URL / SSL and that the primebot_dashboard_session table is reachable).',
    idle_timeout: 'You were logged out automatically because the dashboard tab was inactive for a while. Sign in again to continue.',
};

function loginPage({ errorKey } = {}) {
    const errorMsg = errorKey && LOGIN_ERRORS[errorKey];
    const errorHTML = errorMsg
        ? `<div class="alert alert-error" style="margin:0 0 16px;text-align:left">${esc(errorMsg)}</div>`
        : '';
    const body = `
    <div class="login-wrap">
      <div class="login-hero">${svgIcon('zap')}</div>
      <h1 class="login-title">PrimeBot Dashboard</h1>
      <h3>Premium features in free </h3>
      ${errorHTML}
      <p class="login-sub">Sign in with Discord to configure PrimeBot for the servers you manage — welcome messages, leveling, prefixes, auto-reactions and more, all in one place.</p>
      <div class="login-actions">
        <a href="/auth/discord" class="btn btn-discord">${svgIcon('logIn')} Login with Discord</a>
        <a href="${esc(constants.BOT_INVITE_URL)}" class="btn btn-secondary" target="_blank" rel="noopener">${svgIcon('plus')} Invite PrimeBot</a>
      </div>
      <a href="/docs" class="btn btn-secondary">${svgIcon('book')} Documentation</a>
      <p class="login-legal">By signing in you agree to the <a href="/terms">Terms of Service</a> and <a href="/privacy">Privacy Policy</a>.</p>

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
            <div class="donut-item"><div class="donut" id="donut-leveling"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('trendingUp')} Leveling</div></div>
            <div class="donut-item"><div class="donut" id="donut-welcome"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('hand')} Welcome</div></div>
            <div class="donut-item"><div class="donut" id="donut-reactions"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('repeat')} Auto-reactions</div></div>
            <div class="donut-item"><div class="donut" id="donut-broadcasts"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('megaphone')} Broadcasts</div></div>
            <div class="donut-item"><div class="donut" id="donut-automod"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('shield')} Automod</div></div>
            <div class="donut-item"><div class="donut" id="donut-tickets"><span class="donut-pct">0%</span></div><div class="donut-label">${svgIcon('ticket')} Tickets</div></div>
          </div>
        </div>
      </div>

      <div class="feature-grid">
        <div class="feature"><div class="fi">${svgIcon('hand')}</div><div class="ft">Welcome system</div><div class="fd">Custom messages, banners, DMs and channel routing.</div></div>
        <div class="feature"><div class="fi">${svgIcon('trendingUp')}</div><div class="ft">Leveling &amp; XP</div><div class="fd">Tune multipliers, cooldowns and level-up channels.</div></div>
        <div class="feature"><div class="fi">${svgIcon('zap')}</div><div class="ft">Command prefix</div><div class="fd">Set a per-server prefix instead of the default.</div></div>
        <div class="feature"><div class="fi">${svgIcon('repeat')}</div><div class="ft">Auto-reactions</div><div class="fd">Trigger emojis on matching messages automatically.</div></div>
        <div class="feature"><div class="fi">${svgIcon('shield')}</div><div class="ft">Premium Automod</div><div class="fd">Auto-mod with warnings, escalation, spam &amp; word filters — free.</div></div>
      </div>
    </div>`;
    return render({ title: 'PrimeBot Dashboard — Login', body, login: true, scripts: ['/js/login.js'] });
}

// ── Docs ───────────────────────────────────────────────────────────────────

function docCommandCard(prefix, cmd) {
    const chips = [];
    if (cmd.permission) chips.push(`<span class="doc-chip doc-chip-perm">${esc(cmd.permission)}</span>`);
    if (cmd.note) chips.push(`<span class="doc-chip doc-chip-note">${esc(cmd.note)}</span>`);
    const aliases = cmd.aliases.slice(1);
    const aliasHTML = aliases.length
        ? `<div class="doc-cmd-aliases">Also: ${aliases.map((a) => `<code>${esc(prefix)}${esc(a)}</code>`).join(' ')}</div>`
        : '';
    const usageHTML = cmd.usage.length
        ? `<div class="doc-cmd-usage">${cmd.usage.map((u) => `<code>${esc(prefix)}${esc(u)}</code>`).join('')}</div>`
        : '';
    const search = [
        cmd.name, ...cmd.aliases, cmd.category, cmd.description,
        cmd.permission || '', cmd.note || '', ...cmd.usage.map((u) => `${prefix}${u}`), ...cmd.usage,
    ].join(' ').toLowerCase();
    return `<article class="doc-cmd" id="cmd-${esc(cmd.name)}" data-category="${esc(cmd.category.toLowerCase())}" data-search="${esc(search)}">
      <div class="doc-cmd-head">
        <span class="doc-cmd-icon">${svgIcon(cmd.icon)}</span>
        <h3 class="doc-cmd-name"><code>${esc(prefix)}${esc(cmd.name)}</code></h3>
        <span class="doc-cmd-chips">${chips.join('')}</span>
      </div>
      <p class="doc-cmd-desc">${esc(cmd.description)}</p>
      ${aliasHTML}
      ${usageHTML}
    </article>`;
}

function docsPage({ clientId, user } = {}) {
    const { commands, categories } = commandDocs.buildCommandDocs();
    const prefix = '$'; // default server prefix for usage examples

    const sections = categories
        .map((cat) => {
            const cmds = commands.filter((c) => c.category === cat.name);
            if (!cmds.length) return '';
            return `<section class="doc-cat" data-category="${esc(cat.name.toLowerCase())}">
      <div class="doc-cat-head">
        <span class="doc-cat-icon">${svgIcon(cat.icon)}</span>
        <h2>${esc(cat.name)}</h2>
        <span class="doc-cat-count">${cmds.length} command${cmds.length === 1 ? '' : 's'}</span>
      </div>
      <div class="doc-cmd-grid">
        ${cmds.map((cmd) => docCommandCard(prefix, cmd)).join('\n        ')}
      </div>
    </section>`;
        })
        .filter(Boolean)
        .join('\n      ');

    // Public (logged-out) visitors render the no-nav login shell, so the top
    // nav's back button never appears (login: !user below). Render an in-body
    // back button for them; logged-in users already get the nav's back button.
    const backBtn = user ? '' : `<a href="javascript:history.back()" class="back-btn docs-back" aria-label="Go back to previous page" title="Go back to previous page">${svgIcon('arrowLeft', 'back-symbol')}</a>`;

    const body = `
    <div class="docs docs-commands-layout">
      <div class="docs-hero">
        ${backBtn}
        <div class="docs-hero-icon">${svgIcon('book')}</div>
        <h1 class="docs-title">Command documentation</h1>
        <p class="docs-lead">Every prefix command PrimeBot understands, auto-generated from the bot's command handler. Commands run with your server's prefix (default <code>$</code>) — most also exist as slash commands.</p>
      </div>

      <div class="docs-search-wrap">
        <span class="docs-search-icon">${svgIcon('search')}</span>
        <input id="docs-search" class="docs-search" type="search" placeholder="Search commands, categories, permissions…" autocomplete="off" aria-label="Search commands" />
      </div>
      <div class="docs-meta-row">
        <span id="docs-count">${commands.length} commands</span>
        <span class="docs-meta-hint">Press <kbd>/</kbd> to search</span>
      </div>

      ${sections}

      <div id="docs-empty" class="docs-empty doc-hidden">No commands match your search.</div>
    </div>`;
    // login: !user renders the no-nav shell for logged-out visitors (docs is
    // public — linked from the login screen), matching the legal pages.
    return render({ title: 'PrimeBot Command Documentation', body, active: 'docs', user, login: !user, scripts: ['/js/docs.js'] });
}

// ── Live ────────────────────────────────────────────────────────────────────

// ── Stats (bot + shardnode node status) ──────────────────────────────────────
//
// The dashboard process can't read the bot's in-memory runtime stats (ping,
// uptime, guilds.cache) because it runs separately from the bot. It can,
// however, read the bot's authoritative server count (Discord REST) and the
// shardnode/failover status tables the bot's nodeFailover module writes. The
// page boots with a shell and the client fetches /api/stats/bot + /api/stats/nodes
// so the numbers stay live without a full reload.

function statsPage({ user } = {}) {
    const body = `
    <div class="page-head">
      <h1>Stats</h1>
      <p>Live bot statistics and shardnode health across the PrimeBot cluster.</p>
    </div>

    <div id="stats-bot" class="stats-band">
      <div class="splash"><div class="spinner"></div><p>Loading bot stats…</p></div>
    </div>

    <div class="card">
      <div class="card-title"><span><span class="icon">${svgIcon('globe')}</span> Shardnode status</span></div>
      <p class="card-desc">Per-node heartbeats and the active failover lease across the sn1 / sn2 / sn3 shard nodes.</p>
      <div id="stats-nodes">
        <div class="splash"><div class="spinner"></div><p>Loading node stats…</p></div>
      </div>
    </div>`;
    return render({ title: 'PrimeBot · Stats', body, active: 'stats', scripts: ['/js/stats.js'], user });
}

// ── Live (split into Polls and Giveaways) ────────────────────────────────────

function livePollsPage({ user } = {}) {
    const body = `
    <div class="page-head">
      <h1>Live Polls</h1>
      <p>Cross-server live polls — running and recently ended, across all of PrimeBot.</p>
      <button class="btn btn-secondary live-refresh-btn" id="live-refresh">${svgIcon("refresh")} Refresh</button>
    </div>
    <div id="live-content">
      <div class="splash"><div class="spinner"></div><p>Loading live polls…</p></div>
    </div>
    <div id="live-join-modal" class="modal-overlay hidden"></div>
    <script>window.liveKind = 'poll';</script>`;
    return render({ title: 'PrimeBot · Live Polls', body, active: 'live-polls', scripts: ['/js/live.js'], user });
}

function liveGiveawaysPage({ user } = {}) {
    const body = `
    <div class="page-head">
      <h1>Live Giveaways</h1>
      <p>Cross-server live giveaways — running and recently ended, across all of PrimeBot.</p>
      <button class="btn btn-secondary live-refresh-btn" id="live-refresh">${svgIcon("refresh")} Refresh</button>
    </div>
    <div id="live-content">
      <div class="splash"><div class="spinner"></div><p>Loading live giveaways…</p></div>
    </div>
    <div id="live-join-modal" class="modal-overlay hidden"></div>
    <script>window.liveKind = 'giveaway';</script>`;
    return render({ title: 'PrimeBot · Live Giveaways', body, active: 'live-giveaways', scripts: ['/js/live.js'], user });
}

// ── Overview (servers) ──────────────────────────────────────────────────────

function guildCardHTML(g, present) {
    const tags = [];
    tags.push(`<span class="tag prefix">${esc(g.prefix || '$')} prefix</span>`);
    if (present) {
        tags.push(g.welcomeEnabled ? `<span class="tag on">${svgIcon('hand')} Welcome</span>` : `<span class="tag off">Welcome off</span>`);
        tags.push(g.levelingEnabled ? `<span class="tag on">${svgIcon('trendingUp')} Leveling</span>` : `<span class="tag off">Leveling off</span>`);
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
    </div>`;
}

function overviewPage({ guilds = [], clientId, user } = {}) {
    const manageable = guilds.filter(g => g.botPresent);
    const absent = guilds.filter(g => !g.botPresent);

    const statsHTML = `
    <div class="stats">
      <div class="stat"><div class="sv">${guilds.length}</div><div class="sl">Servers you manage</div></div>
      <div class="stat"><div class="sv">${manageable.length}</div><div class="sl">With PrimeBot</div></div>
      <div class="stat"><div class="sv">${manageable.filter(g => g.welcomeEnabled).length}</div><div class="sl">Welcome enabled</div></div>
      <div class="stat"><div class="sv">${manageable.filter(g => g.levelingEnabled).length}</div><div class="sl">Leveling enabled</div></div>
    </div>`;

    let listHTML = '';
    if (manageable.length === 0 && absent.length === 0) {
        const invite = `https://discord.com/oauth2/authorize?client_id=${esc(clientId || '')}&permissions=8&integration_type=0&scope=bot%20applications.commands`;
        listHTML = `
      <div class="guild-empty">
        <p class="empty-ico">${svgIcon('search')}</p>
        <p>You don't manage any servers yet, or PrimeBot isn't in any of them.</p>
        <p style="margin-top:12px"><a class="btn btn-secondary" href="${invite}" target="_blank" rel="noopener">${svgIcon('plus')} Invite PrimeBot to a server</a></p>
      </div>`;
    } else {
        if (manageable.length) {
            listHTML += `<div class="guild-grid">` + manageable.map(g => guildCardHTML(g, true)).join('') + `</div>`;
        }
        if (absent.length) {
            listHTML += `
        <h3 style="margin:28px 0 12px;font-size:15px;color:var(--text-dim)">PrimeBot not yet added</h3>
        <div class="guild-grid">` + absent.map(g => guildCardHTML(g, false)).join('') + `</div>`;
        }
    }

    const body = `
    <div class="page-head">
      <h1>Your servers</h1>
      <p>Pick a server to configure PrimeBot. Only servers where you have <strong>Manage Server</strong> permission are shown.</p>
      <p style="margin-top:10px"><span class="beta-badge">BETA</span> <span style="color:var(--text-dim);font-size:13px">Event Management is now in beta — try it from a server's menu.</span></p>
    </div>
    ${statsHTML}
    ${listHTML}`;
    return render({ title: 'PrimeBot · Servers', body, active: 'servers', hideBack: true, scripts: ['/js/servers.js'], user });
}

// ── Privacy Policy ─────────────────────────────────────────────────────────

const LEGAL_LAST_UPDATED = '2026-08-19';

function privacyPage({ user } = {}) {
    const body = `
    <div class="docs">
      <div class="docs-hero">
        <div class="docs-hero-icon">${svgIcon('shield')}</div>
        <h1 class="docs-title">Privacy Policy</h1>
        <p class="docs-lead">How PrimeBot collects, uses and protects information when you use the Discord bot and this dashboard. Last updated ${LEGAL_LAST_UPDATED}.</p>
      </div>

      <nav class="docs-toc">
        <h3>On this page</h3>
        <ul>
          <li><a href="#collect">Information we collect</a></li>
          <li><a href="#use">How we use it</a></li>
          <li><a href="#storage">Storage &amp; retention</a></li>
          <li><a href="#sharing">Sharing</a></li>
          <li><a href="#security">Security</a></li>
          <li><a href="#rights">Your rights &amp; deletion</a></li>
          <li><a href="#contact">Contact</a></li>
        </ul>
      </nav>

      <section id="collect" class="docs-section">
        <h2>1 · Information we collect</h2>
        <p><strong>From Discord OAuth (dashboard sign-in):</strong> your Discord user ID, username and avatar, and the list of servers you manage. We only request the <code>identify</code> and <code>guilds</code> scopes — we never see your Discord password or email.</p>
        <p><strong>Configuration data:</strong> per-server settings you save in the dashboard or through bot commands — welcome messages, leveling settings, prefixes, auto-reactions, automod rules, ticket panels, reaction roles, event schedules, live polls/giveaways and similar configuration.</p>
        <p><strong>Bot runtime data:</strong> message metadata strictly needed for features to work (e.g. reaction events for reaction roles, message content scanned in-memory by the automod, XP counters, warnings, ticket transcripts you choose to save), plus node heartbeats used for failover.</p>
      </section>

      <section id="use" class="docs-section">
        <h2>2 · How we use it</h2>
        <ul class="docs-list">
          <li>To authenticate you and show only the servers you can manage.</li>
          <li>To store and apply your per-server bot configuration.</li>
          <li>To operate features you enable (automod scanning, logging to your chosen channels/webhooks, polls, giveaways, leveling, tickets).</li>
          <li>To keep the service reliable (failover heartbeats, error diagnosis, abuse prevention).</li>
        </ul>
        <p>Automod message scanning happens in memory and is not persisted except for warnings, deleted-message log entries you configure, and action logs you opt into.</p>
      </section>

      <section id="storage" class="docs-section">
        <h2>3 · Storage &amp; retention</h2>
        <p>Data is stored in managed PostgreSQL databases. Dashboard sessions expire automatically, including after a period of tab inactivity. Configuration data is kept until you delete it or remove the bot from your server; audit/website logs and warnings may be kept for a reasonable period for moderation continuity.</p>
      </section>

      <section id="sharing" class="docs-section">
        <h2>4 · Sharing</h2>
        <p>We do not sell or rent your data. Data is shared only with the infrastructure providers required to run the service (hosting, database) and with Discord itself through its API. Content you explicitly send to a webhook URL you configured goes to that destination by your choice.</p>
      </section>

      <section id="security" class="docs-section">
        <h2>5 · Security</h2>
        <p>Sessions are stored server-side behind secure cookies, all traffic is over HTTPS, and access to configuration is limited to members with the Manage Server permission. No system is perfectly secure, but we take reasonable steps to protect your data.</p>
      </section>

      <section id="rights" class="docs-section">
        <h2>6 · Your rights &amp; deletion</h2>
        <p>You can revoke dashboard access at any time from <em>Discord → Settings → Authorized Apps</em>. Removing PrimeBot from your server stops further data collection for that server. To request deletion of stored configuration, warnings or logs for a server, contact us in the support server.</p>
      </section>

      <section id="contact" class="docs-section">
        <h2>7 · Contact</h2>
        <p>Questions about this policy? Reach us in our <a href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener">support server</a>. Also see the <a href="/terms">Terms of Service</a>.</p>
      </section>
    </div>`;
    return render({ title: 'PrimeBot · Privacy Policy', body, user, login: !user });
}

// ── Terms of Service ───────────────────────────────────────────────────────

function termsPage({ user } = {}) {
    const body = `
    <div class="docs">
      <div class="docs-hero">
        <div class="docs-hero-icon">${svgIcon('book')}</div>
        <h1 class="docs-title">Terms of Service</h1>
        <p class="docs-lead">The rules for using PrimeBot — the Discord bot and this dashboard. By using PrimeBot you agree to these terms. Last updated ${LEGAL_LAST_UPDATED}.</p>
      </div>

      <nav class="docs-toc">
        <h3>On this page</h3>
        <ul>
          <li><a href="#acceptance">Acceptance</a></li>
          <li><a href="#service">The service</a></li>
          <li><a href="#acceptable-use">Acceptable use</a></li>
          <li><a href="#content">Your content</a></li>
          <li><a href="#availability">Availability &amp; changes</a></li>
          <li><a href="#liability">Liability</a></li>
          <li><a href="#termination">Termination</a></li>
        </ul>
      </nav>

      <section id="acceptance" class="docs-section">
        <h2>1 · Acceptance</h2>
        <p>By inviting PrimeBot to a server, using its commands, or signing in to the dashboard, you agree to these Terms of Service and to <a href="/privacy">our Privacy Policy</a>. If you don't agree, remove the bot and stop using the dashboard.</p>
        <p>You must comply with <a href="https://discord.com/terms" target="_blank" rel="noopener">Discord's Terms of Service</a> and <a href="https://discord.com/guidelines" target="_blank" rel="noopener">Community Guidelines</a> at all times while using PrimeBot.</p>
      </section>

      <section id="service" class="docs-section">
        <h2>2 · The service</h2>
        <p>PrimeBot provides Discord server tooling — welcome messages, leveling, polls, giveaways, tickets, automod, logging, reaction roles, event scheduling and a web dashboard — free of charge. Features marked <strong>BETA</strong> or <strong>SOON</strong> are experimental, may be gated, and may change or be withdrawn at any time.</p>
      </section>

      <section id="acceptable-use" class="docs-section">
        <h2>3 · Acceptable use</h2>
        <ul class="docs-list">
          <li>Don't use PrimeBot to violate Discord's rules, the law, or other people's rights.</li>
          <li>Don't abuse, spam, or attempt to disrupt the bot, the dashboard, or other users — including exploiting bugs, flooding commands, or evading automod.</li>
          <li>Don't use the bot to distribute malware, phishing, hate, or illegal content.</li>
          <li>Only configure servers you have the Manage Server permission for.</li>
        </ul>
      </section>

      <section id="content" class="docs-section">
        <h2>4 · Your content</h2>
        <p>You keep ownership of the content you configure (messages, embeds, images, webhook URLs). You grant us a limited license to store and transmit that content solely to operate the features you enabled. You are responsible for ensuring you have the rights to any content you configure.</p>
      </section>

      <section id="availability" class="docs-section">
        <h2>5 · Availability &amp; changes</h2>
        <p>PrimeBot is provided "as is" and "as available". We aim for high availability via our failover system but do not guarantee uninterrupted service. We may add, change or remove features — including free features — at any time, with notice in the support server where reasonable.</p>
      </section>

      <section id="liability" class="docs-section">
        <h2>6 · Liability</h2>
        <p>To the maximum extent permitted by law, PrimeBot and its operators are not liable for any indirect, incidental or consequential damages, data loss, or moderation outcomes (including automod actions taken under rules you configured). Because the service is free, any aggregate liability is limited to the amount you paid for it — zero.</p>
      </section>

      <section id="termination" class="docs-section">
        <h2>7 · Termination</h2>
        <p>You can stop using PrimeBot at any time by removing it from your servers and revoking dashboard access. We may suspend or block access for servers or users that violate these terms. Sections that should reasonably survive (liability, acceptable use) survive termination.</p>
        <p>Questions? Contact us in the <a href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener">support server</a>.</p>
      </section>
    </div>`;
    return render({ title: 'PrimeBot · Terms of Service', body, user, login: !user });
}

// ── 404 ────────────────────────────────────────────────────────────────────
//
// Catch-all for any unknown path. On Vercel every request is routed to the
// serverless handler (vercel.json `routes` → /dashboard/server.js), so a broken
// or mistyped link lands here. Renders a friendly graphical 404 with a link
// back to the dashboard root.

function notFoundPage({ user } = {}) {
    const body = `
    <div class="notfound-card">
      <div class="notfound-graphic" aria-hidden="true">
        <div class="notfound-404">
          <span>4</span><span class="notfound-zero">0</span><span>4</span>
        </div>
        <div class="notfound-orb"></div>
      </div>
      <h1 class="notfound-title">Page not found</h1>
      <p class="notfound-text">Oops — the page you're looking for doesn't exist or may have moved. The link might be broken or outdated.</p>
      <div class="notfound-actions">
        <a class="btn btn-primary" href="/">${svgIcon('arrowLeft')} Back to dashboard</a>
        <a class="btn btn-secondary" href="/docs">${svgIcon('book')} Read the docs</a>
      </div>
      <p class="notfound-hint">If you think this is a mistake, let us know in our <a href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener">support server</a>.</p>
    </div>`;
    return render({ title: 'PrimeBot · 404 Not found', body, user });
}

module.exports = { loginPage, docsPage, statsPage, livePollsPage, liveGiveawaysPage, overviewPage, notFoundPage, guildCardHTML, privacyPage, termsPage };
