// Login-screen member count + mobile profile menu sizing.
//
// Two bugs covered here:
//
// 1. The dashboard authenticated its REST calls as `Bot ${DISCORD_TOKEN}`
//    while the deployment only set DISCORD_TOKEN2 (the primary production
//    token). The header went out as the literal "Bot undefined", so
//    getBotGuildCount/getBotMemberCount both 401'd and returned null and the
//    login page fell through to the leveling distinct-user count — showing
//    members the bot had tracked XP for, not the real member total. The
//    dashboard now resolves its token through utils/tokenResolver.
//
// 2. The mobile logout dropdown was a 150px-wide rounded panel while the
//    profile pic is a 30px circle. It now shares the avatar's --profile-size
//    square/circle so it reads as the avatar opening.
//
// No DB/network: the server boot block is replayed in-process against a
// temp .env, and the rest is static source/render assertions.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// ── 1. Dashboard bot-token resolution ───────────────────────────────────────

const TOKEN_VARS = ['DISCORD_TOKEN', 'DISCORD_TOKEN2', 'BOT_TOKEN', 'TOKEN', 'CLIENT_TOKEN', 'DASHBOARD_BOT_TOKEN'];

/** Replay the dashboard/server.js token boot block with a given environment. */
function resolveDashboardBotToken(env, cwd) {
    const { resolveDiscordToken } = require('../utils/tokenResolver');
    const saved = {};
    for (const k of TOKEN_VARS) saved[k] = process.env[k];
    for (const k of TOKEN_VARS) delete process.env[k];
    Object.assign(process.env, env);

    try {
        // Mirrors dashboard/server.js (order matters: resolve, then force
        // DISCORD_TOKEN to the resolved/dedicated token so a stale legacy
        // DISCORD_TOKEN can never shadow the primary one).
        if (!process.env.DASHBOARD_BOT_TOKEN) {
            const resolved = resolveDiscordToken({ cwd });
            if (resolved) process.env.DASHBOARD_BOT_TOKEN = resolved;
        }
        if (process.env.DASHBOARD_BOT_TOKEN) {
            process.env.DISCORD_TOKEN = process.env.DASHBOARD_BOT_TOKEN;
        }
        return process.env.DISCORD_TOKEN;
    } finally {
        for (const k of TOKEN_VARS) {
            if (saved[k] === undefined) delete process.env[k];
            else process.env[k] = saved[k];
        }
    }
}

test('dashboard resolves DISCORD_TOKEN2 so botHeaders() is not "Bot undefined"', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'primebot-dash-'));
    fs.writeFileSync(path.join(dir, '.env'), '');
    const token = resolveDashboardBotToken({ DISCORD_TOKEN2: 'primary.token' }, dir);
    assert.equal(token, 'primary.token');
});

test('dashboard still honours a legacy DISCORD_TOKEN deployment', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'primebot-dash-'));
    fs.writeFileSync(path.join(dir, '.env'), '');
    const token = resolveDashboardBotToken({ DISCORD_TOKEN: 'legacy.token' }, dir);
    assert.equal(token, 'legacy.token');
});

test('an explicit DASHBOARD_BOT_TOKEN is never overwritten by the resolver', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'primebot-dash-'));
    fs.writeFileSync(path.join(dir, '.env'), '');
    const token = resolveDashboardBotToken(
        { DASHBOARD_BOT_TOKEN: 'dedicated.token', DISCORD_TOKEN2: 'primary.token' },
        dir
    );
    assert.equal(token, 'dedicated.token');
});

test('a stale legacy DISCORD_TOKEN cannot shadow DISCORD_TOKEN2 (wrong server count)', () => {
    // botHeaders() sends process.env.DISCORD_TOKEN. If a stale legacy token is
    // present in the environment it used to survive the boot block and shadow
    // the resolver's primary DISCORD_TOKEN2, so every REST count call 401'd and
    // the dashboard reported the (far smaller) configured server count.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'primebot-dash-'));
    fs.writeFileSync(path.join(dir, '.env'), '');
    const token = resolveDashboardBotToken(
        { DISCORD_TOKEN: 'stale.legacy.token', DISCORD_TOKEN2: 'primary.token' },
        dir
    );
    assert.equal(token, 'primary.token', 'the primary token must win over a stale legacy one');
});

test('dashboard/server.js wires the shared resolver into the boot block', () => {
    const src = read('dashboard/server.js');
    assert.match(src, /require\(['"]\.\.\/utils\/tokenResolver['"]\)/, 'imports the shared resolver');
    assert.match(src, /resolveDiscordToken\(\{ cwd: path\.join\(__dirname, '\.\.'\) \}\)/, 'resolves with the repo root');
    // The dedicated override must still win.
    assert.match(src, /if \(!process\.env\.DASHBOARD_BOT_TOKEN\) \{[\s\S]*?resolveDiscordToken/, 'override wins');
});

// ── 2. Login page labels the fallback honestly ──────────────────────────────

test('login page labels the member card and dashes when no Discord count is available', () => {
    const page = require('../dashboard/render/pages');
    const html = page.loginPage({});
    assert.match(html, /id="stat-users-label">Total members</, 'default label matches the member semantics');

    const js = read('dashboard/public/js/login.js');
    assert.match(js, /totalUsersSource === 'bot' \|\| stats\.totalUsersSource === 'rest'/, 'treats bot+rest as member counts');
    assert.match(js, /'Members unavailable'/, 'labels the no-Discord-count state honestly');
    assert.ok(!js.includes('Members tracked (leveling)'), 'never presents a leveling-tracked count as the member total');
});

test('/api/stats error fallback reports a null totalUsersSource', () => {
    const src = read('dashboard/server.js');
    assert.match(src, /totalUsers: 0,\s*\n\s*totalUsersSource: null,/, 'fallback payload carries the source field');
});

// ── 3. Profile pic + logout dropdown are the same size ──────────────────────

test('logout dropdown matches the profile pic size', () => {
    const css = read('dashboard/public/styles.css');
    const userMenu = /\.user-menu \{([^}]*)\}/.exec(css);
    assert.ok(userMenu, '.user-menu rule exists');
    assert.match(userMenu[1], /--profile-size:\s*30px/, 'profile size declared once');

    const avatar = /\.user-avatar \{([^}]*)\}/.exec(css);
    assert.match(avatar[1], /width:\s*var\(--profile-size\)/, 'avatar width driven by the variable');
    assert.match(avatar[1], /height:\s*var\(--profile-size\)/, 'avatar height driven by the variable');

    const dropdown = /\.user-menu-dropdown \{([^}]*)\}/.exec(css);
    assert.ok(dropdown, '.user-menu-dropdown rule exists');
    assert.match(dropdown[1], /width:\s*var\(--profile-size\)/, 'dropdown is the same width as the avatar');
    assert.match(dropdown[1], /height:\s*var\(--profile-size\)/, 'dropdown is the same height as the avatar');
    assert.match(dropdown[1], /border-radius:\s*50%/, 'dropdown is a circle like the avatar');
    assert.ok(!/min-width:\s*150px/.test(dropdown[1]), 'the old 150px panel width is gone');
});

test('the dropdown logout button still renders SVG-only', () => {
    const page = require('../dashboard/render/pages');
    const html = page.overviewPage({ user: { id: '1', username: 'Admin', avatar: 'abc' } });
    const link = /<a class="user-menu-logout"[^>]*href="\/logout"[^>]*>([\s\S]*?)<\/a>/.exec(html);
    assert.ok(link, 'dropdown logout link present');
    assert.match(link[1], /<svg/, 'icon is an SVG');
    assert.ok(!/Log out<\/span>/.test(link[1]), 'no text label inside the dropdown button');
});

// ── Anti-Nuke on the login page ─────────────────────────────────────────────

test('login page renders the Anti-Nuke adoption donut + feature card', () => {
    const page = require('../dashboard/render/pages');
    const html = page.loginPage({});
    assert.ok(html.includes('id="donut-antinuke"'), 'Anti-Nuke adoption donut is rendered');
    assert.ok(/id="donut-antinuke"[\s\S]{0,600}Anti-Nuke<\/div>/.test(html), 'the donut is labelled Anti-Nuke');
    assert.ok(html.includes('Anti-Nuke protection'), 'the Anti-Nuke feature card is rendered');
    // Still no emoji — the redesign uses SVG icons only.
    const donut = html.slice(html.indexOf('id="donut-antinuke"'), html.indexOf('id="donut-antinuke"') + 400);
    assert.ok(donut.includes('<svg class="ico"'), 'the donut label uses an SVG icon, not emoji');
});

test('login.js paints the Anti-Nuke donut from the antiNuke feature stat', () => {
    const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'dashboard', 'public', 'js', 'login.js'), 'utf8');
    assert.ok(/donut-antinuke[\s\S]{0,120}f\.antiNuke\?\.percent/.test(src),
        'the client reads features.antiNuke.percent into #donut-antinuke');
});

// ── "Set stats" link beside Documentation on the login page ──────────────────

test('login page shows a "Set stats" link to /stats beside Documentation', () => {
    const page = require('../dashboard/render/pages');
    const html = page.loginPage({});
    const docsIdx = html.indexOf('href="/docs"');
    const statsIdx = html.indexOf('href="/stats"');
    assert.ok(docsIdx !== -1, 'Documentation link present');
    assert.ok(statsIdx !== -1, 'Set stats link present');
    assert.ok(statsIdx > docsIdx, 'Set stats sits beside/after Documentation');
    // The link is a real anchor with an SVG icon, labelled "Set stats".
    const anchor = /<a href="\/stats"[^>]*>([\s\S]*?)<\/a>/.exec(html);
    assert.ok(anchor, 'Set stats anchor found');
    assert.match(anchor[1], /<svg/, 'Set stats uses an SVG icon');
    assert.match(anchor[1], /Set stats/, 'Set stats label present');
});
