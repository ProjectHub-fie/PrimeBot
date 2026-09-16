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
        // Mirrors dashboard/server.js (order matters: resolve, then backfill).
        if (!process.env.DASHBOARD_BOT_TOKEN) {
            const resolved = resolveDiscordToken({ cwd });
            if (resolved) process.env.DASHBOARD_BOT_TOKEN = resolved;
        }
        if (!process.env.DISCORD_TOKEN && process.env.DASHBOARD_BOT_TOKEN) {
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

test('dashboard/server.js wires the shared resolver into the boot block', () => {
    const src = read('dashboard/server.js');
    assert.match(src, /require\(['"]\.\.\/utils\/tokenResolver['"]\)/, 'imports the shared resolver');
    assert.match(src, /resolveDiscordToken\(\{ cwd: path\.join\(__dirname, '\.\.'\) \}\)/, 'resolves with the repo root');
    // The dedicated override must still win.
    assert.match(src, /if \(!process\.env\.DASHBOARD_BOT_TOKEN\) \{[\s\S]*?resolveDiscordToken/, 'override wins');
});

// ── 2. Login page labels the fallback honestly ──────────────────────────────

test('login page labels the member card and relabels a leveling fallback', () => {
    const page = require('../dashboard/render/pages');
    const html = page.loginPage({});
    assert.match(html, /id="stat-users-label">Total members</, 'default label matches the member semantics');

    const js = read('dashboard/public/js/login.js');
    assert.match(js, /totalUsersSource === 'bot' \|\| stats\.totalUsersSource === 'rest'/, 'treats bot+rest as member counts');
    assert.match(js, /'Members tracked \(leveling\)'/, 'relabels the fallback so it is not passed off as the member total');
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
