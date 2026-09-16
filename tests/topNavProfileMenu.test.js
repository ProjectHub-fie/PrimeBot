// Top-nav layout: pinned profile avatar + mobile-only transparent account
// dropdown, with the nav links in their own scrollable rail.
//
// The dashboard is server-rendered, so these are render-level assertions on
// navHTML() plus a CSS audit of the rules that make the mobile behaviour work
// (the desktop/mobile split lives entirely in the 760px media query). No DB or
// network is touched.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { navHTML } = require('../dashboard/render/layout');

const USER = {
    id: '123',
    username: 'tester',
    globalName: 'Tester',
    avatar: 'abc123',
};

const html = navHTML({ active: 'servers', user: USER });
const css = fs.readFileSync(path.join(__dirname, '..', 'dashboard/public/styles.css'), 'utf8');

test('nav renders the profile pic as a dedicated toggle button', () => {
    assert.match(html, /<button[^>]*id="user-menu-toggle"/, 'avatar should be a button');
    assert.match(html, /aria-haspopup="menu"/);
    assert.match(html, /aria-expanded="false"/);
    assert.match(html, /aria-controls="user-menu-dropdown"/);
    assert.match(html, /class="user-avatar"[^>]*src="https:\/\/cdn\.discordapp\.com\/avatars\/123\/abc123\.png/);
});

test('avatar falls back to an initial when the user has no avatar', () => {
    const noAvatar = navHTML({ active: 'servers', user: { id: '9', username: 'zoe' } });
    assert.match(noAvatar, /class="user-avatar user-avatar-fallback"/);
    assert.match(noAvatar, />Z<\/span>/);
});

test('dropdown contains an SVG-only logout link', () => {
    assert.match(html, /<div class="user-menu-dropdown" id="user-menu-dropdown" role="menu">/);
    const link = /<a class="user-menu-logout"[^>]*href="\/logout"[^>]*>([\s\S]*?)<\/a>/.exec(html);
    assert.ok(link, 'logout link present');
    assert.match(link[1], /<svg class="ico"/, 'logout button is an SVG icon');
    assert.ok(!/Log out<\/span>/.test(link[1]), 'no text label inside the dropdown button');
    assert.match(link[1], /<path d="M9 21H5/, 'uses the logOut icon glyph');
});

test('nav links live outside the user menu so the avatar stays pinned', () => {
    const navClose = html.indexOf('</nav>');
    const userMenuStart = html.indexOf('<div class="user-menu">');
    assert.ok(navClose > 0 && userMenuStart > 0, 'both blocks render');
    assert.ok(navClose < userMenuStart, 'nav closes before the user menu begins');

    for (const href of ['/', '/dashboard', '/live', '/docs', '/stats']) {
        const navBlock = html.slice(html.indexOf('<nav class="topnav">'), navClose);
        assert.ok(navBlock.includes(`href="${href}"`), `${href} is inside the nav rail`);
    }
});

test('desktop keeps the inline name + Log out button', () => {
    assert.match(html, /<span class="user-name">Tester<\/span>/);
    assert.match(html, /<button class="logout-btn" id="logout-btn">Log out<\/button>/);
});

test('no nav markup is rendered on the login page', () => {
    assert.equal(navHTML({ login: true, user: USER }), '');
});

// ── CSS audit ───────────────────────────────────────────────────────────────

test('the nav rail is the flexible/scrollable child and the avatar is pinned', () => {
    const navRule = /\.topnav \{([^}]*)\}/.exec(css);
    assert.ok(navRule, '.topnav rule exists');
    assert.match(navRule[1], /overflow-x:\s*auto/, 'nav scrolls horizontally');
    assert.match(navRule[1], /min-width:\s*0/, 'nav can shrink');

    const userMenuRule = /\.user-menu \{([^}]*)\}/.exec(css);
    assert.ok(userMenuRule, '.user-menu rule exists');
    assert.match(userMenuRule[1], /flex:\s*0 0 auto/, 'user menu never shrinks');
    assert.match(userMenuRule[1], /position:\s*relative/, 'dropdown anchors to the avatar');
});

test('the dropdown is hidden by default, transparent, and mobile-revealed', () => {
    const dropdownRule = /\.user-menu-dropdown \{([^}]*)\}/.exec(css);
    assert.ok(dropdownRule, '.user-menu-dropdown rule exists');
    assert.match(dropdownRule[1], /display:\s*none/, 'hidden on desktop');
    assert.match(dropdownRule[1], /rgba\(/, 'translucent (transparent) background');
    assert.match(dropdownRule[1], /backdrop-filter/, 'glassy transparent panel');
    assert.match(dropdownRule[1], /position:\s*absolute/);

    assert.match(css, /\.user-menu-dropdown\.open \{ display: block; \}/, 'opening reveals it');
});

test('the 760px media query swaps the desktop logout for the dropdown', () => {
    const mq = /@media \(max-width: 760px\) \{([\s\S]*?)\n\}/.exec(css);
    assert.ok(mq, '760px media query exists');
    assert.match(mq[1], /\.user-menu \.logout-btn \{ display: none; \}/, 'inline logout hidden on mobile');
    assert.match(mq[1], /\.user-name \{ display: none; \}/, 'username hidden on mobile');
    assert.match(mq[1], /\.user-menu-dropdown/, 'dropdown positioned on mobile');
});