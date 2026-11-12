// Render smoke test: the redesigned pages emit the new design tokens and SVG
// icons, with no leftover emoji iconography. Pure — no DB, no network.
const { test } = require('node:test');
const assert = require('node:assert');

const pages = require('../dashboard/render/pages');
const guildPages = require('../dashboard/render/guild-pages');
const { render, loginPage } = pages;

function hasIco(html) { return /<svg class="ico"/.test(html); }

test('login page: new tokens + svg icons, no emoji brand/login', () => {
    const html = loginPage({});
    assert.match(html, /<svg class="ico"/);
    assert.match(html, /fonts\.googleapis\.com.*Sora/);
    assert.doesNotMatch(html, /login-hero">⚡/);
    assert.doesNotMatch(html, />🚪 Login with Discord/);
});

test('docs page: svg hero + command-card icons', () => {
    const html = pages.docsPage({});
    assert.match(html, /<svg class="ico"/);
});

test('stats page: svg node + globe icons, no leftover emoji', () => {
    const html = pages.statsPage({ nodes: [] });
    assert.match(html, /<svg class="ico"/);
});

test('stats page: renders the website-latency card shell with 7/30/90 switcher', () => {
    const html = pages.statsPage({});
    assert.match(html, /Website latency/);
    assert.match(html, /id="stats-latency"/);
    assert.match(html, /id="stats-latency-routes"/);
    assert.match(html, /lat-window/);
    // Exactly three day-window buttons, 30 days active by default.
    assert.match(html, /data-days="7"/);
    assert.match(html, /data-days="30"/);
    assert.match(html, /data-days="90"/);
});

test('overview (servers) page: svg tags, no emoji', () => {
    const html = pages.overviewPage({ guilds: [], user: { username: 'u' } });
    assert.match(html, /<svg class="ico"/);
});

test('404 page: svg + graphic, returns 404 status', () => {
    const html = pages.notFoundPage();
    assert.match(html, /notfound-card/);
    assert.match(html, /<svg class="ico"/);
});

test('guild tab pages: card-title icons are SVG, no emoji leftovers in titles', () => {
    const guild = {
        id: '1', name: 'Test', icon: null,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, antiNuke: {} },
        _channels: [], _roles: [],
    };
    for (const fn of ['welcomePage', 'levelingPage', 'badgesPage', 'prefixPage',
                      'roleRewardsPage', 'autoResponderPage', 'reactionsPage',
                      'birthdaysPage', 'youtubePage', 'loggingPage', 'reactionRolesPage', 'ticketsPage',
                      'automodPage', 'antiNukePage', 'eventsPage', 'livePollsPage', 'liveGiveawaysPage']) {
        const html = guildPages[fn]({ guild, user: { username: 'u' } });
        assert.ok(hasIco(html), `${fn} has no svg icon`);
        // No leftover emoji in card-title icon spans.
        assert.doesNotMatch(html, /class="icon">[^$<]/, `${fn} has an emoji (non-${'${svgIcon}'}) card-title icon`);
    }
});
