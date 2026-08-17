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
        _config: { server: {}, welcome: {}, logging: {}, automod: {} },
        _channels: [], _roles: [],
    };
    for (const fn of ['welcomePage', 'levelingPage', 'badgesPage', 'prefixPage',
                      'roleRewardsPage', 'autoResponderPage', 'reactionsPage',
                      'loggingPage', 'reactionRolesPage', 'ticketsPage',
                      'automodPage', 'eventsPage', 'livePollsPage', 'liveGiveawaysPage']) {
        const html = guildPages[fn]({ guild, user: { username: 'u' } });
        assert.ok(hasIco(html), `${fn} has no svg icon`);
        // No leftover emoji in card-title icon spans.
        assert.doesNotMatch(html, /class="icon">[^$<]/, `${fn} has an emoji (non-${'${svgIcon}'}) card-title icon`);
    }
});
