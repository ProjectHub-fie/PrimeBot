const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Renders + wiring tests for the redesigned AutoMod page and the Anti-Nuke tab.
//
// These are static (no DB/network): they render the pages through the real
// render modules and cross-check the client script against the markup. The
// point is to catch the class of bug that is invisible in a unit test but
// obvious in a browser — a section the nav can't reach, an element id the
// client reads but the page never renders, or a duplicate section that makes
// half the settings unreachable.

const guildPages = require('../dashboard/render/guild-pages');
const { TABS } = require('../dashboard/render/guild');

function fixture(overrides = {}) {
    return {
        id: '111111111111111111', name: 'Test Server', icon: null,
        _config: {
            server: {}, welcome: {}, logging: {},
            automod: {
                enabled: true,
                rules: [
                    { type: 'invites', enabled: true, actions: ['delete', 'warn'], severity: 'medium' },
                    { type: 'spam', enabled: false, actions: ['timeout'], threshold: 5, seconds: 10 },
                ],
                warnLadder: [{ count: 2, actions: ['timeout'] }, { count: 5, actions: ['kick'] }],
                logChannelId: '222222222222222222',
            },
            antiNuke: {},
        },
        _channels: [{ id: '222222222222222222', name: 'general', type: 0 }],
        _roles: [{ id: '333333333333333333', name: 'Staff' }],
        ...overrides,
    };
}

function renderAutomod(guild = fixture()) {
    return guildPages.automodPage({ guild, user: { username: 'u' } });
}
function renderAntiNuke(guild = fixture()) {
    return guildPages.antiNukePage({ guild, user: { username: 'u' } });
}

function idsIn(html) {
    return new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
}

// Every element id the client script looks up, in both getElementById and
// querySelector('#id') form.
function clientIdRefs(scriptPath) {
    const js = fs.readFileSync(scriptPath, 'utf8');
    const refs = new Set();
    for (const m of js.matchAll(/getElementById\(\s*['"]([^'"]+)['"]\s*\)/g)) refs.add(m[1]);
    for (const m of js.matchAll(/[^a-zA-Z](\$|querySelector)\(\s*'#([a-zA-Z0-9_-]+)'/g)) refs.add(m[2]);
    return refs;
}

// ── Sections ────────────────────────────────────────────────────────────────

test('automod page renders each section exactly once', () => {
    const html = renderAutomod();
    const sections = [...html.matchAll(/<section class="am-section" data-section="([^"]+)"/g)].map(m => m[1]);
    assert.ok(sections.length >= 10, `expected the full section set, got ${sections.length}`);
    const counts = {};
    for (const s of sections) counts[s] = (counts[s] || 0) + 1;
    for (const [key, n] of Object.entries(counts)) {
        assert.equal(n, 1, `section "${key}" rendered ${n} times — a duplicate makes half the settings unreachable`);
    }
});

test('every nav button targets a rendered section and vice versa', () => {
    const html = renderAutomod();
    const navKeys = new Set([...html.matchAll(/class="am-section-btn[^"]*"\s+data-section="([^"]+)"/g)].map(m => m[1]));
    const sectionKeys = new Set([...html.matchAll(/<section class="am-section" data-section="([^"]+)"/g)].map(m => m[1]));
    assert.ok(navKeys.size >= 10, `expected the full sidebar, got ${navKeys.size} entries`);
    for (const k of navKeys) assert.ok(sectionKeys.has(k), `nav button "${k}" has no section`);
    for (const k of sectionKeys) assert.ok(navKeys.has(k), `section "${k}" is unreachable from the nav`);
});

test('automod page covers every section the client script navigates to', () => {
    const html = renderAutomod();
    const sectionKeys = new Set([...html.matchAll(/<section class="am-section" data-section="([^"]+)"/g)].map(m => m[1]));
    // The client's rule-card "test" button and deep links jump to these.
    for (const key of ['overview', 'rules', 'spam', 'content', 'raid', 'warnings',
                       'punishments', 'exemptions', 'incidents', 'analytics', 'settings']) {
        assert.ok(sectionKeys.has(key), `missing section "${key}"`);
    }
});

// ── Client/markup contract ──────────────────────────────────────────────────

test('every element id the automod client reads is rendered by the page', () => {
    const html = renderAutomod();
    const ids = idsIn(html);
    // Ids the client renders itself (into the containers above) rather than
    // reading from the server-rendered markup.
    const CLIENT_CREATED = new Set(['am-exempt-user-input']);
    const missing = [...clientIdRefs(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'automod.js'))]
        .filter(id => !ids.has(id) && !CLIENT_CREATED.has(id));
    assert.deepEqual(missing, [], `client reads ids the page never renders: ${missing.join(', ')}`);
});

test('every element id the antinuke client reads is rendered by the page', () => {
    const html = renderAntiNuke();
    const ids = idsIn(html);
    const missing = [...clientIdRefs(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'antinuke.js'))]
        .filter(id => !ids.has(id));
    assert.deepEqual(missing, [], `client reads ids the page never renders: ${missing.join(', ')}`);
});

test('the page injects the catalogs the client renders from', () => {
    const html = renderAutomod();
    for (const global of ['__AUTOMOD_RULES', '__AUTOMOD_ACTIONS', '__AUTOMOD_SEVERITIES',
                          '__AUTOMOD_PRESETS', '__AUTOMOD_PARAMS', '__AUTOMOD_SETTINGS']) {
        assert.ok(html.includes(`window.${global}=`), `page does not inject window.${global}`);
    }
    // The param catalog must actually contain definitions, or every rule card
    // would render without its threshold/words inputs.
    const m = html.match(/window\.__AUTOMOD_PARAMS=(\{.*?\});/s);
    assert.ok(m, 'no __AUTOMOD_PARAMS payload');
    const params = JSON.parse(m[1]);
    assert.ok(params.threshold && params.words && params.seconds, 'param catalog is missing core definitions');
});

test('the automod page loads its own script and the shared guild script', () => {
    const scripts = guildPages.automodPage({ guild: fixture(), user: { username: 'u' } });
    assert.ok(scripts, 'page returned nothing');
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'render', 'automod-page.js'), 'utf8');
    assert.match(src, /scripts: \['\/js\/guild-common\.js', '\/js\/automod\.js'\]/);
});

// ── Anti-Nuke tab ───────────────────────────────────────────────────────────

test('Anti-Nuke is its own sidebar tab and renders the Coming Soon overlay', () => {
    const tab = TABS.find(t => t.key === 'antinuke');
    assert.ok(tab, 'Anti-Nuke tab is missing from the server-features sidebar');
    assert.equal(tab.label, 'Anti-Nuke');
    assert.equal(tab.upcoming, true, 'Anti-Nuke must be flagged upcoming (Coming Soon)');

    const html = renderAntiNuke();
    assert.match(html, /upcoming-locked-wrap locked/, 'no blurred/inert wrapper');
    assert.match(html, /Coming Soon/, 'no Coming Soon overlay');
    assert.match(html, /antinuke\.js/, 'the Anti-Nuke page must load its client script');
});

test('the Anti-Nuke overlay blurs the real editor rather than replacing it', () => {
    const html = renderAntiNuke();
    // The underlying controls stay in the markup (blurred + inert), so removing
    // the flag later re-enables the feature with no rewrite.
    assert.match(html, /id="an-enabled"/);
    assert.match(html, /class="an-watch-card"/);
    assert.match(html, /class="an-response"/);
});

test('the Anti-Nuke client exits when the Coming Soon overlay is present', () => {
    const js = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'antinuke.js'), 'utf8');
    assert.match(js, /upcoming-locked-wrap\.locked/, 'client must detect the upcoming overlay');
    assert.match(js, /return;/, 'client must exit early behind the overlay');
});

test('Anti-Nuke renders watch cards for every catalog action', () => {
    const { NUKE_ACTIONS } = require('../utils/antiNukeRules');
    const html = renderAntiNuke();
    for (const action of NUKE_ACTIONS) {
        assert.ok(html.includes(`data-action="${action.key}"`), `no watch card for ${action.key}`);
    }
});

// ── Safety properties of the rendered page ──────────────────────────────────

test('rule cards render the configured actions, thresholds and severity', () => {
    const html = renderAutomod();
    // The invites rule is enabled with delete+warn; the spam rule is disabled.
    assert.match(html, /data-type="invites"/);
    assert.match(html, /data-type="spam"/);
    assert.match(html, /class="am-action" value="delete" checked/);
    assert.match(html, /class="am-action" value="warn" checked/);
    assert.match(html, /class="am-threshold" value="5"/);
    assert.match(html, /class="am-seconds" value="10"/);
    assert.match(html, /am-sev am-sev-medium/);
});

test('the warning ladder renders one row per configured step', () => {
    const html = renderAutomod();
    const rows = [...html.matchAll(/class="am-ladder-row"/g)];
    assert.equal(rows.length, 2, 'expected one ladder row per configured step');
    assert.match(html, /class="am-ladder-count" value="2"/);
    assert.match(html, /class="am-ladder-count" value="5"/);
});

test('per-rule exemptions render collapsed (hidden) by default', () => {
    const html = renderAutomod();
    assert.match(html, /class="am-rule-exempt" hidden/, 'per-rule exemptions should start collapsed');
    assert.match(html, /am-rule-exempt-toggle/);
});

test('the incident center renders search + filter controls and a pager slot', () => {
    const html = renderAutomod();
    assert.match(html, /id="am-inc-search"/);
    for (const id of ['am-inc-rule', 'am-inc-severity', 'am-inc-action', 'am-inc-days']) {
        assert.ok(html.includes(`id="${id}"`), `missing incident filter ${id}`);
    }
    assert.match(html, /id="am-incidents-pager"/);
});

test('the rule tester is present and marked as non-enforcing', () => {
    const html = renderAutomod();
    assert.match(html, /id="am-test-content"/);
    assert.match(html, /id="am-run-test"/);
    // The tester must be advertised as safe to run.
    assert.match(html, /(no action|not punish|without punishing|Nothing is (sent|actioned))/i);
});

test('the overview surfaces the master toggle and its live status pill', () => {
    const html = renderAutomod();
    assert.match(html, /id="am-enabled"/);
    assert.match(html, /id="am-status-pill"/);
    assert.match(html, /id="am-status-text"/);
    assert.match(html, /id="am-stats"/);
});

test('every preset is offered as an apply button', () => {
    const { PRESETS } = require('../utils/automodPresets');
    const html = renderAutomod();
    for (const p of PRESETS) {
        assert.ok(html.includes(`data-preset="${p.key}"`), `preset ${p.key} has no apply button`);
    }
});

test('the page escapes guild-supplied text (no raw injection into markup)', () => {
    const guild = fixture({ name: '<img src=x onerror=alert(1)>' });
    guild._config.automod.rules = [{ type: 'blockedWords', enabled: true, actions: ['delete'], words: ['<script>alert(1)</script>'] }];
    const html = renderAutomod(guild);
    assert.ok(!html.includes('<script>alert(1)</script>'), 'blocked word was not escaped');
    assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'guild name was not escaped');
});

test('inlined settings cannot break out of the script tag', () => {
    // A rule value containing `</script>` would otherwise close the inline
    // script element and let the rest be parsed as HTML — stored XSS via a
    // saved blocked word. jsonForScript escapes `<` to prevent that.
    const guild = fixture();
    guild._config.automod.rules = [{
        type: 'blockedWords', enabled: true, actions: ['delete'],
        words: ['</script><img src=x onerror=alert(1)>'],
    }];
    const html = renderAutomod(guild);
    assert.ok(!html.includes('</script><img'), 'settings JSON broke out of the script tag');
    assert.ok(html.includes('\\u003c/script'), 'expected the `<` to be escaped as \\u003c');
    // The payload must still survive as data.
    const m = html.match(/window\.__AUTOMOD_SETTINGS=(\{.*?\});<\/script>/s);
    assert.ok(m, 'settings payload missing');
    const parsed = JSON.parse(m[1]);
    assert.equal(parsed.rules[0].words[0], '</script><img src=x onerror=alert(1)>');
});

test('jsonForScript neutralizes script-breaking and line-separator payloads', () => {
    const { jsonForScript } = require('../dashboard/render/layout');
    const out = jsonForScript({ a: '</script><!--', b: '\u2028\u2029' });
    assert.ok(!out.includes('</script'), 'raw closing tag survived');
    assert.ok(!out.includes('<!--'), 'raw HTML comment opener survived');
    assert.ok(!/[\u2028\u2029]/.test(out), 'raw line separator survived');
    // Still valid JSON that round-trips.
    assert.deepEqual(JSON.parse(out), { a: '</script><!--', b: '\u2028\u2029' });
    assert.equal(jsonForScript(undefined), 'null');
});