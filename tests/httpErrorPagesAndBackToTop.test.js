const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const pages = require('../dashboard/render/pages');
const layout = require('../dashboard/render/layout');
const guildPages = require('../dashboard/render/guild-pages');
const { svgIcon, ICONS } = require('../dashboard/public/js/icons');

const SERVER = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'server.js'), 'utf-8');
const STYLES = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'styles.css'), 'utf-8');

const CODES = [400, 401, 403, 408, 429, 500, 502];

function fakeGuild() {
    return {
        id: '111',
        icon: null,
        name: 'Test Guild',
        _ticketPanel: {
            id: 'p1',
            guildId: '111',
            name: 'Support',
            channelId: '222',
            messageType: 'embed',
            content: '',
            title: 'Support Tickets',
            description: 'Click the button below to open a support ticket.',
            authorName: '',
            authorIconUrl: '',
            footerText: '',
            thumbnailUrl: '',
            imageUrl: '',
            embedColor: '#5865F2',
            buttonLabel: 'Open Ticket',
            buttonEmoji: '',
            buttonStyle: 'primary',
            openNameTemplate: '',
            claimedNameTemplate: '',
            closedNameTemplate: '',
            enabled: true,
        },
    };
}

test('HTTP error pages: every requested code renders same design family as 404', () => {
    for (const code of CODES) {
        const html = pages.errorPage({ code, user: null });
        assert.ok(html.includes('notfound-card'), code + ': card');
        assert.ok(html.includes('<span>' + code + '</span>'), code + ': code numeral');
        assert.ok(html.includes('Back to dashboard'), code + ': action link');
        assert.ok(html.includes('Read the docs'), code + ': docs link');
        assert.ok(!html.includes('notfound-zero'), code + ': no animated zero (plain digits for errors)');
    }
    const unknown = pages.errorPage({ code: 418, user: null });
    assert.ok(unknown.includes('Internal Server Error'), 'unknown code falls back to 500 copy');
});

test('HTTP error pages: title + message + status-appropriate copy', () => {
    const byCode = {
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        408: 'Request Timeout',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
        502: 'Bad Gateway',
    };
    for (const code of Object.keys(byCode)) {
        const num = Number(code);
        const title = byCode[code];
        const html = pages.errorPage({ code: num, user: null });
        assert.ok(html.includes(title), code + ' renders ' + title);
        assert.ok(html.includes('PrimeBot · ' + code + ' ' + title), code + ' page title');
    }
});

test('HTTP error pages: exported by pages module', () => {
    assert.equal(typeof pages.errorPage, 'function');
});

test('server: registers /error/:code and /:code routes for the seven codes + keeps 404 catch-all', () => {
    for (const code of CODES) {
        assert.ok(SERVER.includes('/error/${code}'), 'route /error/' + code);
        assert.ok(SERVER.includes('/${code}'), 'route /' + code);
    }
    assert.ok(SERVER.includes('pages.errorPage'), 'errorPage wired into server');
    assert.ok(SERVER.includes('pages.notFoundPage'), '404 handler retained');
    assert.ok(SERVER.includes('HTTP_ERROR_CODES'), 'code list constant');
});

test('server: error middleware surfaces err.status for html clients', () => {
    assert.ok(SERVER.includes('err.status'), 'uses err.status');
    assert.ok(SERVER.includes('res.headersSent'), 'guards headersSent');
    assert.ok(SERVER.includes('renderHttpError('), 'delegates to renderHttpError');
});

test('ticket editor: color field was moved OUT of the preview embed bar (restructured)', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    const colorRegion = html.indexOf('edb-region-color');
    const previewEmbed = html.indexOf('tk-preview-embed');
    assert.ok(colorRegion >= 0, 'color region exists');
    assert.ok(previewEmbed >= 0, 'preview embed exists');
    assert.ok(colorRegion < previewEmbed, 'color region now sits BEFOREthe preview embed (no longer inside the bar)');
    assert.ok(html.includes('id="edb-bar"'), 'live color bar still on the preview embed');
    assert.ok((html.match(/id="tk-color"/g) || []).length === 1,'single tk-color input');
});

test('ticket editor: Author/Title/Description/Thumbnail/Image/Footer fields all sit INSIDEthe embed body', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    const bodyStart = html.indexOf('edb-preview-embed-body');
    const bodyEnd = html.lastIndexOf('edb-live-button');
    const inside = ['edb-author', 'edb-title', 'edb-desc', 'edb-thumb', 'edb-image', 'edb-footer'];
    for (const cls of inside) {
        const idx = html.indexOf(cls);
        assert.ok(idx > bodyStart && idx < bodyEnd, cls + ' inside embed body');
    }
});

test('preview embed: bar and body remain a row with min-width guards (fits page width)', () => {
    assert.match(STYLES, /\.tk-preview-embed-body \{ min-width:\s*0;/);
    assert.match(STYLES, /\.tk-embed-builder \{[\s\S]*?min-width:\s*0;/);
    assert.match(STYLES, /\.edb-duo \{ display:\s*grid; grid-template-columns:\s*minmax\(0,\s*1fr\)\s*minmax\(0,\s*1fr\);/);
    assert.match(STYLES, /@media \(max-width:\s*980px\)[\s\S]*?\.edb-duo,\s*\.edb-triple \{ grid-template-columns:\s*1fr;/);
});

test('embed builder: mobile 720px rules stack the bar above the body', () => {
    assert.match(STYLES, /@media \(max-width:\s*720px\)/);
    assert.match(STYLES, /\.tk-preview-embed \{\s*flex-direction:\s*column;/);
    assert.match(STYLES, /\.tk-preview-embed-bar \{ width:\s*100%; height:\s*4px;/);
});

test('back-to-top: layout renders the button with the arrowUp SVG + inline scroll handler', () => {
    const html = layout.render({ title: 'Test', body: 'x', user: null, hideBack: true });
    assert.ok(html.includes('id="back-to-top"'), 'button element');
    assert.ok(html.includes('<polyline points="5 12 12 5 19 12"/>'), 'arrowUp svg icon used');
    assert.ok(html.includes('window.scrollY > 420'), 'scroll threshold in inline script');
    assert.ok(html.includes('scrollTo({ top: 0,'), 'smooth scroll to top');
    assert.ok(ICONS.arrowUp, 'arrowUp icon registered in catalog');
    assert.ok(svgIcon('arrowUp').includes('<svg class="ico"'), 'svgIcon renders arrowUp as svg');
});

test('back-to-top: styles define hidden -> visible state with svg sizing', () => {
    assert.match(STYLES, /\.back-to-top \{\s*position:\s*fixed;/);
    assert.match(STYLES, /\.back-to-top\.visible \{\s*opacity:/);
    assert.match(STYLES, /\.back-to-top \.ico \{ width:\s*22px;/);
    assert.match(STYLES, /pointer-events:\s*none;/);
    assert.match(STYLES, /pointer-events:\s*auto;/);
});

test('back-to-top: button styled after the toast block (toast stays visually dominant)', () => {
    const toastIdx = STYLES.indexOf('.toast {');
    const bttIdx = STYLES.indexOf('.back-to-top {');
    assert.ok(toastIdx >= 0, 'both rule sets exist');
    assert.ok(bttIdx > toastIdx, 'back-to-top styles appear after toast styles');
});