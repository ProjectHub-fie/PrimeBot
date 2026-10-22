'use strict';

// Embed palette consistency — every system embed color must live on the
// Figma-inspired palette (config.colors), so "all embeds in the same design"
// stays true and no raw off-palette hex can drift back in.

const test = require('node:test');
const assert = require('node:assert/strict');

const config = require('../config');
const P = config.colors;
const PALETTE_HEXES = new Set(Object.values(P).map(h => h.toUpperCase()));

function assertOnPalette(where, hex) {
    assert.match(hex, /^#[0-9A-Fa-f]{6}$/, `${where}: "${hex}" is not a hex color`);
    assert.ok(
        PALETTE_HEXES.has(hex.toUpperCase()),
        `${where}: color ${hex} is not on the PrimeBot palette (${[...PALETTE_HEXES].join(', ')})`
    );
}

test('system embed sources no longer carry off-palette hex colors', () => {
    // Files whose embeds moved onto config.colors. Static scan prevents the raw
    // off-palette hexes from sneaking back into these code paths. The broadcast
    // wizard's user-chosen color options in events/messageCreate.js are preserved
    // (user input), so messageCreate is excluded from the sweep.
    const fs = require('node:fs');
    const path = require('node:path');
    const files = [
        'utils/countingManager.js',
        'utils/birthdayManager.js',
        'utils/webhookLogger.js',
        'commands/appeal.js',
        'commands/snipe.js',
    ];
    const FORBIDDEN = /#FF0000|#FFA500|#FFC0CB|#FF69B4|#9B59B6|#2ECC71|#95A5A6|#EB459E|#99AAB5|#ED8A5C|#800080|#FFFF00|#00FF00|#0000FF/i;
    for (const rel of files) {
        const src = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
        assert.equal(FORBIDDEN.test(src), false, `${rel} still contains an off-palette hex color`);
    }
});

test('automod severity catalog colors all live on the palette and stay consistent', () => {
    const { SEVERITIES, severityMeta } = require('../utils/automodRules');
    const order = ['low', 'medium', 'high', 'critical'];
    for (const s of SEVERITIES) {
        assertOnPalette(`severity ${s.key} colorHex`, s.colorHex);
        assert.equal(parseInt(s.colorHex.slice(1), 16), s.color, `${s.key} colorHex must equal color`);
    }
    assert.deepEqual(SEVERITIES.map((s) => s.key), order);
    assert.equal(severityMeta('high').colorHex, P.gold.toUpperCase());
});

test('bot roles catalog colors all live on the palette', () => {
    const { ROLE_INFO } = require('../utils/botRoles');
    for (const [role, meta] of Object.entries(ROLE_INFO)) {
        assertOnPalette(`bot role ${role}`, meta.color);
    }
});

test('event management catalog colors all live on the palette', () => {
    const C = require('../shared/eventConstants');
    for (const t of [...C.EVENT_TYPES, ...C.EVENT_STATUSES, ...C.PARTICIPANT_STATUSES, ...C.ATTENDANCE_STATUSES]) {
        assertOnPalette(`event ${t.key}`, t.color);
    }
});

test('failover webhook log colors are derived from the palette', () => {
    const { COLORS } = require('../utils/webhookLogger');
    const hex = (n) => '#' + ('000000' + n.toString(16)).slice(-6).toUpperCase();
    for (const [kind, int] of Object.entries(COLORS)) {
        assertOnPalette(`webhook ${kind}`, hex(int));
    }
});

test('logging + ticket-logging catalog hexes are legacy presets the theme remaps', () => {
    // These catalogs feed the themed EmbedBuilder at runtime; colors must be
    // legacy presets that the theme layer maps (never arbitrary off-palette).
    const { LOG_EVENTS, metaFor } = require('../utils/logEvents');
    const { TICKET_LOG_EVENTS, metaFor: tMeta } = require('../shared/ticketLogging');
    const { colorInt } = require('../utils/serverLogger');
    const LEGACY = new Set(['#5865F2', '#4752C4', '#57F287', '#ED4245', '#FEE75C', '#FFD700', '#CD7F32', '#C0C0C0', '#E5E4E2']);
    for (const e of [...LOG_EVENTS, ...TICKET_LOG_EVENTS]) {
        assert.ok(LEGACY.has(e.color.toUpperCase()), `${e.key} color ${e.color} is not a mapped legacy preset`);
    }
    // The runtime theme maps every legacy preset onto the palette.
    const discord = require('discord.js');
    const { installEmbedTheme } = require('../utils/embedTheme');
    installEmbedTheme(discord);
    const themed = new discord.EmbedBuilder().setColor(colorInt(metaFor('memberJoin').color)).toJSON();
    assert.equal(themed.color, Number.parseInt(P.success.replace(/^#/, ''), 16));
    const themedPending = new discord.EmbedBuilder().setColor(colorInt(tMeta('created').color)).toJSON();
    assert.equal(themedPending.color, Number.parseInt(P.success.replace(/^#/, ''), 16));
});