/**
 * webhookLogger.js
 *
 * Sends rich Discord embed messages for shard-node failover events.
 * Set FAILOVER_WEBHOOK_URL in your environment/secrets to enable.
 * Fire-and-forget — never throws, never blocks the caller.
 */

const https = require('https');
const { URL } = require('url');

// ── Constants ──────────────────────────────────────────────────────────────

const COLORS = {
    online:  0x57F287, // green
    offline: 0xED4245, // red
    standby: 0xFEE75C, // yellow
    warning: 0xFFA500, // orange
    info:    0x5865F2, // blurple
};

const STATUS_ICONS = {
    online:  '🟢',
    offline: '🔴',
    standby: '🟡',
    warning: '🟠',
    info:    '🔵',
};

const ROLE_META = {
    sn1: { label: 'SN1 — Primary',   priority: '1  (Highest)', icon: '👑' },
    sn2: { label: 'SN2 — Secondary', priority: '2  (Middle)',  icon: '🔷' },
    sn3: { label: 'SN3 — Tertiary',  priority: '3  (Lowest)',  icon: '🔹' },
};

// Unix timestamp (seconds) of when this process first loaded the module.
// Used to show "active since" on Online events.
const BOOT_UNIX = Math.floor(Date.now() / 1000);

// ── Helpers ────────────────────────────────────────────────────────────────

function getNodeMeta() {
    const role = (process.env.NODE_ROLE || 'sn1').toLowerCase();
    const name = process.env.NODE_NAME || role.toUpperCase();
    const meta = ROLE_META[role] || { label: role.toUpperCase(), priority: '—', icon: '❔' };
    return { role, name, ...meta };
}

/** Post a JSON payload to the Discord webhook. */
function post(webhookUrl, payload) {
    const body = JSON.stringify(payload);
    try {
        const url = new URL(webhookUrl);
        const req = https.request(
            {
                hostname: url.hostname,
                path:     url.pathname + url.search,
                method:   'POST',
                headers: {
                    'Content-Type':   'application/json',
                    'Content-Length': Buffer.byteLength(body),
                },
            },
            (res) => {
                res.resume(); // drain so socket is released
                if (res.statusCode >= 400) {
                    console.error(`[WEBHOOK] Discord responded HTTP ${res.statusCode}`);
                }
            }
        );
        req.on('error', (err) => console.error('[WEBHOOK] Request error:', err.message));
        req.write(body);
        req.end();
    } catch (err) {
        console.error('[WEBHOOK] Failed to post embed:', err.message);
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Send a rich embed to the failover webhook channel.
 *
 * @param {object} opts
 * @param {string} opts.title        - Short event title (no emoji prefix needed)
 * @param {string} [opts.description]- One-sentence description shown under title
 * @param {'online'|'offline'|'standby'|'warning'|'info'} [opts.type='info']
 * @param {string} [opts.reason]     - Reason string shown as a full-width field
 * @param {string} [opts.fromNode]   - Name of the node that triggered this (e.g. sn1 returning)
 * @param {Array<{name,value,inline?}>} [opts.extraFields] - Any additional fields
 */
function send({ title, description = '', type = 'info', reason, fromNode, extraFields = [] }) {
    const webhookUrl = process.env.FAILOVER_WEBHOOK_URL;
    if (!webhookUrl) return;

    const { name, label, priority, icon } = getNodeMeta();
    const statusIcon = STATUS_ICONS[type] ?? STATUS_ICONS.info;
    const color      = COLORS[type]       ?? COLORS.info;
    const now        = Math.floor(Date.now() / 1000); // Unix seconds

    // ── Core identity fields (always shown, inline 3-col) ──────────────────
    const fields = [
        { name: `${icon}  Node ID`,  value: `\`${name}\``,   inline: true },
        { name: '🏷️  Role',          value: label,            inline: true },
        { name: '⚡  Priority',       value: priority,         inline: true },
    ];

    // ── Conditional fields ─────────────────────────────────────────────────
    if (type === 'online') {
        fields.push({ name: '⏱️  Active Since', value: `<t:${BOOT_UNIX}:R>  (<t:${BOOT_UNIX}:T>)`, inline: false });
    }

    if (type === 'offline' || type === 'standby') {
        fields.push({ name: '🕐  Time', value: `<t:${now}:F>`, inline: false });
    }

    if (fromNode) {
        fields.push({ name: '🔄  Triggered By', value: `\`${fromNode}\``, inline: true });
    }

    if (reason) {
        fields.push({ name: '📋  Reason', value: reason, inline: false });
    }

    fields.push(...extraFields);

    // ── Build embed ────────────────────────────────────────────────────────
    const embed = {
        author: {
            name:     'ShardNode Failover System',
            icon_url: 'https://cdn.discordapp.com/embed/avatars/0.png',
        },
        title:       `${statusIcon}  ${title}`,
        description: description || undefined,
        color,
        fields,
        footer: {
            text: `BOT_FAILOVER_ENABLED · role=${process.env.NODE_ROLE || 'sn1'}`,
        },
        timestamp: new Date().toISOString(),
    };

    post(webhookUrl, {
        username:   'ShardNode Monitor',
        avatar_url: 'https://cdn.discordapp.com/embed/avatars/0.png',
        embeds:     [embed],
    });
}

module.exports = { send, COLORS, STATUS_ICONS };
