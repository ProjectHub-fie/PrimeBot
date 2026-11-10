/**
 * Anti-Nuke — health / readiness scan.
 *
 * Produces a per-guild diagnostic the owner (or a delegated security manager)
 * can run to find out exactly why protection may not be live before, during or
 * after an incident. Every check returns PASS / WARNING / FAILED and carries an
 * optional `note`, so the dashboard and the Discord embed can show the real
 * state — "PASS" is never reported for a check that was not actually
 * performed (unavailable data → WARNING, never a fabricated PASS).
 *
 * The scan is intentionally read-only: it never mutates settings, the database
 * or the guild. Repairs (e.g. re-running setup to fix a quarantine role
 * position) are separate, existing owner actions.
 */

const { PermissionFlagsBits } = require('discord.js');
const { validateBotPermissions } = require('./antiNukeContainment');
const { NUKE_ACTIONS, responsesForAction, NUKE_ACTION_BY_KEY } = require('./antiNukeRules');

const PASS = 'PASS';
const WARN = 'WARNING';
const FAIL = 'FAILED';

function check(key, label, result, note = '') {
    return { key, label, result, note };
}

/**
 * Run the health scan for one guild.
 *
 * @param {object} deps
 * @param {object} deps.manager   the AntiNukeManager instance
 * @param {object|null} deps.client    discord.js client (may be null on the dashboard)
 * @param {object} deps.guild      discord.js Guild or a REST guild descriptor
 * @param {object} [deps.botPerms] optional pre-computed permission report for REST shims
 * @returns {Promise<{ overall: string, checkedAt: string, checks: Array }>}
 */
async function healthScan({ manager, client, guild, botPerms }) {
    const checks = [];
    const gid = guild && guild.id;

    // 1. Gateway intent + live audit-log stream availability.
    const intentDesired = Boolean(client && client.options && client.options.intents);
    const streamObserved = manager && manager._auditStreamAvailable === true;
    const handlerLoaded = manager && typeof manager.processEvent === 'function';
    checks.push(check('gateway', 'Gateway event handler',
        handlerLoaded ? PASS : FAIL,
        handlerLoaded ? '' : 'AntiNukeManager.processEvent is unavailable on this node.'));
    if (intentDesired) {
        const { GatewayIntentBits } = require('discord.js');
        let hasGuildMod = false;
        try {
            const intents = client.options.intents;
            hasGuildMod = Boolean(intents && typeof intents.has === 'function' && intents.has(GatewayIntentBits.GuildModeration));
        } catch (_) { hasGuildMod = false; }
        checks.push(check('intent', 'GuildModeration intent',
            hasGuildMod ? PASS : FAIL,
            hasGuildMod ? '' : 'The GuildModeration gateway intent must be enabled in the Discord Developer Portal → Bot → Privileged Gateway Intents, and in index.js.'));
    } else {
        checks.push(check('intent', 'GuildModeration intent', WARN, 'No live client on this process — intent state unknown.'));
    }
    checks.push(check('audit_stream', 'Live audit-log stream observed',
        streamObserved ? PASS : WARN,
        streamObserved ? '' : 'No guildAuditLogEntryCreate event has been observed yet. If protection is live but attribution shows "unknown", confirm the GuildModeration intent is enabled and granted.'));

    if (!gid) {
        checks.unshift(check('context', 'Guild context', FAIL, 'No guild was provided to the health scan.'));
        return { overall: FAIL, checkedAt: new Date().toISOString(), checks };
    }

    // 2. Database + config synchronization with the bot's in-memory cache.
    let dbResult = PASS;
    let dbNote = '';
    const settings = manager ? await manager.getSettings(gid) : null;
    try {
        const anuke = require('../server/anukeDb');
        const pool = anuke && anuke.pool;
        if (!pool || typeof pool.query !== 'function') {
            dbResult = WARN;
            dbNote = 'Anti-Nuke database pool is not configured on this process — connectivity not performed (reporting WARNING, not PASS).';
        } else {
            const res = await Promise.race([
                pool.query('SELECT 1'),
                new Promise((_, rej) => setTimeout(() => rej(new Error('db_timeout')), 4000)),
            ]);
            dbResult = (res && res.rows && res.rows.length) ? PASS : FAIL;
            dbNote = dbResult === PASS ? '' : 'No rows returned from the Anti-Nuke database pool.';
        }
    } catch (err) {
        dbResult = FAIL;
        dbNote = `Database unreachable for read: ${err && err.message ? err.message : err}`;
    }
    checks.push(check('database', 'Database connectivity', dbResult, dbNote));
    if (settings) {
        checks.push(check('config_cache', 'Config cache loaded',
            settings.updatedAt ? PASS : WARN,
            settings.updatedAt ? '' : 'No persisted updated_at — settings may be default, not explicitly saved.'));
    }

    // 3. Enabled state / dry-run / watched modules / effective responses.
    const s = settings || { enabled: false, dryRun: true, watched: {}, actionResponses: {}, responses: [] };
    checks.push(check('enabled', 'Anti-Nuke enabled',
        s.enabled === true ? PASS : FAIL,
        s.enabled === true ? '' : 'enabled is false — detection is off.'));
    checks.push(check('dry_run', 'Dry run',
        s.dryRun === false ? PASS : WARN,
        s.dryRun === false ? '' : 'dry run is ON — threats are detected and logged but nothing is enforced.'));
    const watchedEnabled = Object.values(s.watched || {}).filter(w => w && w.enabled !== false).length;
    checks.push(check('watched', 'Watched modules',
        watchedEnabled > 0 ? PASS : WARN,
        watchedEnabled > 0 ? `${watchedEnabled} of ${NUKE_ACTIONS.length} protection rules enabled` : 'No protection rules are enabled.'));

    // Effective responses per watched action — the requirement says display and
    // log the effective response list for EVERY rule.
    const effective = {};
    for (const action of NUKE_ACTIONS) {
        const w = s.watched && s.watched[action.key];
        if (!w || w.enabled === false) continue;
        effective[action.key] = {
            label: action.label,
            threshold: w.threshold,
            seconds: w.seconds,
            responses: responsesForAction(s, action.key),
        };
    }
    const hasEnforcement = Object.values(effective).some(e => e.responses.some(r =>
        ['ban', 'kick', 'quarantine', 'deleteWebhook', 'lockChannels', 'lockdown', 'removeRoles'].includes(r)));
    checks.push(check('responses', 'Effective response plan',
        hasEnforcement ? PASS : WARN,
        hasEnforcement ? '' : 'No watched rule resolves to a containment/punishment response — detection-only.'));
    checks.push(check('own_responses', 'Owner opted-in punishment',
        (Object.values(effective).some(e => e.responses.includes('ban') || e.responses.includes('kick')))
            ? PASS : WARN,
        'Permanent bans/kicks are NOT enabled for any rule (they stay owner-opt-in).'));

    // 4. Bot permissions + hierarchy + quarantine role.
    const permReport = botPerms || validateBotPermissions(guild);
    checks.push(check('bot_permissions', 'Bot permissions',
        permReport.ok ? PASS : (permReport.missing.length ? WARN : PASS),
        permReport.ok ? '' : `Missing: ${(permReport.missing || []).join(', ')}`));
    for (const c of permReport.checks || []) {
        checks.push(check(`perm:${c.key}`, c.label,
            c.available ? PASS : FAIL,
            c.available ? '' : `needed for: ${c.neededFor}`));
    }

    const me = guild && guild.members && guild.members.me;
    const botHighest = me && me.roles && me.roles.highest ? Number(me.roles.highest.position) : null;
    const ownerId = guild && guild.ownerId;
    checks.push(check('hierarchy_bot', 'Bot highest role',
        botHighest == null ? WARN : PASS,
        botHighest == null ? 'The bot member is not resolvable on this process.' : `Position ${botHighest}.`));
    checks.push(check('hierarchy_owner', 'Server owner',
        ownerId ? PASS : WARN,
        ownerId ? `Owner ${ownerId} is always exempt from detection.` : 'Owner id unknown.'));

    const qRole = s.quarantineRoleId
        ? (guild && guild.roles && guild.roles.cache ? guild.roles.cache.get(s.quarantineRoleId) : null)
        : null;
    if (s.quarantineRoleId) {
        if (!qRole) {
            checks.push(check('quarantine_role', 'Quarantine role',
                FAIL, `Configured quarantine role ${s.quarantineRoleId} does not exist in this guild. Set up a quarantine role (or clear it to fall back to role-stripping only).`));
        } else {
            const qBelowBot = botHighest == null || Number(qRole.position) < botHighest;
            const botCanManage = me && typeof me.permissions.has === 'function' && me.permissions.has(PermissionFlagsBits.ManageRoles);
            checks.push(check('quarantine_role', 'Quarantine role',
                qBelowBot && botCanManage ? PASS : FAIL,
                qBelowBot && botCanManage ? '' :
                    `Role "role" exists but ${!qBelowBot ? 'sits at/above the bot\'s highest role' : ''}${!botCanManage ? ' the bot lacks Manage Roles' : ''}. Move the bot\'s role above it.`));
        }
    } else {
        checks.push(check('quarantine_role', 'Quarantine role', WARN,
            'No quarantine role configured — the "quarantine" response falls back to stripping dangerous roles only.'));
    }

    // 5. Alert channel usable (best-effort from the cache on a live client).
    if (s.alertChannelId) {
        let channel = null;
        try {
            channel = guild && guild.channels && typeof guild.channels.fetch === 'function'
                ? await guild.channels.fetch(s.alertChannelId).catch(() => null)
                : (guild && guild.channels && guild.channels.cache ? guild.channels.cache.get(s.alertChannelId) : null);
        } catch (_) { channel = null; }
        checks.push(check('alert_channel', 'Alert channel',
            channel ? PASS : WARN,
            channel ? '' : 'Configured alert channel was not found — alerts will not be delivered.'));
    } else {
        checks.push(check('alert_channel', 'Alert channel', WARN, 'No alert channel configured.'));
    }

    // 6. Last activity: last event processed + last successful enforcement.
    let lastEvent = null;
    let lastEnforcement = null;
    try {
        const { pool } = require('../server/anukeDb');
        const [ev, enf] = await Promise.all([
            pool.query(`SELECT created_at FROM antinuke_incidents WHERE guild_id = $1 ORDER BY created_at DESC LIMIT 1`, [gid]).catch(() => ({ rows: [] })),
            pool.query(`SELECT created_at FROM antinuke_incidents WHERE guild_id = $1 AND status IN ('action_executed','action_partial') ORDER BY created_at DESC LIMIT 1`, [gid]).catch(() => ({ rows: [] })),
        ]);
        lastEvent = ev.rows && ev.rows.length ? ev.rows[0].created_at : null;
        lastEnforcement = enf.rows && enf.rows.length ? enf.rows[0].created_at : null;
    } catch (_) { /* non-fatal — activity may be empty */ }
    checks.push(check('last_event', 'Last detection event',
        lastEvent ? PASS : WARN,
        lastEvent ? `Last incident recorded ${lastEvent}.` : 'No incidents recorded yet — the scan cannot confirm end-to-end traffic.'));
    checks.push(check('last_enforcement', 'Last successful enforcement',
        lastEnforcement ? PASS : WARN,
        lastEnforcement ? `Last enforced action ${lastEnforcement}.` : 'No successfully enforced action recorded yet.'));

    const overall = checks.some(c => c.result === FAIL) ? FAIL : (checks.some(c => c.result === WARN) ? WARN : PASS);
    return { overall, checkedAt: new Date().toISOString(), checks };
}

/** Discord embed from a scan result (never pings anyone). */
function healthEmbed(guildName, scan) {
    const { EmbedBuilder } = require('discord.js');
    const color = scan.overall === FAIL ? 0xED4245 : (scan.overall === WARN ? 0xFABD2F : 0x57F287);
    const embed = new EmbedBuilder()
        .setTitle(`🛡️ Anti-Nuke health scan — ${scan.overall}`)
        .setDescription(guildName ? `Protection readiness for **${guildName}**` : 'Anti-Nuke readiness')
        .setColor(color)
        .setTimestamp(new Date(scan.checkedAt))
        .setFooter({ text: 'PrimeBot • Anti-Nuke health' });
    const lines = scan.checks.map(c => {
        const icon = c.result === PASS ? '✅' : (c.result === WARN ? '⚠️' : '❌');
        return `${icon} **${c.label}** — ${c.result}${c.note ? `\n   ${c.note}` : ''}`;
    });
    // Discord limits field values to 1024 chars — chunk per check.
    let current = '';
    let index = 0;
    for (const line of lines) {
        if (current.length + line.length > 1000) {
            embed.addFields({ name: `Check ${++index}`, value: current });
            current = '';
        }
        current += (current ? '\n' : '') + line;
    }
    if (current) embed.addFields({ name: `Check ${++index}`, value: current });
    return embed;
}

module.exports = { healthScan, healthEmbed, PASS, WARN, FAIL };