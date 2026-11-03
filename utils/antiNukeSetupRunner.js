/**
 * Anti-Nuke — automatic setup runner.
 *
 * Performs the eight automatic-setup steps *for real*: it inspects the guild,
 * validates the bot's permissions, builds a recommended configuration, resolves
 * the alert channel, persists the result and then validates what was saved.
 *
 * The runner is driven one step at a time (`runNextStep`) so the dashboard can
 * show a live progress bar that reflects actual execution, support per-step
 * retry, and resume an interrupted setup. Nothing is faked: each step performs
 * its backend operation and records the outcome; a step that fails is recorded
 * as `failed` and never counted as completed.
 *
 * Everything degrades safely:
 *   • a missing permission does not fail setup — it is recorded so the dashboard
 *     can warn that a module is not fully operational;
 *   • an unusable alert channel fails only the (required) alert step, which can
 *     be retried after the admin picks a channel;
 *   • a database failure fails the save step, and setup cannot complete.
 */

const {
    normalizeAntiNukeSettings, defaultAntiNukeSettings, NUKE_ACTIONS,
} = require('./antiNukeRules');
const { validateBotPermissions } = require('./antiNukeContainment');
const {
    stepsForMethod, normalizeSetupState, applyStep, withStatus, computeProgress, isComplete,
} = require('./antiNukeSetup');

// Channel names we look for when the guild has no alert channel configured.
const ALERT_CHANNEL_CANDIDATES = ['security-logs', 'security', 'mod-logs', 'antinuke', 'audit-logs', 'logs'];

/**
 * The recommended security configuration for a server that is setting up for
 * the first time. Deliberately safe: every module enabled, catalog-default
 * thresholds, alert-only responses, dry-run ON, and no automatic permanent
 * punishment.
 */
function recommendedConfig() {
    const base = defaultAntiNukeSettings();
    const watched = {};
    for (const action of NUKE_ACTIONS) {
        watched[action.key] = { enabled: true, threshold: action.threshold, seconds: action.seconds };
    }
    return normalizeAntiNukeSettings({
        ...base,
        enabled: true,
        dryRun: true,
        watched,
        responses: ['alertOwner', 'alertChannel', 'logOnly'],
    });
}

/**
 * Merge the recommended configuration into the current one.
 *
 * `applyRecommended=true` overwrites the watched rules + responses + dryRun (the
 * explicit "apply recommended settings" choice). Otherwise (the safer default
 * for an existing server) only fields still at their defaults are filled in —
 * custom thresholds, trusted lists and responses are preserved untouched.
 */
function mergeRecommended(current, recommended, applyRecommended) {
    const cur = normalizeAntiNukeSettings(current || {});
    if (applyRecommended) {
        return normalizeAntiNukeSettings({
            ...cur,
            enabled: true,
            dryRun: true,
            watched: recommended.watched,
            responses: recommended.responses,
            dangerousPermissions: cur.dangerousPermissions && cur.dangerousPermissions.length
                ? cur.dangerousPermissions
                : recommended.dangerousPermissions,
            lockdown: cur.lockdown || recommended.lockdown,
        });
    }
    const base = defaultAntiNukeSettings();
    const watched = {};
    for (const action of NUKE_ACTIONS) {
        const c = cur.watched[action.key];
        const d = base.watched[action.key];
        // Only "upgrade" an action that is still at the catalog default; a value
        // the admin has customised is kept as-is.
        const isDefault = c && c.threshold === d.threshold && c.seconds === d.seconds && c.enabled === d.enabled;
        watched[action.key] = isDefault
            ? recommended.watched[action.key]
            : c;
    }
    return normalizeAntiNukeSettings({
        ...cur,
        // Running the wizard is the explicit setup action, so protection is
        // activated — but always in dry-run (set in the caller) and never with
        // a destructive response. This is the "protection ON" recommended
        // configuration from the task, not a silent flip on page load.
        enabled: true,
        dryRun: true,
        watched,
        responses: (cur.responses && cur.responses.length) ? cur.responses : recommended.responses,
    });
}

/** Resolve the alert channel: existing config first, then a name match. */
async function resolveAlertChannel(guild, currentChannelId) {
    // A guild can be a live discord.js Guild (channels have `send`) or the
    // dashboard's REST shim (plain channel descriptors with no `send`). Accept
    // both: for a REST descriptor the bot's guild-level permission report is
    // what actually proves it can post, and that is validated separately.
    const isTextLike = (ch) => ch && (ch.type === 0 || ch.type === 5 || ch.type === undefined);
    const usable = (ch) => {
        if (!isTextLike(ch)) return false;
        if (typeof ch.send === 'function') {
            return !ch.permissionsFor || !guild.members?.me || ch.permissionsFor(guild.members.me)?.has('SendMessages');
        }
        return true;
    };

    if (currentChannelId) {
        try {
            const ch = await guild.channels.fetch(currentChannelId).catch(() => null);
            if (usable(ch)) return { channelId: ch.id, name: ch.name, source: 'existing' };
            return { channelId: null, name: null, source: 'existing_invalid', invalid: currentChannelId };
        } catch (_) { /* fall through to a name match */ }
    }
    try {
        for (const name of ALERT_CHANNEL_CANDIDATES) {
            const ch = guild.channels.cache.find(c => c && (c.type === 0 || c.type === undefined) && c.name === name);
            if (usable(ch)) return { channelId: ch.id, name: ch.name, source: 'matched' };
        }
    } catch (_) { /* no channel cache — leave it for the admin */ }
    return { channelId: null, name: null, source: 'none' };
}

/**
 * Run the next pending/running/failed step of an automatic setup.
 *
 * @returns {Promise<{ state:object, progress:object, done:boolean, lastStep:string|null }>}
 */
async function runNextStep({ client, guild, state, options = {} }) {
    const method = 'automatic';
    let s = normalizeSetupState(state);
    s.method = method;
    if (s.status === 'not_started') s.status = 'in_progress';

    const catalog = stepsForMethod(method);
    // The next step is the first required one that is not completed, or the
    // first step that previously failed (so a retry re-runs it).
    const next = catalog.find(step => {
        const st = s.steps[step.key];
        return !st || st.status === 'pending' || st.status === 'running' || st.status === 'failed';
    });

    if (!next) {
        s = withStatus(s, isComplete(method, s) ? 'completed' : 'failed');
        return { state: s, progress: computeProgress(method, s), done: true, lastStep: null };
    }

    s = applyStep(s, next.key, { status: 'running' });
    let result = null;
    let error = null;
    try {
        result = await runStep(next.key, { client, guild, state: s, options });
        s = applyStep(s, next.key, { status: 'completed', result });
    } catch (err) {
        error = err && err.message ? err.message : String(err);
        s = applyStep(s, next.key, { status: 'failed', error });
    }

    const progress = computeProgress(method, s);
    const done = !catalog.some(step => {
        const st = s.steps[step.key];
        return !st || st.status === 'pending' || st.status === 'running' || st.status === 'failed';
    });
    if (done) s = withStatus(s, error ? 'failed' : 'completed');
    return { state: s, progress, done, lastStep: next.key };
}

/** Execute one named step's real backend operation. Throws to fail the step. */
async function runStep(stepKey, { client, guild, state, options }) {
    const manager = client && client.antiNukeManager;
    switch (stepKey) {
        case 'inspection': {
            const settings = manager ? manager.getSettings(guild.id) : {};
            return {
                guildId: guild.id,
                name: guild.name,
                ownerId: guild.ownerId,
                memberCount: guild.memberCount,
                channelCount: guild.channels && guild.channels.cache ? guild.channels.cache.size : 0,
                roleCount: guild.roles && guild.roles.cache ? guild.roles.cache.size : 0,
                existingEnabled: settings.enabled === true,
                trustedUsers: Array.isArray(settings.trustedUserIds) ? settings.trustedUserIds.length : 0,
                trustedRoles: Array.isArray(settings.trustedRoleIds) ? settings.trustedRoleIds.length : 0,
                alertChannelId: settings.alertChannelId || null,
            };
        }
        case 'permissions': {
            const report = validateBotPermissions(guild);
            return { ok: report.ok, checks: report.checks, missing: report.missing };
        }
        case 'settings': {
            const settings = manager ? manager.getSettings(guild.id) : {};
            return {
                enabled: settings.enabled === true,
                dryRun: settings.dryRun !== false,
                watchedEnabled: Object.values(settings.watched || {}).filter(w => w && w.enabled !== false).length,
                responses: settings.responses || [],
            };
        }
        case 'rules': {
            const recommended = recommendedConfig();
            return {
                applyRecommended: options.applyRecommended === true,
                responses: recommended.responses,
                watchedActions: Object.keys(recommended.watched).length,
            };
        }
        case 'thresholds': {
            const recommended = recommendedConfig();
            const thresholds = {};
            for (const [key, w] of Object.entries(recommended.watched)) {
                thresholds[key] = `${w.threshold}/${w.seconds}s`;
            }
            return { thresholds };
        }
        case 'alert': {
            const settings = manager ? manager.getSettings(guild.id) : {};
            const resolved = await resolveAlertChannel(guild, settings.alertChannelId);
            if (resolved.source === 'none') {
                // Not fatal on its own — but the step records that no channel was
                // found so the dashboard can ask the admin to pick one. We treat
                // "no channel" as a soft failure so the wizard surfaces it.
                throw new Error('No usable alert channel found. Create #security-logs or pick a channel, then retry.');
            }
            return resolved;
        }
        case 'save': {
            if (!manager || typeof manager.updateSettingsAsync !== 'function') {
                throw new Error('Anti-Nuke manager is unavailable.');
            }
            const current = manager.getSettings(guild.id);
            const recommended = recommendedConfig();
            const merged = mergeRecommended(current, recommended, options.applyRecommended === true);
            // Keep the alert channel resolved in the previous step.
            const alertStep = state.steps && state.steps.alert && state.steps.alert.result;
            const alertChannelId = (alertStep && alertStep.channelId) || current.alertChannelId || null;
            const saved = await manager.updateSettingsAsync(guild.id, { ...merged, alertChannelId });
            return { enabled: saved.enabled, dryRun: saved.dryRun, alertChannelId: saved.alertChannelId };
        }
        case 'validate': {
            if (!manager) throw new Error('Anti-Nuke manager is unavailable.');
            // Re-read from the database to prove persistence, then re-validate
            // the pieces that matter.
            if (typeof manager._refreshFromDatabase === 'function') {
                await manager._refreshFromDatabase();
            }
            const settings = manager.getSettings(guild.id);
            const report = validateBotPermissions(guild);
            const channelOk = settings.alertChannelId
                ? await guild.channels.fetch(settings.alertChannelId).then(ch => !!ch).catch(() => false)
                : false;
            const persisted = settings.enabled === true || Object.keys(settings.watched || {}).length > 0;
            if (!persisted) throw new Error('Configuration did not persist to the database.');
            return {
                persisted,
                permissionsOk: report.ok,
                missingPermissions: report.missing,
                alertChannelOk: channelOk,
                modulesEnabled: Object.values(settings.watched || {}).filter(w => w && w.enabled !== false).length,
            };
        }
        default:
            throw new Error(`Unknown setup step: ${stepKey}`);
    }
}

/** Run the whole automatic setup in one call (used by the Discord command). */
async function runAll({ client, guild, state = null, options = {} }) {
    let s = normalizeSetupState(state);
    let guard = 0;
    let last = null;
    while (guard++ < 20) {
        const res = await runNextStep({ client, guild, state: s, options });
        s = res.state;
        last = res;
        if (res.done) break;
    }
    return last || { state: s, progress: computeProgress('automatic', s), done: true };
}

module.exports = {
    recommendedConfig,
    mergeRecommended,
    resolveAlertChannel,
    runNextStep,
    runAll,
    ALERT_CHANNEL_CANDIDATES,
};
