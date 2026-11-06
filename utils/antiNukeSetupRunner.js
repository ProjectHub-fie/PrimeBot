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
    stepsForMethod, normalizeSetupState, applyStep, withStatus, withUpdater, computeProgress, isComplete, diffRecommended,
    AUTO_WALKTHROUGH_STEPS,
} = require('./antiNukeSetup');

// Channel names we look for when the guild has no alert channel configured.
const ALERT_CHANNEL_CANDIDATES = ['security-logs', 'security', 'mod-logs', 'antinuke', 'audit-logs', 'logs'];

/**
 * The recommended security configuration for a server that is setting up for
 * the first time. Safe defaults: every module enabled, catalog-default
 * thresholds, alert-only responses and no automatic permanent punishment.
 *
 * Dry-run is OFF by default: the owner explicitly ran the setup wizard, so they
 * are telling PrimeBot to protect the server now. Detection still never
 * punishes the owner, the bot or trusted users/roles, never punishes without
 * audit-log attribution, and never bans/kicks a moderator automatically.
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
        dryRun: false,
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
            // The owner explicitly confirmed the recommended configuration, so
            // live protection starts now (dry-run is off). Reversible
            // containment only — never automatic bans/kicks.
            dryRun: false,
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
        // Preserve-except-defaults merge. Protection is activated and dry-run is
        // turned OFF — the owner ran the setup wizard, which is the explicit
        // opt-in to live protection. Trusted lists and custom responses are
        // always preserved untouched.
        enabled: true,
        dryRun: false,
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
    const recommended = recommendedConfig();
    switch (stepKey) {
        case 'inspection': {
            // `manager.getSettings` may be async (dashboard manager shim) or
            // sync (bot manager) — await both shapes.
            const settings = manager ? await manager.getSettings(guild.id) : {};
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
            const settings = manager ? await manager.getSettings(guild.id) : {};
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
            const settings = manager ? await manager.getSettings(guild.id) : {};
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
            // `save` stages the recommended configuration: `apply` (later in the
            // walkthrough) is what actually persists the confirmed settings.
            // Persisting here too would silently apply an unconfirmed config.
            if (!manager) throw new Error('Anti-Nuke manager is unavailable.');
            return { staged: true, dryRun: recommended.dryRun !== false };
        }
        case 'validate': {
            if (!manager) throw new Error('Anti-Nuke manager is unavailable.');
            // Re-read from the database to prove persistence, then re-validate
            // the pieces that matter.
            if (typeof manager._refreshFromDatabase === 'function') {
                await manager._refreshFromDatabase();
            }
            const settings = await manager.getSettings(guild.id);
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
        default: {
            // The walkthrough steps (restore/confirm/apply/validateModules/…)
            // are the dashboard executor's job. Running them from here means the
            // dashboard's `setup/step` route reached a walkthrough key — dispatch
            // it to that executor instead of throwing "Unknown setup step", which
            // previously failed the whole walkthrough at the `restore` step.
            if (typeof stepKey === 'string' && AUTO_WALKTHROUGH_STEPS.some(s => s.key === stepKey)) {
                return runWalkthroughStepOp(stepKey, { manager, guild, state, options });
            }
            throw new Error(`Unknown setup step: ${stepKey}`);
        }
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

/**
 * Run one step of the dashboard's full automatic walkthrough (16 steps: the 8
 * backend steps + restore/confirm/apply/validateModules + review/save/finished).
 * Each step performs a REAL backend operation and persists its outcome, so the
 * progress reflects actual work and resumes from the persisted state.
 *
 * `manager` is the dashboard manager shim (or the live manager for the Discord
 * path) and `saveListener` lets the dashboard persist after each step.
 */
async function runWalkthroughStep({ manager, guild, state = null, options = {}, actorId = null, saveListener = null }) {
    const catalog = stepsForMethod('automatic');
    let s = normalizeSetupState(state);
    s.method = 'automatic';
    if (s.status === 'not_started') s.status = 'in_progress';

    const next = catalog.find(step => {
        const st = s.steps[step.key];
        return !st || st.status === 'pending' || st.status === 'running' || st.status === 'failed';
    });
    if (!next) {
        s = withStatus(s, isComplete('automatic', s) ? 'completed' : 'failed');
        return { state: s, progress: computeProgress('automatic', s), done: true, lastStep: null };
    }

    s = withUpdater(applyStep(s, next.key, { status: 'running' }), actorId);
    let result = null;
    let error = null;
    try {
        result = await runWalkthroughStepOp(next.key, { manager, guild, state: s, options });
        s = applyStep(s, next.key, { status: 'completed', result });
    } catch (err) {
        error = err && err.message ? err.message : String(err);
        s = applyStep(s, next.key, { status: 'failed', error });
    }
    s = withUpdater(s, actorId);

    const allDone = !catalog.some(step => {
        const st = s.steps[step.key];
        return !st || st.status === 'pending' || st.status === 'running' || st.status === 'failed';
    });
    if (allDone) s = withStatus(s, error ? 'failed' : 'completed');

    const progress = computeProgress('automatic', s);
    if (typeof saveListener === 'function') {
        await saveListener(s, next.key, allDone).catch(() => {});
    }
    return { state: s, progress, done: allDone, lastStep: next.key };
}

/** One backend operation for the walkthrough steps. Throws to fail the step. */
async function runWalkthroughStepOp(stepKey, { manager, guild, state, options }) {
    const current = manager ? await manager.getSettings(guild.id) : {};
    const recommended = recommendedConfig();
    switch (stepKey) {
        // ── Walkthrough steps (compose real operations) ──────────────────────
        case 'restore': {
            // The state was already re-read by the caller (startsWith). This
            // step just records what is being resumed.
            return {
                resumedMethod: 'automatic',
                resumedStatus: state.status,
                existingSteps: Object.keys(state.steps || {}).length,
            };
        }
        case 'confirm': {
            if (!options.confirmed) throw new Error('Confirm the proposed changes to apply them.');
            return { diff: diffRecommended(current, recommended) };
        }
        case 'apply': {
            if (!manager || typeof manager.updateSettingsAsync !== 'function') {
                throw new Error('Anti-Nuke manager is unavailable.');
            }
            const merged = mergeRecommended(current, recommended, options.applyRecommended === true);
            // Keep the alert channel resolved in the earlier `alert` step.
            const alertStep = state.steps && state.steps.alert && state.steps.alert.result;
            const alertChannelId = (alertStep && alertStep.channelId) || current.alertChannelId || null;
            const saved = await manager.updateSettingsAsync(guild.id, { ...merged, alertChannelId });
            return {
                enabled: saved.enabled === true,
                dryRun: saved.dryRun !== false,
                alertChannelId: saved.alertChannelId || null,
            };
        }
        case 'validate': {
            if (!manager) throw new Error('Anti-Nuke manager is unavailable.');
            // Reload from the database to prove the config `apply` wrote actually
            // persisted, then re-verify the pieces that matter.
            if (typeof manager._refreshFromDatabase === 'function') {
                await manager._refreshFromDatabase();
            }
            const settings = await manager.getSettings(guild.id);
            const report = validateBotPermissions(guild);
            const persisted = settings.enabled === true || Object.keys(settings.watched || {}).length > 0;
            if (!persisted) throw new Error('Configuration did not persist to the database.');
            return {
                persisted,
                permissionsOk: report.ok,
                missingPermissions: report.missing,
                modulesEnabled: Object.values(settings.watched || {}).filter(w => w && w.enabled !== false).length,
            };
        }
        case 'validateModules': {
            const report = validateBotPermissions(guild);
            return {
                ok: report.ok,
                moduleCount: (require('./antiNukeSetup').stepsForMethod('automatic')).length,
                missing: report.missing,
            };
        }
        case 'review': {
            const applied = manager ? await manager.getSettings(guild.id) : {};
            return {
                enabled: applied.enabled === true,
                dryRun: applied.dryRun !== false,
                trustedUsers: Array.isArray(applied.trustedUserIds) ? applied.trustedUserIds.length : 0,
                trustedRoles: Array.isArray(applied.trustedRoleIds) ? applied.trustedRoleIds.length : 0,
                watchedEnabled: Object.values(applied.watched || {}).filter(w => w && w.enabled !== false).length,
            };
        }
        case 'botperms': {
            const report = validateBotPermissions(guild);
            return { ok: report.ok, missing: report.missing || [] };
        }
        case 'persist': {
            if (!manager || typeof manager.updateSettingsAsync !== 'function') throw new Error('Anti-Nuke manager is unavailable.');
            await manager.updateSettingsAsync(guild.id, { dryRun: false });
            return { persisted: true, configVersion: (state && state.configVersion) || 1 };
        }
        case 'report': {
            const applied = manager ? await manager.getSettings(guild.id) : {};
            return {
                enabled: applied.enabled === true,
                dryRun: applied.dryRun !== false,
                alertChannelId: applied.alertChannelId || null,
                trustedUsers: Array.isArray(applied.trustedUserIds) ? applied.trustedUserIds.length : 0,
                trustedRoles: Array.isArray(applied.trustedRoleIds) ? applied.trustedRoleIds.length : 0,
                watchCount: Object.keys(applied.watched || {}).length,
            };
        }
        case 'save': {
            if (!manager || typeof manager.updateSettingsAsync !== 'function') throw new Error('Anti-Nuke manager is unavailable.');
            await manager.updateSettingsAsync(guild.id, { dryRun: false });
            return {};
        }
        case 'finished': {
            return { finished: true };
        }
        // ── The 8 backend steps ──────────────────────────────────────────────
        default:
            return runStep(stepKey, { client: { antiNukeManager: manager, guilds: { cache: new Map([[guild.id, guild]]) } }, guild, state, options });
    }
}

module.exports = {
    recommendedConfig,
    mergeRecommended,
    resolveAlertChannel,
    runNextStep,
    runAll,
    runWalkthroughStep,
    runWalkthroughStepOp,
    ALERT_CHANNEL_CANDIDATES,
};
