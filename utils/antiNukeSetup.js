/**
 * Anti-Nuke — setup wizard state, step catalog and progress calculation.
 *
 * Shared by the dashboard (render + API) and the Discord `/antinuke setup`
 * command, so both interfaces describe the same steps and compute the same
 * percentage. Pure — no DB, no Discord — so it is directly testable and the
 * progress bar can never drift from the state it is drawn from.
 *
 * Progress is *derived from real step state*, never a timer: the client renders
 * whatever `computeProgress` reports for the persisted `setup_state`, and a step
 * only counts as completed once its backend operation actually succeeded.
 */

const AUTOMATIC_STEPS = [
    { key: 'inspection',  label: 'Inspecting server',          required: true, description: 'Read guild info, roles, channels and existing configuration.' },
    { key: 'permissions', label: 'Checking bot permissions',   required: true, description: 'Verify the permissions each protection module needs.' },
    { key: 'settings',    label: 'Loading existing settings',  required: true, description: 'Load the guild\'s current Anti-Nuke configuration.' },
    { key: 'rules',       label: 'Preparing security rules',   required: true, description: 'Select the recommended watched actions and responses.' },
    { key: 'thresholds',  label: 'Configuring detection thresholds', required: true, description: 'Apply safe initial thresholds per action.' },
    { key: 'alert',       label: 'Preparing alert channel',    required: true, description: 'Validate (or create) the security alert channel.' },
    { key: 'save',        label: 'Saving configuration',       required: true, description: 'Persist the recommended configuration to the database.' },
];

// The full automatic setup walkthrough presented by the dashboard. The first
// step REQUIRES `antinuke.setup`; the dashboard hides the whole wizard behind
// that permission, so the walkthrough itself carries no extra gate.
//
// The complete automatic walkthrough is 16 required steps: the 7 backend steps
// (AUTOMATIC_STEPS) plus these 9 walkthrough steps. `stepsForMethod('automatic')`
// concatenates the two, so `total` is always 16 and the bar can hold 100%.
//
// ORDER MATTERS: `apply` persists the confirmed configuration, and `validate`
// reloads and re-verifies it. `validate` therefore runs AFTER `apply` — when it
// ran before (as a naive concatenation of the two lists did) it always found
// nothing persisted and failed the whole walkthrough at step 8.
const AUTO_WALKTHROUGH_STEPS = [
    { key: 'restore',          label: 'Restoring prior progress',     required: true, description: 'Re-read the persisted setup state and resume where you left off.' },
    { key: 'confirm',          label: 'Reviewing proposed changes',   required: true, description: 'Show exactly what applying the recommended configuration would change.' },
    { key: 'apply',            label: 'Applying recommended settings', required: true, description: 'Apply the confirmed recommended configuration.' },
    { key: 'validate',         label: 'Final validation',             required: true, description: 'Reload and re-verify the saved configuration.' },
    { key: 'validateModules',  label: 'Validating protection modules', required: true, description: 'Verify each protection module can initialize and watch its actions.' },
    { key: 'botperms',         label: 'Re-validating bot permissions', required: true, description: 'Confirm the bot still holds every permission the modules need.' },
    { key: 'persist',          label: 'Persisting final setup status', required: true, description: 'Record the completed setup status and configuration version.' },
    { key: 'report',           label: 'Building completion report',    required: true, description: 'Assemble the setup summary for the owner.' },
    { key: 'finished',         label: 'Finished',                      required: true, description: 'Setup complete — protection is active.' },
];

const MANUAL_SECTIONS = [
    { key: 'general',  label: 'General Settings',             required: true, description: 'Enable Anti-Nuke and the master moderation settings.' },
    { key: 'channel',  label: 'Alert Channel',                required: true, description: 'Where security alerts are posted.' },
    { key: 'channels', label: 'Channel Protection',           required: true, description: 'Channel/category deletion, creation and updates.' },
    { key: 'role',     label: 'Role Protection',              required: true, description: 'Role deletion/creation and permission changes.' },
    { key: 'member',   label: 'Member Protection',            required: true, description: 'Mass bans, kicks and role changes.' },
    { key: 'webhook',  label: 'Webhook Protection',           required: true, description: 'Webhook creation, deletion and changes.' },
    { key: 'bot',      label: 'Bot Protection',               required: true, description: 'Untrusted bot additions and permission escalation.' },
    { key: 'server',   label: 'Server Settings Protection',   required: true, description: 'Sensitive server settings.' },
    { key: 'trustedUsers', label: 'Trusted Users',            required: false, description: 'Individual users exempt from Anti-Nuke.' },
    { key: 'trustedRoles', label: 'Trusted Roles',            required: false, description: 'Roles exempt from Anti-Nuke.' },
    { key: 'thresholds',label: 'Detection Thresholds',        required: true, description: 'How many actions within a window count as an attack.' },
    { key: 'responses', label: 'Automated Responses',         required: true, description: 'What happens when a threshold trips.' },
    { key: 'safety',    label: 'Dry Run & Safety',            required: true, description: 'Detection mode, lockdown policy and dangerous permissions.' },
    { key: 'review',    label: 'Review and Apply',            required: true, description: 'Review and save the configuration.' },
];

const STEP_STATUSES = ['pending', 'running', 'completed', 'failed', 'skipped'];

/** The step catalog for a setup method (automatic incl. the walkthrough). */
function stepsForMethod(method) {
    return method === 'manual' ? MANUAL_SECTIONS : [...AUTOMATIC_STEPS, ...AUTO_WALKTHROUGH_STEPS];
}

/** The 8 backend automatic steps (what a single `setup/step` run executes). */
function autoBackendSteps() {
    return AUTOMATIC_STEPS;
}

/** Default (empty) setup state for a guild. */
function defaultSetupState() {
    return {
        method: null,
        status: 'not_started',
        sessionId: null,
        currentStep: null,
        steps: {},
        lastError: null,
        initiatedBy: null,
        lastUpdatedBy: null,
        configVersion: 1,
        startedAt: null,
        lastUpdated: null,
        completedAt: null,
        version: 1,
    };
}

/** Normalize a persisted setup state into the canonical shape. */
function normalizeSetupState(raw = {}) {
    const base = defaultSetupState();
    const src = raw && typeof raw === 'object' ? raw : {};
    const method = src.method === 'manual' || src.method === 'automatic' ? src.method : null;
    const steps = {};
    if (src.steps && typeof src.steps === 'object') {
        for (const [key, val] of Object.entries(src.steps)) {
            if (!val || typeof val !== 'object') continue;
            steps[key] = {
                status: STEP_STATUSES.includes(val.status) ? val.status : 'pending',
                error: val.error ? String(val.error).slice(0, 500) : null,
                result: (val.result && typeof val.result === 'object') ? val.result : null,
                at: val.at || null,
            };
        }
    }
    return {
        method,
        status: ['not_started', 'in_progress', 'completed', 'failed'].includes(src.status) ? src.status : 'not_started',
        sessionId: src.sessionId ? String(src.sessionId).slice(0, 40) : null,
        currentStep: src.currentStep ? String(src.currentStep) : null,
        steps,
        lastError: src.lastError ? String(src.lastError).slice(0, 1000) : null,
        initiatedBy: src.initiatedBy ? String(src.initiatedBy) : null,
        lastUpdatedBy: src.lastUpdatedBy ? String(src.lastUpdatedBy) : null,
        configVersion: Number(src.configVersion) || base.configVersion,
        startedAt: src.startedAt || null,
        lastUpdated: src.lastUpdated || null,
        completedAt: src.completedAt || null,
        version: Number(src.version) || base.version,
    };
}

/**
 * Start a fresh setup session for a guild. `initiatedBy` records the acting
 * user so the wizard can show who started/resumed it.
 */
function newSetupSession(method, initiatedBy = null) {
    return withStatus(normalizeSetupState({
        method,
        sessionId: `ss_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
        version: 1,
        initiatedBy: initiatedBy ? String(initiatedBy) : null,
        lastUpdatedBy: initiatedBy ? String(initiatedBy) : null,
        startedAt: new Date().toISOString(),
    }), 'in_progress');
}

/**
 * Compute progress from real step state.
 *
 * Only REQUIRED steps count toward the denominator (an optional step that is
 * skipped never inflates or deflates the bar). `completed` counts required steps
 * whose status is `completed`; `failed` and `skipped` are reported separately
 * and never counted as completed.
 */
function computeProgress(method, state) {
    const catalog = stepsForMethod(method);
    const s = normalizeSetupState(state);
    const required = catalog.filter(st => st.required);
    let completed = 0, failed = 0, skipped = 0, running = 0, pending = 0;
    const perStep = catalog.map(step => {
        const st = s.steps[step.key] || { status: 'pending' };
        const status = st.status || 'pending';
        if (step.required) {
            if (status === 'completed') completed++;
            else if (status === 'failed') failed++;
            else if (status === 'skipped') skipped++;
            else if (status === 'running') running++;
            else pending++;
        } else if (status === 'completed') {
            // An optional step that is genuinely completed is still shown as
            // done, but it never changes the percentage.
            completed += 0;
        }
        return { key: step.key, label: step.label, required: step.required, description: step.description, status };
    });
    const total = required.length;
    const percent = total > 0 ? Math.round((completed / total) * 100) : 0;
    return {
        method: method || null,
        total,
        completed,
        failed,
        skipped,
        running,
        pending,
        remaining: Math.max(0, total - completed),
        percent,
        currentStep: s.currentStep,
        status: s.status,
        steps: perStep,
    };
}

/**
 * Apply a step result to a setup state (immutably). Used by the automatic
 * setup runner and the manual wizard save path. A failed step is recorded as
 * failed — it is never silently marked completed.
 */
function applyStep(state, stepKey, { status, error = null, result = null } = {}) {
    const s = normalizeSetupState(state);
    const prev = s.steps[stepKey] || { status: 'pending', error: null, result: null, at: null };
    s.steps[stepKey] = {
        status: STEP_STATUSES.includes(status) ? status : prev.status,
        error: error ? String(error).slice(0, 500) : (status === 'failed' ? prev.error : null),
        result: result || prev.result || null,
        at: new Date().toISOString(),
    };
    s.currentStep = stepKey;
    s.lastUpdated = new Date().toISOString();
    if (status === 'failed') s.lastError = error ? String(error).slice(0, 1000) : (s.lastError || null);
    if (status === 'completed' && prev.status === 'failed') s.lastError = null;
    return s;
}

/** Mark the whole setup as in-progress / completed / failed. */
function withStatus(state, status) {
    const s = normalizeSetupState(state);
    const allowed = ['not_started', 'in_progress', 'completed', 'failed'];
    if (!allowed.includes(status)) return s;
    s.status = status;
    s.lastUpdated = new Date().toISOString();
    if (status === 'completed') s.completedAt = s.completedAt || new Date().toISOString();
    if (status === 'in_progress' && !s.startedAt) s.startedAt = new Date().toISOString();
    return s;
}

/** Mark the acting user on the state (used by every setup mutation). */
function withUpdater(state, userId) {
    const s = normalizeSetupState(state);
    if (userId) {
        s.lastUpdatedBy = String(userId);
        if (!s.initiatedBy) s.initiatedBy = String(userId);
    }
    s.lastUpdated = new Date().toISOString();
    return s;
}

/** Is the setup complete (every required step completed, none failed)? */
function isComplete(method, state) {
    const p = computeProgress(method, state);
    return p.total > 0 && p.completed === p.total && p.failed === 0;
}

/**
 * Diff the recommended automatic configuration against the guild's current one,
 * so the dashboard can show what "apply recommended" would change and default
 * to preserving the admin's custom values.
 */
function diffRecommended(current = {}, recommended = {}) {
    const changes = [];
    for (const key of ['enabled', 'dryRun', 'alertChannelId']) {
        if ((current[key] ?? null) !== (recommended[key] ?? null)) {
            changes.push({ field: key, from: current[key] ?? null, to: recommended[key] ?? null });
        }
    }
    const curWatched = current.watched || {};
    for (const [actionKey, rec] of Object.entries(recommended.watched || {})) {
        const cur = curWatched[actionKey];
        if (!cur || cur.enabled !== rec.enabled || cur.threshold !== rec.threshold || cur.seconds !== rec.seconds) {
            changes.push({
                field: `watched.${actionKey}`,
                from: cur ? `${cur.enabled ? 'on' : 'off'} ${cur.threshold}/${cur.seconds}s` : 'default',
                to: `${rec.enabled ? 'on' : 'off'} ${rec.threshold}/${rec.seconds}s`,
            });
        }
    }
    return changes;
}

module.exports = {
    AUTOMATIC_STEPS,
    AUTO_WALKTHROUGH_STEPS,
    MANUAL_SECTIONS,
    STEP_STATUSES,
    stepsForMethod,
    autoBackendSteps,
    defaultSetupState,
    normalizeSetupState,
    newSetupSession,
    computeProgress,
    applyStep,
    withStatus,
    withUpdater,
    isComplete,
    diffRecommended,
};
