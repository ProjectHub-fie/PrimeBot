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
    { key: 'inspection',  label: 'Inspecting server',       required: true,  description: 'Read guild info, roles, channels and existing configuration.' },
    { key: 'permissions', label: 'Checking bot permissions', required: true, description: 'Verify the permissions each protection module needs.' },
    { key: 'settings',    label: 'Loading existing settings', required: true, description: 'Load the guild\'s current Anti-Nuke configuration.' },
    { key: 'rules',       label: 'Preparing security rules',  required: true, description: 'Select the recommended watched actions and responses.' },
    { key: 'thresholds',  label: 'Configuring detection thresholds', required: true, description: 'Apply safe initial thresholds per action.' },
    { key: 'alert',       label: 'Preparing alert channel',   required: true, description: 'Validate (or create) the security alert channel.' },
    { key: 'save',        label: 'Saving configuration',      required: true, description: 'Persist the configuration to the database.' },
    { key: 'validate',    label: 'Final validation',          required: true, description: 'Reload and re-verify the saved configuration.' },
];

const MANUAL_SECTIONS = [
    { key: 'general',  label: 'General',                 required: true, description: 'Enable Anti-Nuke, dry-run and the alert channel.' },
    { key: 'channel',  label: 'Channel Protection',      required: true, description: 'Channel/category deletion, creation and updates.' },
    { key: 'role',     label: 'Role Protection',         required: true, description: 'Role deletion/creation and permission changes.' },
    { key: 'member',   label: 'Member Protection',       required: true, description: 'Mass bans, kicks and role changes.' },
    { key: 'webhook',  label: 'Webhook Protection',      required: true, description: 'Webhook creation, deletion and changes.' },
    { key: 'bot',      label: 'Bot Protection',          required: true, description: 'Untrusted bot additions and permission escalation.' },
    { key: 'server',   label: 'Server Protection',       required: true, description: 'Sensitive server settings.' },
    { key: 'trust',    label: 'Trusted Users & Roles',   required: false, description: 'Users/roles exempt from Anti-Nuke.' },
    { key: 'response', label: 'Response Configuration',  required: true, description: 'Alerting, containment and lockdown behaviour.' },
    { key: 'review',   label: 'Final Review',            required: true, description: 'Review and save the configuration.' },
];

const STEP_STATUSES = ['pending', 'running', 'completed', 'failed', 'skipped'];

/** The step catalog for a setup method. */
function stepsForMethod(method) {
    return method === 'manual' ? MANUAL_SECTIONS : AUTOMATIC_STEPS;
}

/** Default (empty) setup state for a guild. */
function defaultSetupState() {
    return {
        method: null,
        status: 'not_started',
        currentStep: null,
        steps: {},
        lastUpdated: null,
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
        currentStep: src.currentStep ? String(src.currentStep) : null,
        steps,
        lastUpdated: src.lastUpdated || null,
        version: Number(src.version) || base.version,
    };
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
    return s;
}

/** Mark the whole setup as in-progress / completed / failed. */
function withStatus(state, status) {
    const s = normalizeSetupState(state);
    s.status = ['not_started', 'in_progress', 'completed', 'failed'].includes(status) ? status : s.status;
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
    MANUAL_SECTIONS,
    STEP_STATUSES,
    stepsForMethod,
    defaultSetupState,
    normalizeSetupState,
    computeProgress,
    applyStep,
    withStatus,
    isComplete,
    diffRecommended,
};
