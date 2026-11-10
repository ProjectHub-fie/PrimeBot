/* Anti-Nuke dashboard client.
 *
 * Serves three views rendered server-side by dashboard/render/antinuke-page.js:
 *   • setup   — the Automatic/Manual chooser + live progress panel
 *   • wizard  — the manual setup wizard (10 sections, resumable)
 *   • console — the protection console (modules, responses, trust, lockdown,
 *               security activity)
 *
 * All progress is derived from the persisted setup state returned by the API —
 * never a timer. Every mutation is confirmed by a toast; dangerous actions
 * (lockdown, reset) ask for confirmation first.
 */

(function () {
  'use strict';

  var GUILD_ID = window.guildData && window.guildData.guildId;
  if (!GUILD_ID) return;

  var ACCESS = window.__ANTINUKE_ACCESS || { role: 'none', level: 4, isOwner: false, permissions: [] };
  var ACTIONS = window.__ANTINUKE_ACTIONS || [];
  var MODULES = window.__ANTINUKE_MODULES || [];
  var SETTINGS = window.__ANTINUKE_SETTINGS || {};
  var SETUP = window.__ANTINUKE_SETUP || { status: 'not_started' };
  var VIEW = window.__ANTINUKE_VIEW || 'setup';
  // Shared with the server-rendered page: every permission id + preset catalog.
  var PERMS = window.__ANTINUKE_PERMISSION_CATALOG || { permissions: [], groups: [], presets: [], levels: {} };
  var PERM_BY_ID = {};
  (PERMS.permissions || []).forEach(function (p) { PERM_BY_ID[p.id] = p; });

  function hasPerm(id) {
    return ACCESS.isOwner || (ACCESS.permissions || []).indexOf(id) >= 0;
  }

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var esc = window.esc || function (s) { return String(s == null ? '' : s); };
  var svg = window.svgIcon || function () { return ''; };

  function toast(msg, type) { if (window.toast) window.toast(msg, type); else console.log(msg); }

  function api(path, opts) {
    return fetch(path, Object.assign({
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    }, opts || {})).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data && data.error ? data.error : ('HTTP ' + res.status));
        return data;
      });
    });
  }

  // ── Step rendering (shared by setup + wizard) ─────────────────────────────

  function stepIconHTML(status) {
    switch (status) {
      case 'completed': return svg('check');
      case 'running': return '<span class="an-step-spin"></span>';
      case 'failed': return svg('x');
      case 'skipped': return svg('minus');
      default: return svg('clock');
    }
  }

  function renderStepList(el, steps) {
    if (!el) return;
    el.innerHTML = (steps || []).map(function (step) {
      var cls = 'an-step an-step-' + esc(step.status);
      var opt = step.required ? '' : ' <span class="an-step-opt">optional</span>';
      return '<li class="' + cls + '" data-step="' + esc(step.key) + '">' +
        '<span class="an-step-icon">' + stepIconHTML(step.status) + '</span>' +
        '<span class="an-step-label">' + esc(step.label) + opt + '</span>' +
        '<span class="an-step-status">' + esc(step.status) + '</span>' +
        '</li>';
    }).join('');
  }

  function statusLabel(status) {
    switch (status) {
      case 'completed': return 'Completed';
      case 'in_progress': return 'In progress';
      case 'failed': return 'Failed — needs attention';
      default: return 'Not started';
    }
  }

  function flagsHTML(p) {
    var chips = [];
    if (p.failed > 0) chips.push('<span class="an-flag an-flag-failed">' + svg('x') + ' ' + p.failed + ' failed</span>');
    if (p.skipped > 0) chips.push('<span class="an-flag an-flag-skipped">' + svg('minus') + ' ' + p.skipped + ' skipped</span>');
    if (p.remaining > 0) chips.push('<span class="an-flag">' + svg('clock') + ' ' + p.remaining + ' remaining</span>');
    if (p.running > 0) chips.push('<span class="an-flag an-flag-running"><span class="an-step-spin"></span> running</span>');
    return chips.join('');
  }

  /* Render a progress object into the shared progress card. Both the automatic
   * chooser and the manual wizard use this — the card markup is identical, so a
   * percentage can never be shown one way in one view and differently in the
   * other. Percent is clamped to 0-100 and always reflects real backend state. */
  function renderProgress(progress) {
    if (!progress) return;
    var pct = Math.max(0, Math.min(100, Number(progress.percent) || 0));

    var fill = $('#an-progress-fill');
    if (fill) fill.style.width = pct + '%';

    var track = $('#an-progress-track');
    if (track) track.setAttribute('aria-valuenow', String(pct));

    var meta = $('#an-progress-meta');
    if (meta) {
      meta.innerHTML = '<strong>' + pct + '%</strong> · ' +
        (progress.completed || 0) + ' of ' + (progress.total || 0) + ' required steps completed';
    }

    var status = $('#an-progress-status');
    if (status) {
      var st = progress.status || 'in_progress';
      status.className = 'an-progress-status an-progress-status-' + st;
      status.textContent = statusLabel(st);
    }

    var flags = $('#an-progress-flags');
    if (flags) flags.innerHTML = flagsHTML(progress);

    renderStepList($('#an-step-list'), progress.steps);
  }

  /** Replace the whole progress card with a loading/error message. */
  function progressMessage(kind, text) {
    var card = $('#an-progress-card');
    if (!card) return;
    var fill = $('#an-progress-fill');
    if (kind === 'loading') {
      card.setAttribute('aria-busy', 'true');
      if (fill) fill.style.width = '0%';
      var meta = $('#an-progress-meta');
      if (meta) meta.innerHTML = '<span class="an-muted">' + esc(text) + '</span>';
      return;
    }
    // error
    card.setAttribute('aria-busy', 'false');
    var m = $('#an-progress-meta');
    if (m) m.innerHTML = '<span class="an-bad">' + esc(text) + '</span>';
  }

  // ── Setup chooser ─────────────────────────────────────────────────────────

  function initSetupView() {
    $$('.an-setup-start').forEach(function (btn) {
      btn.addEventListener('click', function () { startSetup(btn.getAttribute('data-method')); });
    });
    var resume = $('#an-resume-setup');
    if (resume) resume.addEventListener('click', function () { resumeSetup(); });
    var reset = $('#an-reset-setup');
    if (reset) reset.addEventListener('click', function () { resetSetup(); });
    // Load the persisted setup state on page load (refresh / return / resume).
    loadSetupState();
  }

  /* Fetch the persisted setup state so a refresh or a return to the page shows
   * the REAL progress (never a stale in-memory value). Shows a loading state
   * while fetching and an error state if it cannot be loaded. */
  function loadSetupState() {
    // The server already rendered the persisted progress, so only show the
    // loading state when there is genuinely nothing on screen yet (avoids a
    // flash of "Loading…" over real data).
    var list = $('#an-step-list');
    if (!list || !list.children.length) progressMessage('loading', 'Loading setup progress…');
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup', { method: 'GET' })
      .then(function (data) {
        var s = (data && data.setup) || {};
        SETUP = { method: s.method || null, status: s.status || 'not_started', state: s.state || SETUP.state || {} };
        renderProgress(s.progress);
        var resumable = s.status === 'in_progress' || s.status === 'failed';
        var resume = $('#an-resume-setup'); if (resume) resume.hidden = !resumable;
        var reset = $('#an-reset-setup'); if (reset) reset.hidden = !resumable;
      })
      .catch(function (err) {
        // Keep the last known progress; surface that it could not be refreshed.
        progressMessage('error', 'Could not load setup progress: ' + err.message);
      });
  }

  function setSetupButtonsBusy(busy) {
    var resume = $('#an-resume-setup'); if (resume) resume.disabled = busy;
    $$('.an-setup-start').forEach(function (b) { b.disabled = busy; });
  }

  function startSetup(method) {
    setSetupButtonsBusy(true);
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/start', {
      method: 'POST', body: JSON.stringify({ method: method }),
    }).then(function () {
      toast('Setup started', 'success');
      if (method === 'manual') { window.location.href = window.location.pathname + '?view=wizard'; return; }
      // The resume/reset controls are now meaningful.
      var resume = $('#an-resume-setup'); if (resume) resume.hidden = false;
      var reset = $('#an-reset-setup'); if (reset) reset.hidden = false;
      runAutomaticSteps();
    }).catch(function (err) { setSetupButtonsBusy(false); toast('Could not start setup: ' + err.message, 'error'); });
  }

  function resumeSetup() {
    var method = (SETUP && SETUP.method) || 'automatic';
    setSetupButtonsBusy(true);
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/resume', { method: 'POST', body: JSON.stringify({ method: method }) })
      .then(function (data) {
        // Show the persisted progress before the next step runs.
        if (data && data.setup) renderProgress(data.setup.progress);
        if (method === 'manual') { window.location.href = window.location.pathname + '?view=wizard'; return; }
        runAutomaticSteps();
      })
      .catch(function (err) { setSetupButtonsBusy(false); toast('Could not resume: ' + err.message, 'error'); });
  }

  function resetSetup() {
    if (!window.confirm('Reset the setup progress? Your saved protection configuration is NOT erased.')) return;
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/reset', { method: 'POST', body: '{}' })
      .then(function () { window.location.reload(); })
      .catch(function (err) { toast('Could not reset: ' + err.message, 'error'); });
  }

  var GUILD_CHANNELS = (window.guildData && window.guildData.channels) || [];
  var GUILD_ROLES = (window.guildData && window.guildData.roles) || [];

  /* A premium, centered floating window that asks the admin to pick an existing
   * channel/role or let PrimeBot create one. `kind` is 'alert_channel' or
   * 'isolation_role'. `onChoose(choice)` resumes the setup with the choice;
   * `onError(msg)` surfaces a failed create so the window can stay open. */
  function askSetupChoice(kind, onChoose) {
    var isChannel = kind === 'alert_channel';
    var overlay = document.createElement('div');
    overlay.className = 'an-modal-overlay';
    var options = isChannel
      ? GUILD_CHANNELS.map(function (c) { return '<option value="' + esc(c.id) + '">#' + esc(c.name) + '</option>'; }).join('')
      : GUILD_ROLES.map(function (r) { return '<option value="' + esc(r.id) + '">' + esc(r.name) + '</option>'; }).join('');
    if (!options) options = '<option value="">— nothing available —</option>';
    overlay.innerHTML =
      '<div class="an-modal" role="dialog" aria-modal="true" aria-labelledby="an-modal-title">' +
      '<div class="an-modal-head">' +
      '<span class="an-modal-ico">' + svg(isChannel ? 'megaphone' : 'userCheck') + '</span>' +
      '<strong id="an-modal-title">' + (isChannel ? 'Choose an alert channel' : 'Choose an isolation role') + '</strong>' +
      '<button class="an-modal-x" aria-label="Close">' + svg('x') + '</button></div>' +
      '<div class="an-modal-body">' +
      '<p class="card-desc">' + (isChannel
        ? 'Where should PrimeBot post security alerts? Pick an existing channel, or let PrimeBot create <strong>#primebot-antinuke-log</strong> for you.'
        : 'Which role should isolate a confirmed attacker? Pick an existing role, or let PrimeBot create <strong>isolated</strong> just below its own role.') + '</p>' +
      '<div class="field"><label class="field-label">' + (isChannel ? 'Existing channel' : 'Existing role') + '</label>' +
      '<select id="an-setup-choice">' + options + '</select></div>' +
      '<div class="an-modal-error" id="an-modal-error" hidden></div>' +
      '</div>' +
      '<div class="an-modal-foot">' +
      '<button class="btn btn-mini an-choice-cancel">Cancel</button>' +
      '<button class="btn btn-mini an-choice-auto">' + svg('sparkles') + ' Make automatically</button>' +
      '<button class="btn btn-primary btn-mini an-choice-select">Use selected</button>' +
      '</div></div>';
    document.body.appendChild(overlay);
    function close() { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }
    function showError(msg) {
      var el = overlay.querySelector('#an-modal-error');
      if (el) { el.hidden = false; el.textContent = msg; }
    }
    function attempt(choice) {
      var btns = $$('.an-choice-select, .an-choice-auto', overlay);
      btns.forEach(function (b) { b.disabled = true; });
      Promise.resolve(onChoose(choice)).then(function () {
        // Success: the setup resumed — close the window.
        close();
      }).catch(function (err) {
        // Failure: keep the window open and show the real reason so the admin
        // can pick again instead of seeing nothing happen.
        btns.forEach(function (b) { b.disabled = false; });
        showError(err && err.message ? err.message : String(err));
      });
    }
    overlay.querySelector('.an-modal-x').addEventListener('click', close);
    overlay.querySelector('.an-choice-cancel').addEventListener('click', function () {
      close();
      toast('Setup paused — press Resume setup when you are ready.', 'error');
      setSetupButtonsBusy(false);
      var r = $('#an-resume-setup'); if (r) r.hidden = false;
    });
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    overlay.querySelector('.an-choice-select').addEventListener('click', function () {
      var sel = overlay.querySelector('#an-setup-choice');
      var id = sel ? sel.value : '';
      if (!id) { showError('Nothing is selected. Pick a ' + (isChannel ? 'channel' : 'role') + ' or use Make automatically.'); return; }
      attempt(isChannel ? { alertChannelId: id } : { isolationRoleId: id });
    });
    overlay.querySelector('.an-choice-auto').addEventListener('click', function () {
      attempt(isChannel ? { automaticChannel: true } : { automaticRole: true });
    });
    return { close: close, showError: showError };
  }

  /* One setup step request. Returns the parsed response (throws on HTTP error). */
  function runSetupStep(body) {
    return api('/api/guilds/' + GUILD_ID + '/antinuke/setup/step', {
      method: 'POST', body: JSON.stringify(Object.assign({ method: 'automatic' }, body || {})),
    });
  }

  /* Human-readable reason for a failed step, from the persisted state. */
  function stepFailureReason(data) {
    var failed = (data && data.progress && data.progress.steps || []).filter(function (s) { return s.status === 'failed'; });
    if (!failed.length) return 'A setup step failed.';
    return 'Step failed: ' + failed[0].label + (failed[0].error ? (' — ' + failed[0].error) : '');
  }

  /* Mark the setup as stopped with a retry affordance. */
  function stopSetupWithError(message) {
    setSetupButtonsBusy(false);
    var resume = $('#an-resume-setup'); if (resume) resume.hidden = false;
    var reset = $('#an-reset-setup'); if (reset) reset.hidden = false;
    toast(message + ' Press Resume setup to retry.', 'error');
  }

  /* Drive the automatic setup one step at a time, rendering real progress after
   * each step. A step that needs a choice opens the premium centered window; the
   * window STAYS OPEN and shows the real error if the chosen action fails (e.g.
   * "Make automatically" without Manage Roles/Channels), so the admin can pick
   * again instead of seeing nothing happen. */
  function runAutomaticSteps(extraBody) {
    return driveSetup(extraBody || {}, 0);
  }

  function driveSetup(extraBody, depth) {
    if (depth > 40) { stopSetupWithError('Setup did not converge.'); return Promise.resolve(); }
    setSetupButtonsBusy(true);
    return runSetupStep(extraBody).then(function (data) {
      renderProgress(data.progress);
      if (data.done) { toast('Anti-Nuke setup completed', 'success'); window.location.href = window.location.pathname; return; }
      if (data.prompt) {
        setSetupButtonsBusy(false);
        return new Promise(function (resolve) {
          askSetupChoice(data.prompt, function (choice) {
            setSetupButtonsBusy(true);
            var merged = Object.assign({}, extraBody, choice);
            return runSetupStep(merged).then(function (d2) {
              renderProgress(d2.progress);
              if (d2.done) { toast('Anti-Nuke setup completed', 'success'); window.location.href = window.location.pathname; resolve(); return; }
              if (d2.progress && d2.progress.failed > 0) {
                // Reject: the window stays open and shows the real reason.
                throw new Error(stepFailureReason(d2));
              }
              // Success: resolve so the window closes, then keep driving (a later
              // step may prompt again — that opens a fresh window).
              resolve();
              driveSetup(merged, depth + 1);
            });
          });
        });
      }
      if (data.progress && data.progress.failed > 0) { stopSetupWithError(stepFailureReason(data)); return; }
      return driveSetup(extraBody, depth + 1);
    }).catch(function (err) {
      // A rejection reaching here is either an HTTP failure or a failure we
      // re-threw from the window path (the window already showed it inline).
      if (!err || err.__handled) return;
      stopSetupWithError('Setup step failed: ' + err.message);
    });
  }

  // ── Manual wizard ─────────────────────────────────────────────────────────

  function initWizardView() {
    var sections = $$('.an-wizard-section');
    if (!sections.length) return;
    var index = 0;
    // `completed` is seeded from the persisted setup state (resume), so a
    // refresh does not silently reset the manual wizard's progress to 0.
    var completed = {};
    var savedState = (SETUP && SETUP.state) || {};
    var savedSteps = savedState.steps || {};
    sections.forEach(function (sec) {
      var key = sec.getAttribute('data-section');
      if (savedSteps[key] && savedSteps[key].status === 'completed') completed[key] = true;
    });

    function sectionLabel(sec, n) {
      var title = sec.querySelector('.an-wizard-title');
      return title ? title.textContent : ('Section ' + (n + 1));
    }

    function show(i) {
      index = Math.max(0, Math.min(sections.length - 1, i));
      sections.forEach(function (sec, n) { sec.hidden = n !== index; });
      var isLast = index === sections.length - 1;
      var next = $('#an-wizard-next'); if (next) next.hidden = isLast;
      var save = $('#an-wizard-save'); if (save) save.hidden = !isLast;
      var prev = $('#an-wizard-prev'); if (prev) prev.disabled = index === 0;
      if (isLast) renderReview();
      updateWizardProgress();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function updateWizardProgress() {
      var steps = sections.map(function (sec, n) {
        var key = sec.getAttribute('data-section');
        // The two trusted lists are optional (they match the catalog's
        // `required: false`), so skipping them never lowers the percentage.
        var required = key !== 'trustedUsers' && key !== 'trustedRoles';
        // The section the admin is on is only "running" while it is not done;
        // a completed section always shows completed (never regressed to
        // running when navigated back to).
        var status = completed[key] ? 'completed' : (n === index ? 'running' : 'pending');
        return { key: key, label: sectionLabel(sec, n), required: required, status: status };
      });
      var requiredSteps = steps.filter(function (s) { return s.required; });
      var done = requiredSteps.filter(function (s) { return s.status === 'completed'; }).length;
      var percent = requiredSteps.length ? Math.round((done / requiredSteps.length) * 100) : 0;
      // Reuse the shared renderer so the wizard and the automatic setup show an
      // identical card. Percent is clamped inside renderProgress.
      renderProgress({
        percent: percent,
        completed: done,
        total: requiredSteps.length,
        remaining: Math.max(0, requiredSteps.length - done),
        failed: 0,
        skipped: 0,
        running: requiredSteps.some(function (s) { return s.status === 'running'; }) ? 1 : 0,
        status: percent >= 100 ? 'completed' : 'in_progress',
        steps: steps,
      });
    }

    function markCurrentComplete() {
      completed[sections[index].getAttribute('data-section')] = true;
      persistManualProgress();
    }

    function persistManualProgress() {
      api('/api/guilds/' + GUILD_ID + '/antinuke/setup/progress', {
        method: 'PATCH', body: JSON.stringify({ method: 'manual', completed: Object.keys(completed) }),
      }).then(function (data) {
        if (data && data.setup) SETUP = { method: 'manual', status: data.setup.status, state: data.setup.state };
      }).catch(function () { /* best-effort */ });
    }

    function renderReview() {
      var el = $('#an-review');
      if (!el) return;
      var s = collectSettings();
      var rows = [];
      rows.push(['Enable Anti-Nuke', s.enabled ? 'Enabled' : 'Disabled']);
      rows.push(['Dry run', s.dryRun ? 'Enabled' : 'Disabled']);
      rows.push(['Alert channel', s.alertChannelId ? ('<#' + s.alertChannelId + '>') : '—']);
      rows.push(['Responses', (s.responses || []).join(', ') || '—']);
      rows.push(['Trusted users', String((s.trustedUserIds || []).length)]);
      rows.push(['Trusted roles', String((s.trustedRoleIds || []).length)]);
      var enabledCount = Object.keys(s.watched || {}).filter(function (k) { return s.watched[k].enabled; }).length;
      rows.push(['Watched actions enabled', String(enabledCount)]);
      el.innerHTML = '<table class="an-review-table"><tbody>' + rows.map(function (r) {
        return '<tr><th>' + esc(r[0]) + '</th><td>' + r[1] + '</td></tr>';
      }).join('') + '</tbody></table>';
    }

    var nextBtn = $('#an-wizard-next');
    if (nextBtn) nextBtn.addEventListener('click', function () { markCurrentComplete(); show(index + 1); });
    var prevBtn = $('#an-wizard-prev');
    if (prevBtn) prevBtn.addEventListener('click', function () { show(index - 1); });
    var saveBtn = $('#an-wizard-save');
    if (saveBtn) saveBtn.addEventListener('click', function () { markCurrentComplete(); saveSettings(true); });

    renderTrustedUsers();
    renderTrustedRoles();
    initWizardCreateButtons();
    initWizardReadinessCheck();
    // Resume at the first section that is not yet completed (so a return to the
    // wizard picks up where the admin left off rather than restarting at 1).
    var firstIncomplete = 0;
    for (var i = 0; i < sections.length; i++) {
      if (!completed[sections[i].getAttribute('data-section')]) { firstIncomplete = i; break; }
      if (i === sections.length - 1) firstIncomplete = i;
    }
    show(firstIncomplete);
  }

  /* "Make automatically" in the manual wizard — creates the alert channel or the
   * isolation role via the shared setup/create endpoint, then selects it in the
   * matching control. On failure the real reason is shown (no silent no-op). */
  function initWizardCreateButtons() {
    $$('.an-create-auto').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var kind = btn.dataset.create;
        btn.disabled = true;
        var old = btn.innerHTML;
        btn.innerHTML = 'Creating…';
        api('/api/guilds/' + GUILD_ID + '/antinuke/setup/create', { method: 'POST', body: JSON.stringify({ kind: kind }) })
          .then(function (res) {
            toast((kind === 'alert_channel' ? 'Created #' : 'Created the “') + (res.name || '') + (kind === 'alert_channel' ? '' : '” role'), 'success');
            if (kind === 'alert_channel') {
              var sel = $('#an-alert-channel');
              if (sel) {
                var opt = document.createElement('option');
                opt.value = res.channelId; opt.textContent = '#' + (res.name || '');
                sel.appendChild(opt); sel.value = res.channelId;
              }
            } else {
              var rsel = $('#an-quarantine-role');
              if (rsel) {
                var ropt = document.createElement('option');
                ropt.value = res.roleId; ropt.textContent = res.name || 'isolated';
                rsel.appendChild(ropt); rsel.value = res.roleId;
              }
            }
            if (window.saveBar && window.saveBar.markDirty) window.saveBar.markDirty();
          })
          .catch(function (err) { toast(err.message, 'error'); })
          .then(function () { btn.disabled = false; btn.innerHTML = old; });
      });
    });
  }

  /* The manual wizard's bot-readiness check (permissions + hierarchy), the same
   * scan the automatic setup gates on — surfaced as a card on the first step. */
  function initWizardReadinessCheck() {
    var run = $('#an-wizard-check-run');
    if (run) run.addEventListener('click', wizardReadinessCheck);
    wizardReadinessCheck();
  }

  function wizardReadinessCheck() {
    var out = $('#an-wizard-check-result');
    if (!out) return;
    out.innerHTML = '<div class="an-empty">Running check…</div>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/health')
      .then(function (scan) {
        var checks = (scan && scan.checks) || [];
        var relevant = checks.filter(function (c) {
          return /bot_permissions|hierarchy|enabled|intent|audit_stream|alert_channel|quarantine_role/i.test(c.key || '');
        });
        if (!relevant.length) relevant = checks.slice(0, 6);
        out.innerHTML = '<div class="an-health-list">' + relevant.map(function (c) {
          var result = c.result || (c.ok ? 'PASS' : 'FAILED');
          var cls = result === 'PASS' ? 'pass' : (result === 'WARNING' ? 'warn' : 'fail');
          return '<div class="an-health-row an-health-' + cls + '">' +
            '<span class="an-health-badge">' + esc(cls.toUpperCase()) + '</span>' +
            '<span class="an-health-label">' + esc(c.label || c.key) + '</span>' +
            '<span class="an-health-detail">' + esc(c.note || '') + '</span>' +
            (c.recommendation ? '<span class="an-health-fix">' + svg('wrench') + ' ' + esc(c.recommendation) + '</span>' : '') +
            '</div>';
        }).join('') + '</div>';
      })
      .catch(function (err) { out.innerHTML = '<div class="an-empty">Could not run the check: ' + esc(err.message) + '</div>'; });
  }

  // ── Console ───────────────────────────────────────────────────────────────

  function initConsoleView() {
    var enabled = $('#an-enabled');
    if (enabled) enabled.addEventListener('change', function () {
      // The master switch saves immediately — a security switch must not wait
      // on unrelated dirty fields.
      api('/api/guilds/' + GUILD_ID + '/antinuke/toggle', {
        method: 'POST', body: JSON.stringify({ enabled: enabled.checked }),
      }).then(function () {
        if (window.saveBar && window.saveBar.syncControl) window.saveBar.syncControl(enabled);
        toast(enabled.checked ? 'Anti-Nuke enabled' : 'Anti-Nuke disabled', 'success');
      }).catch(function (err) {
        enabled.checked = !enabled.checked;
        toast('Could not save: ' + err.message, 'error');
      });
    });

    renderTrustedUsers();
    renderTrustedRoles();
    initLockdown();
    initActivity();

    var rerun = $('#an-rerun-setup');
    if (rerun) rerun.addEventListener('click', function () {
      if (!window.confirm('Re-run the setup wizard? Your current configuration is preserved.')) return;
      api('/api/guilds/' + GUILD_ID + '/antinuke/setup/reset', { method: 'POST', body: '{}' })
        .then(function () { window.location.href = window.location.pathname + '?view=setup'; })
        .catch(function (err) { toast(err.message, 'error'); });
    });

    if (window.saveBar) {
      window.saveBar.register(function () { return saveSettings(false); });
      window.saveBar.track(document.querySelector('.an-console-page') || document.body);
    }
  }

  function initLockdown() {
    var engage = $('#an-lockdown-engage');
    if (engage) engage.addEventListener('click', function () {
      if (!window.confirm('Engage emergency lockdown? This raises the verification level and pauses new invites. It can be reversed.')) return;
      engage.disabled = true;
      api('/api/guilds/' + GUILD_ID + '/antinuke/lockdown', { method: 'POST', body: JSON.stringify({ action: 'engage' }) })
        .then(function () { toast('Lockdown engaged', 'success'); window.location.reload(); })
        .catch(function (err) { engage.disabled = false; toast('Lockdown failed: ' + err.message, 'error'); });
    });
    var lift = $('#an-lockdown-lift');
    if (lift) lift.addEventListener('click', function () {
      if (!window.confirm('Restore the pre-lockdown settings? Changes an administrator made after lockdown are kept.')) return;
      lift.disabled = true;
      api('/api/guilds/' + GUILD_ID + '/antinuke/lockdown', { method: 'POST', body: JSON.stringify({ action: 'restore' }) })
        .then(function (data) {
          toast('Lockdown restored', 'success');
          if (data && data.warnings && data.warnings.length) toast(data.warnings.join('; '), 'error');
          window.location.reload();
        })
        .catch(function (err) { lift.disabled = false; toast('Restore failed: ' + err.message, 'error'); });
    });
  }

  function incidentStatusLabel(status) {
    var labels = {
      detected: 'Detected',
      investigating: 'Investigating',
      confirmed: 'Confirmed',
      action_executed: 'Action Executed',
      action_partial: 'Partial',
      action_attempted: 'Action Attempted',
      action_failed: 'Action Failed',
      unattributed: 'Unattributed',
      dry_run: 'Dry Run',
      ignored_trusted_user: 'Ignored — Trusted User',
      ignored_below_threshold: 'Ignored — Below Threshold',
    };
    return labels[status] || (status || 'Detected');
  }

  var _activityLoad = null;
  function refreshIncidents() { if (_activityLoad) _activityLoad(); }

  function initActivity() {
    var body = $('#an-activity-body');
    if (!body) return;
    var offset = 0, limit = 25, total = 0;
    function load() {
      var qs = (typeof incidentQuery === 'function')
        ? incidentQuery(limit)
        : ('limit=' + limit + '&offset=' + offset);
      api('/api/guilds/' + GUILD_ID + '/antinuke/incidents?' + qs)
        .then(function (data) {
          total = data.total || 0;
          var rows = data.incidents || [];
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="8" class="an-empty">No incidents detected yet.</td></tr>';
          } else {
            body.innerHTML = rows.map(function (inc) {
              var exec = inc.executorId ? ('<@' + inc.executorId + '>') : '<span class="an-muted">unknown</span>';
              var resp = (inc.responseTaken || []).join(', ') || '—';
              var result = inc.responseOk ? '<span class="an-ok">ok</span>' : '<span class="an-bad">partial/failed</span>';
              var mode = inc.dryRun ? 'dry-run' : 'live';
              var status = incidentStatusLabel(inc.status);
              return '<tr>' +
                '<td>' + esc(new Date(inc.createdAt).toLocaleString()) + '</td>' +
                '<td>' + exec + '</td>' +
                '<td><span class="an-sev an-sev-' + esc(inc.severity) + '">' + esc(inc.severity) + '</span></td>' +
                '<td>' + esc(inc.count) + ' / ' + esc(inc.threshold) + ' in ' + esc(inc.windowSeconds) + 's</td>' +
                '<td>' + esc(resp) + '</td>' +
                '<td><span class="an-status an-status-' + esc(inc.status || 'detected') + '">' + status + '</span></td>' +
                '<td>' + result + '</td>' +
                '<td>' + esc(mode) + '</td>' +
                '</tr>';
            }).join('');
          }
          var page = Math.floor(offset / limit) + 1;
          var pages = Math.max(1, Math.ceil(total / limit));
          var label = $('#an-activity-page'); if (label) label.textContent = 'Page ' + page + ' / ' + pages;
          var prev = $('#an-activity-prev'); if (prev) prev.disabled = offset <= 0;
          var next = $('#an-activity-next'); if (next) next.disabled = offset + limit >= total;
        })
        .catch(function (err) {
          body.innerHTML = '<tr><td colspan="8" class="an-empty">Could not load activity: ' + esc(err.message) + '</td></tr>';
        });
    }
    var prev = $('#an-activity-prev');
    if (prev) prev.addEventListener('click', function () { INCIDENT_FILTERS.page = Math.max(0, INCIDENT_FILTERS.page - 1); load(); });
    var next = $('#an-activity-next');
    if (next) next.addEventListener('click', function () { INCIDENT_FILTERS.page += 1; load(); });
    _activityLoad = load;
    load();
  }

  // ── Overview wiring ───────────────────────────────────────────────────────

  function initOverview() {
    var rangeEl = $('#an-overview-range');
    if (rangeEl) rangeEl.addEventListener('change', refreshOverview);
    var qa = $('#an-qa-lockdown');
    if (qa) qa.addEventListener('click', function () {
      var sec = $('.am-section-btn[data-section="lockdown"]');
      if (sec) sec.click();
    });
    var qb = $('#an-qa-backup');
    if (qb) qb.addEventListener('click', function () {
      var sec = $('.am-section-btn[data-section="backups"]');
      if (sec) sec.click();
    });
    var qh = $('#an-qa-health');
    if (qh) qh.addEventListener('click', function () {
      var sec = $('.am-section-btn[data-section="health"]');
      if (sec) sec.click();
    });
  }

  // ── Trusted users / roles ─────────────────────────────────────────────────

  function renderTrustedUsers() {
    var el = $('#an-trusted-users');
    if (!el) return;
    var ids = SETTINGS.trustedUserIds || [];
    el.innerHTML = ids.length ? ids.map(function (id) {
      return '<div class="rr-row" data-id="' + esc(id) + '"><span class="rr-name"><@' + esc(id) + '> <code>' + esc(id) + '</code></span>' +
        '<button class="btn btn-mini an-remove-trusted-user" data-id="' + esc(id) + '">' + svg('x') + ' Remove</button></div>';
    }).join('') : '<div class="field-hint">No trusted users.</div>';
    $$('.an-remove-trusted-user', el).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.getAttribute('data-id');
        SETTINGS.trustedUserIds = (SETTINGS.trustedUserIds || []).filter(function (x) { return x !== id; });
        renderTrustedUsers();
        if (window.saveBar) window.saveBar.markDirty();
      });
    });
    var add = $('#an-add-trusted-user');
    if (add && !add._bound) {
      add._bound = true;
      add.addEventListener('click', function () {
        var input = $('#an-trusted-user-input');
        var id = ((input && input.value) || '').trim();
        if (!/^\d{15,22}$/.test(id)) { toast('Enter a valid user ID (15-22 digits)', 'error'); return; }
        var botId = (window.guildData && window.guildData.botUserId) || null;
        if (botId && id === botId) { toast('PrimeBot cannot be trusted (it is always exempt)', 'error'); return; }
        if ((SETTINGS.trustedUserIds || []).indexOf(id) < 0) SETTINGS.trustedUserIds = (SETTINGS.trustedUserIds || []).concat(id);
        if (input) input.value = '';
        renderTrustedUsers();
        if (window.saveBar) window.saveBar.markDirty();
      });
    }
  }

  function renderTrustedRoles() {
    var el = $('#an-trusted-roles');
    if (!el) return;
    var trusted = SETTINGS.trustedRoleIds || [];
    var roles = (window.guildData && window.guildData.roles) || [];
    el.innerHTML = roles.length ? roles.map(function (r) {
      return '<label class="switch mini"><input type="checkbox" class="an-trusted-role" value="' + esc(r.id) + '"' + (trusted.indexOf(r.id) >= 0 ? ' checked' : '') + '/><span class="slider"></span><span class="switch-text">' + esc(r.name) + '</span></label>';
    }).join('') : '<div class="field-hint">No roles loaded.</div>';
  }

  // ── Collect + save ────────────────────────────────────────────────────────

  function collectSettings() {
    var watched = {};
    $$('.an-action-row').forEach(function (row) {
      var key = row.getAttribute('data-action');
      if (!ACTIONS.some(function (a) { return a.key === key; })) return;
      var enabledEl = $('.an-watch-enabled', row);
      var thresholdEl = $('.an-watch-threshold', row);
      var secondsEl = $('.an-watch-seconds', row);
      watched[key] = {
        enabled: enabledEl ? enabledEl.checked : false,
        threshold: thresholdEl ? parseInt(thresholdEl.value, 10) || undefined : undefined,
        seconds: secondsEl ? parseInt(secondsEl.value, 10) || undefined : undefined,
      };
    });
    // Only send dangerousPermissions when the page actually renders the
    // checkboxes. The console view does not, and sending an empty list there
    // would silently wipe the admin's configured list on every save (the
    // "Keep at least one dangerous permission" rejection).
    var permBoxes = $$('.an-danger-perm');
    // Per-rule response overrides: group `.an-action-response-cb` by data-action.
    var actionResponses = {};
    $$('.an-action-response-cb').forEach(function (cb) {
      if (cb.checked) {
        var action = cb.getAttribute('data-action');
        if (!action) return;
        if (!actionResponses[action]) actionResponses[action] = [];
        if (actionResponses[action].indexOf(cb.value) === -1) actionResponses[action].push(cb.value);
      }
    });
    var quarantineEl = $('#an-quarantine-role');
    return {
      enabled: $('#an-enabled') ? $('#an-enabled').checked : (SETTINGS.enabled === true),
      dryRun: $('#an-dry-run') ? $('#an-dry-run').checked : (SETTINGS.dryRun !== false),
      alertChannelId: ($('#an-alert-channel') && $('#an-alert-channel').value) || null,
      responses: $$('.an-response-cb').filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; }),
      actionResponses: actionResponses,
      quarantineRoleId: quarantineEl ? (quarantineEl.value || null) : (SETTINGS.quarantineRoleId || null),
      dangerousPermissions: permBoxes.length
        ? permBoxes.filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; })
        : (SETTINGS.dangerousPermissions || []),
      trustedUserIds: SETTINGS.trustedUserIds || [],
      trustedRoleIds: $$('.an-trusted-role').filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; }),
      watched: watched,
      responseCooldownSeconds: $('#an-response-cooldown') ? parseInt($('#an-response-cooldown').value, 10) : SETTINGS.responseCooldownSeconds,
      lockdown: { enabled: $('#an-lockdown-enabled') ? $('#an-lockdown-enabled').checked : (SETTINGS.lockdown && SETTINGS.lockdown.enabled !== false) },
    };
  }

  function saveSettings(isWizardFinish) {
    var body = collectSettings();
    if (!body.responses || body.responses.length === 0) {
      toast('Select at least one response action', 'error');
      return Promise.reject(new Error('no responses'));
    }
    return api('/api/guilds/' + GUILD_ID + '/antinuke', { method: 'PATCH', body: JSON.stringify(body) })
      .then(function (data) {
        if (data && data.antiNuke) Object.assign(SETTINGS, data.antiNuke);
        toast('Anti-Nuke settings saved', 'success');
        if (isWizardFinish) {
          return api('/api/guilds/' + GUILD_ID + '/antinuke/setup/complete', { method: 'POST', body: JSON.stringify({ method: 'manual' }) })
            .then(function () { window.location.href = window.location.pathname; });
        }
        return data;
      })
      .catch(function (err) {
        toast('Could not save: ' + err.message, 'error');
        throw err;
      });
  }

  // ── Owner-controlled Access Control ───────────────────────────────────────

  var ACCESS_SNAPSHOT = null;

  function canManageAccess() { return ACCESS.isOwner || hasPerm('antinuke.access.manage'); }
  function canViewAccess() { return ACCESS.isOwner || hasPerm('antinuke.access.view'); }
  function canRevokeAccess() { return ACCESS.isOwner || hasPerm('antinuke.access.revoke'); }

  function levelLabel(role) {
    var levels = PERMS.levels || {};
    if (role === 'owner') return (levels.owner && levels.owner.label) || 'Server Owner';
    if (role === 'coOwner') return (levels.coOwner && levels.coOwner.label) || 'Co-Owner';
    if (role === 'trustedAdmin') return (levels.trustedAdmin && levels.trustedAdmin.label) || 'Trusted Admin';
    return (levels.none && levels.none.label) || 'No Access';
  }

  function permissionName(id) {
    var p = PERM_BY_ID[id];
    return p ? p.label : id;
  }

  function permissionRowHTML(p, opts) {
    var o = opts || {};
    var checked = (o.checked || false) ? ' checked' : '';
    var disabled = o.disabled ? ' disabled' : '';
    return '<label class="an-perm-row">' +
      '<input type="checkbox" class="an-perm-cb" value="' + esc(p.id) + '"' + checked + disabled + '/>' +
      '<span class="an-perm-meta"><span class="an-perm-name">' + esc(p.label) +
      (p.ownerOnly ? ' <span class="an-owner-badge">owner</span>' : '') + '</span>' +
      '<span class="an-perm-desc">' + esc(p.description) + '</span></span></label>';
  }

  /* The permission matrix used in the editor. Groups come from the shared
   * registry; owner-only permissions are shown but force-disabled for
   * non-owners and never editable for the owner (they already hold them). */
  function permissionMatrixHTML(currentPerms, editable) {
    var groups = PERMS.groups || [];
    if (!groups.length) return '<div class="an-access-loading">No permission catalog loaded.</div>';
    return groups.map(function (g) {
      return '<div class="an-perm-group"><div class="an-perm-group-title">' + esc(g.label) + '</div>' +
        g.permissions.map(function (p) {
          var checked = (currentPerms || []).indexOf(p.id) >= 0;
          // Non-owners can never toggle owner-only permissions.
          var disabled = p.ownerOnly && !ACCESS.isOwner;
          return permissionRowHTML(p, { checked: checked, disabled: disabled || !editable });
        }).join('') + '</div>';
    }).join('');
  }

  function confirmSensitive(reason, extra) {
    var msg = reason;
    if (extra) msg += '\n\n' + extra;
    return window.confirm(msg);
  }

  /* Render the Access Control section (owner + assignments + history). */
  function renderAccessControl() {
    var root = $('#an-access-root');
    if (!root) return;
    if (!canViewAccess()) {
      root.innerHTML = '<div class="an-access-empty">Access Control is restricted to the server owner' +
        ' (and Co-Owners / Trusted Admins holding the access management permissions).</div>';
      return;
    }
    root.innerHTML = '<div class="an-access-loading">Loading access control…</div>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/access', { method: 'GET' })
      .then(function (snap) {
        ACCESS_SNAPSHOT = snap;
        renderAccessSnapshot(snap);
      })
      .catch(function (err) {
        root.innerHTML = '<div class="an-access-empty">Could not load access control: ' + esc(err.message) + '</div>';
      });
  }

  function renderAccessSnapshot(snap) {
    var root = $('#an-access-root');
    if (!root) return;
    var assignments = snap.assignments || [];
    var history = snap.history || [];
    var viewerLevel = ACCESS.level != null ? ACCESS.level : 4;
    var canEdit = canManageAccess();

    var ownerCard = '<div class="an-access-owner">' +
      '<div class="an-access-avatar">' + svg('shield') + '</div>' +
      '<div><div class="an-access-name">Server Owner <span class="an-access-tag an-access-tag-owner">' + esc(snap.ownerId || 'unknown') + '</span></div>' +
      '<div class="an-access-desc">The actual Discord guild owner. Full access — never removable or demotable.</div></div></div>';

    var assignmentCards = assignments.map(function (a) {
      var roleLabel = levelLabel(a.role);
      var tagCls = a.role === 'coOwner' ? 'an-access-tag-co' : 'an-access-tag-ta';
      var shortPerms = (a.permissions || []).slice(0, 4).map(permissionName).join(', ') +
        ((a.permissions || []).length > 4 ? '…' : '');
      var canRemove = (ACCESS.isOwner || (canRevokeAccess() && a.level > viewerLevel)) && a.userId !== snap.ownerId;
      var canEditRow = (ACCESS.isOwner || (canEdit && a.level > viewerLevel)) && a.userId !== snap.ownerId;
      return '<div class="an-access-row" data-user="' + esc(a.userId) + '" data-role="' + esc(a.role) + '">' +
        '<div class="an-access-name">' + a.userId + ' <span class="an-access-tag ' + tagCls + '">' + esc(roleLabel) + '</span></div>' +
        '<div class="an-access-desc">' + esc(shortPerms || 'No permissions assigned') + '</div>' +
        '<div class="an-access-row-actions">' +
        (canEditRow ? '<button class="btn btn-mini an-access-edit" data-user="' + esc(a.userId) + '" data-role="' + esc(a.role) + '">' + svg('settings') + ' Permissions</button>' : '') +
        (canRemove ? '<button class="btn btn-mini btn-danger-an an-access-remove" data-user="' + esc(a.userId) + '" data-role="' + esc(a.role) + '">' + svg('trash') + ' Remove</button>' : '') +
        '</div></div>';
    }).join('');

    var addBtn = canManageAccess()
      ? '<button class="btn btn-primary an-access-add" id="an-access-add">' + svg('userPlus') + ' Add Co-Owner / Trusted Admin</button>'
      : '';

    var historyRows = history.slice(0, 12).map(function (h) {
      var target = h.targetId ? '→ ' + esc(h.targetId) : '';
      return '<tr><td>' + esc(h.action) + ' ' + target + '</td><td>by ' + esc(h.actorId) + '</td>' +
        '<td class="an-history-result an-history-' + esc(h.result) + '">' + esc(h.result) + '</td>' +
        '<td>' + esc(new Date(h.createdAt).toLocaleString()) + '</td></tr>';
    }).join('') || '<tr><td colspan="4" class="an-empty">No access changes recorded yet.</td></tr>';

    root.innerHTML =
      '<div class="an-access-grid">' + ownerCard +
      '<div class="an-access-assigned"><div class="an-access-head">' +
      '<span><span class="icon">' + svg('users') + '</span> Assigned access</span>' + addBtn + '</div>' +
      '<div class="an-access-list">' + (assignmentCards || '<div class="an-access-empty">No Co-Owners or Trusted Admins yet.</div>') + '</div></div>' +
      '<div class="an-access-history"><div class="an-access-head"><span><span class="icon">' + svg('scroll') + '</span> Access history</span></div>' +
      '<table class="an-hist-table"><tbody>' + historyRows + '</tbody></table></div>' +
      '</div>';

    var add = $('#an-access-add');
    if (add) add.addEventListener('click', function () {
      var userId = window.prompt('Enter the Discord user id of the member to grant Anti-Nuke management access to:');
      if (!userId) return;
      if (!/^\d{15,22}$/.test(userId.trim())) { toast('Enter a valid 15–22 digit Discord user id', 'error'); return; }
      var isCoOwner = window.confirm('Appoint this user as a Co-Owner? Co-Owners must be confirmed before they receive permissions.\n\nChoose OK for Co-Owner, Cancel for Trusted Admin.');
      openAccessEditor(null, userId.trim(), isCoOwner ? 'coOwner' : 'trustedAdmin');
    });

    $$('.an-access-edit', root).forEach(function (btn) {
      btn.addEventListener('click', function () { openAccessEditor(btn.getAttribute('data-role'), btn.getAttribute('data-user')); });
    });
    $$('.an-access-remove', root).forEach(function (btn) {
      btn.addEventListener('click', function () { removeAccessRow(btn); });
    });
  }

  /* Build (or edit) the assignment in the permission-popup modal. */
  function openAccessEditor(role, userId, forcedRole) {
    var isNew = !role;
    var targetRole = forcedRole || role || 'trustedAdmin';
    if (!canManageAccess()) { toast('You do not have permission to manage Anti-Nuke access.', 'error'); return; }
    // Existing assignment's current permissions.
    var existing = null;
    if (ACCESS_SNAPSHOT && ACCESS_SNAPSHOT.assignments) {
      existing = ACCESS_SNAPSHOT.assignments.find(function (a) { return a.userId === userId; }) || null;
    }
    var current = existing ? (existing.permissions || []) : [];
    if ((existing && existing.role) && !forcedRole) targetRole = existing.role;
    var canPickCoOwner = ACCESS.isOwner;
    var canSave = ACCESS.isOwner || (canManageAccess() && (!existing || existing.level > ACCESS.level));

    var overlay = document.createElement('div');
    overlay.className = 'an-modal-overlay';
    overlay.innerHTML =
      '<div class="an-modal" role="dialog" aria-modal="true" aria-label="Edit Anti-Nuke access">' +
      '<div class="an-modal-head"><strong>' + (isNew ? 'Grant Anti-Nuke access' : 'Edit access — ' + esc(userId)) + '</strong>' +
      '<button class="an-modal-x" aria-label="Close">' + svg('x') + '</button></div>' +
      '<div class="an-modal-body">' +
      '<div class="field"><label class="field-label">Level</label>' +
      '<select id="an-acc-level-editor">' +
      '<option value="trustedAdmin">Trusted Admin</option>' +
      (canPickCoOwner ? '<option value="coOwner">Co-Owner</option>' : '') +
      '</select></div>' +
      '<div class="field"><label class="field-label">Preset</label>' +
      '<select id="an-acc-preset"><option value="">— Custom —</option>' +
      (PERMS.presets || []).filter(function (pr) { return pr.key !== 'custom'; }).map(function (pr) {
        return '<option value="' + esc(pr.key) + '">' + esc(pr.label) + '</option>';
      }).join('') + '</select></div>' +
      '<div class="an-perm-matrix" id="an-acc-matrix">' + permissionMatrixHTML(current, canSave) + '</div>' +
      (!ACCESS.isOwner ? '<p class="an-acc-hint">Co-Owners can only be appointed by the server owner.</p>' : '') +
      '</div>' +
      '<div class="an-modal-foot">' +
      '<button class="btn btn-mini an-acc-cancel">Cancel</button>' +
      '<button class="btn btn-primary btn-mini an-acc-save">Save changes</button>' +
      '</div></div>';
    document.body.appendChild(overlay);

    var levelSel = overlay.querySelector('#an-acc-level-editor');
    var presetSel = overlay.querySelector('#an-acc-preset');
    var matrix = overlay.querySelector('#an-acc-matrix');
    if (levelSel) levelSel.value = targetRole;
    if (existing && existing.preset) { if (presetSel) presetSel.value = existing.preset; }

    function applyPresetToMatrix(key) {
      var preset = (PERMS.presets || []).find(function (pr) { return pr.key === key; });
      if (!preset) return;
      var ids = preset.permissions || [];
      matrix.querySelectorAll('.an-perm-cb').forEach(function (cb) {
        cb.checked = ids.indexOf(cb.value) >= 0 && !cb.disabled;
      });
    }
    if (presetSel) presetSel.addEventListener('change', function () { applyPresetToMatrix(presetSel.value); });
    if (levelSel) levelSel.addEventListener('change', function () {
      if (levelSel.value === 'coOwner') { applyPresetToMatrix('protectionManager'); }
    });

    overlay.querySelector('.an-modal-x').addEventListener('click', close);
    overlay.querySelector('.an-acc-cancel').addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    function close() { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }

    overlay.querySelector('.an-acc-save').addEventListener('click', function () {
      if (!canSave) { toast('You cannot manage this assignment.', 'error'); return; }
      var perms = matrix.querySelectorAll('.an-perm-cb');
      var selected = [];
      perms.forEach(function (cb) { if (cb.checked) selected.push(cb.value); });
      var selRole = levelSel ? levelSel.value : 'trustedAdmin';
      var sensitive = selRole === 'coOwner' || (existing && existing.role === 'coOwner') ||
        selected.indexOf('antinuke.lockdown') >= 0 || selected.indexOf('antinuke.recovery') >= 0 ||
        selected.indexOf('antinuke.access.manage') >= 0 || selected.indexOf('antinuke.access.revoke') >= 0;
      if (sensitive && !confirmSensitive(
        (selRole === 'coOwner' && !existing) ? 'Appoint this user as a CO-OWNER? They will receive the selected Anti-Nuke management permissions.' :
        ((existing && existing.role === 'coOwner' && selRole !== 'coOwner') ? 'DEMOTE this Co-Owner to a Trusted Admin?' :
        'This change grants sensitive permissions (lockdown / recovery / access management).'),
        'Only grant permissions you are authorized to delegate. Non-owner managers are capped to their own permission set.'
      )) return;

      var url = isNew
        ? '/api/guilds/' + GUILD_ID + '/antinuke/access/assign'
        : '/api/guilds/' + GUILD_ID + '/antinuke/access/' + encodeURIComponent(userId);
      var method = isNew ? 'POST' : 'PATCH';
      api(url, { method: method, body: JSON.stringify({ userId: userId, role: selRole, permissions: selected, preset: presetSel ? presetSel.value || null : null }) })
        .then(function () {
          close();
          toast('Anti-Nuke access saved', 'success');
          renderAccessControl();
        })
        .catch(function (err) { toast('Could not save access: ' + err.message, 'error'); });
    });
  }

  function removeAccessRow(btn) {
    var userId = btn.getAttribute('data-user');
    var role = btn.getAttribute('data-role');
    if (!confirmSensitive('Remove ' + (role === 'coOwner' ? 'this Co-Owner' : 'this Trusted Admin') +
      ' from Anti-Nuke access?', 'This revokes ALL their Anti-Nuke management permissions immediately.')) return;
    api('/api/guilds/' + GUILD_ID + '/antinuke/access/' + encodeURIComponent(userId), { method: 'DELETE', body: '{}' })
      .then(function () { toast('Access revoked', 'success'); renderAccessControl(); })
      .catch(function (err) { toast('Could not revoke: ' + err.message, 'error'); });
  }

  // ── Boot ──────────────────────────────────────────────────────────────────

  // Progress auto-refresh: the setup view polls the persisted progress at most
  // once per 5s, stops when the setup is complete/failed, and pauses while the
  // tab is hidden or the page is inactive. No fake increments — the API returns
  // the actual persisted state.
  var progressPollTimer = null;
  var progressPollInterval = 5000;
  function startProgressPolling() {
    stopProgressPolling();
    progressPollTimer = setInterval(function () {
      if (document.hidden) return; // pausing while the tab is inactive
      api('/api/guilds/' + GUILD_ID + '/antinuke/setup', { method: 'GET' })
        .then(function (data) {
          var s = (data && data.setup) || {};
          if (s.progress) {
            SETUP = { method: s.method || 'automatic', status: s.status || 'not_started', state: s.state || {} };
            renderProgress(s.progress);
          }
          if (s.status === 'completed' || s.status === 'failed' || (s.progress && s.progress.failed > 0)) stopProgressPolling();
        })
        .catch(function () { /* keep polling — a transient network error must not stop progress */ });
    }, progressPollInterval);
  }
  function stopProgressPolling() {
    if (progressPollTimer) { clearInterval(progressPollTimer); progressPollTimer = null; }
  }
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stopProgressPolling();
    else if (VIEW === 'setup') startProgressPolling();
  });
  document.addEventListener('pagehide', function () { stopProgressPolling(); });

  function initConsoleViewExtra() {
    renderAccessControl();
    initSections();
    initOverview();
    initRaid();
    initBackups();
    initHealth();
    initLockdownProfiles();
    initIncidentFilters();
  }

  // ── Premium section navigation ────────────────────────────────────────────
  //
  // One horizontal rail; sections switch without a page reload, the active
  // section is kept in the URL (?section=) so a refresh restores it, the rail
  // scrolls the active tab into view on mobile, and Left/Right arrow keys move
  // between tabs when the rail has focus.

  function initSections() {
    var rail = $('#an-sections');
    if (!rail) return;
    var buttons = $$('.am-section-btn', rail);

    function sectionKeys() { return buttons.map(function (b) { return b.dataset.section; }); }

    function showSection(key, opts) {
      opts = opts || {};
      if (!$('.an-section[data-section="' + key + '"]')) key = 'overview';
      $$('.an-section').forEach(function (sec) { sec.hidden = sec.dataset.section !== key; });
      buttons.forEach(function (btn) {
        var on = btn.dataset.section === key;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-current', on ? 'true' : 'false');
      });
      var active = buttons.filter(function (b) { return b.dataset.section === key; })[0];
      if (active && active.scrollIntoView) {
        try { active.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' }); } catch (_) { active.scrollIntoView(); }
      }
      if (opts.push !== false && window.history && window.history.replaceState) {
        var url = new URL(window.location.href);
        url.searchParams.set('section', key);
        window.history.replaceState({ section: key }, '', url);
      }
      onSectionShown(key);
    }

    rail.addEventListener('click', function (e) {
      var btn = e.target.closest('.am-section-btn');
      if (btn) showSection(btn.dataset.section);
    });

    rail.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      var keys = sectionKeys();
      var cur = keys.indexOf($('.am-section-btn.active', rail) ? $('.am-section-btn.active', rail).dataset.section : 'overview');
      var next = e.key === 'ArrowRight' ? Math.min(keys.length - 1, cur + 1) : Math.max(0, cur - 1);
      var target = buttons[next];
      if (target) { target.focus(); showSection(target.dataset.section); }
      e.preventDefault();
    });

    window.addEventListener('popstate', function (ev) {
      var key = (ev.state && ev.state.section) || new URL(window.location.href).searchParams.get('section') || 'overview';
      showSection(key, { push: false });
    });

    var initial = new URL(window.location.href).searchParams.get('section') || 'overview';
    showSection(initial, { push: false });
    // Keep the rail under the sticky header on scroll without overlapping it.
    rail.scrollTop = 0;
  }

  function onSectionShown(key) {
    if (key === 'overview') refreshOverview();
    if (key === 'antiraid') refreshRaid();
    if (key === 'backups') refreshBackups();
    if (key === 'health') refreshHealth();
    if (key === 'incidents') refreshIncidents();
  }

  // ── Overview (real aggregates from the incident ledger) ───────────────────

  function fmtTs(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString(); } catch (_) { return String(ts); }
  }

  function refreshOverview() {
    var live = $('#an-overview-live');
    var rangeEl = $('#an-overview-range');
    if (!live) return;
    var days = rangeEl ? rangeEl.value : '30';
    live.innerHTML = '<div class="am-stat"><div class="am-stat-body"><div class="am-stat-label">Loading…</div></div></div>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/overview?days=' + encodeURIComponent(days))
      .then(function (o) {
        live.innerHTML = [
          statHTML('Total incidents', o.total, 'inbox'),
          statHTML('Critical', o.critical, 'alertTriangle'),
          statHTML('Confirmed attacks', o.confirmed, 'shieldAlert'),
          statHTML('Contained', o.contained, 'shieldCheck'),
          statHTML('Failed enforcement', o.failed, 'x'),
          statHTML('Last success', o.lastSuccessAt ? new Date(o.lastSuccessAt).toLocaleDateString() : '—', 'check'),
        ].join('');
        var top = $('#an-overview-top');
        if (top) {
          top.innerHTML = (o.topCategories && o.topCategories.length)
            ? '<div class="card-title"><span>Top categories</span></div><div class="an-bars">' + o.topCategories.map(function (c) {
                var max = o.topCategories[0].count || 1;
                var pct = Math.round((c.count / max) * 100);
                return '<div class="an-bar-row"><span class="an-bar-label">' + esc(actionLabel(c.action)) + '</span><span class="an-bar"><span class="an-bar-fill" style="width:' + pct + '%"></span></span><span class="an-bar-val">' + esc(c.count) + '</span></div>';
              }).join('') + '</div>'
            : '<div class="an-empty">No incidents in this window.</div>';
        }
        var mods = $('#an-overview-modules');
        if (mods) {
          var byAction = {};
          (o.topCategories || []).forEach(function (c) { byAction[c.action] = c.count; });
          mods.innerHTML = '<div class="card-title"><span>Detection modules</span></div><div class="an-module-status">' +
            MODULES.map(function (m) {
              var acts = ACTIONS.filter(function (a) { return a.module === m.key; });
              var enabled = acts.some(function (a) { return (SETTINGS.watched && SETTINGS.watched[a.key] || {}).enabled !== false; });
              return '<span class="an-mod-pill ' + (enabled ? 'on' : 'off') + '">' + svg(enabled ? 'check' : 'x') + ' ' + esc(m.label) + '</span>';
            }).join('') + '</div>';
        }
      })
      .catch(function (err) {
        live.innerHTML = '<div class="an-empty">Could not load overview: ' + esc(err.message) + '</div>';
      });
  }

  function statHTML(label, value, icon) {
    return '<div class="am-stat"><div class="am-stat-icon">' + svg(icon) + '</div><div class="am-stat-body"><div class="am-stat-label">' + esc(label) + '</div><div class="am-stat-value">' + esc(value) + '</div></div></div>';
  }

  function actionLabel(key) {
    var a = ACTIONS.filter(function (x) { return x.key === key; })[0];
    return a ? a.label : key;
  }

  // ── Anti-Raid ─────────────────────────────────────────────────────────────

  function initRaid() {
    var refresh = $('#an-raid-refresh');
    if (refresh) refresh.addEventListener('click', refreshRaid);
  }

  function refreshRaid() {
    var body = $('#an-raid-incidents-body');
    if (!body) return;
    body.innerHTML = '<tr><td colspan="5" class="an-empty">Loading…</td></tr>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/raid?limit=25')
      .then(function (data) {
        var rows = data.incidents || [];
        if (!rows.length) { body.innerHTML = '<tr><td colspan="5" class="an-empty">No raid incidents detected.</td></tr>'; return; }
        body.innerHTML = rows.map(function (inc) {
          var details = inc.details || '';
          var joins = (details.match(/joins?[=: ](\d+)/i) || [])[1] || inc.count || '—';
          var newAcc = (details.match(/new[_-]?accounts?[=: ](\d+)/i) || [])[1] || '—';
          return '<tr><td>' + esc(fmtTs(inc.createdAt)) + '</td>' +
            '<td><span class="an-sev an-sev-' + esc(inc.severity) + '">' + esc(inc.severity) + '</span></td>' +
            '<td>' + esc(joins) + '</td><td>' + esc(newAcc) + '</td>' +
            '<td>' + esc((inc.responseTaken || []).join(', ') || '—') + '</td></tr>';
        }).join('');
      })
      .catch(function (err) { body.innerHTML = '<tr><td colspan="5" class="an-empty">Could not load: ' + esc(err.message) + '</td></tr>'; });
  }

  // ── Backups ───────────────────────────────────────────────────────────────

  function initBackups() {
    var create = $('#an-backup-create');
    if (create) create.addEventListener('click', function () {
      create.disabled = true;
      var nameEl = $('#an-backup-name');
      api('/api/guilds/' + GUILD_ID + '/antinuke/backups', { method: 'POST', body: JSON.stringify({ name: nameEl ? nameEl.value : '' }) })
        .then(function () { toast('Snapshot created', 'success'); if (nameEl) nameEl.value = ''; refreshBackups(); })
        .catch(function (err) { toast('Backup failed: ' + err.message, 'error'); })
        .then(function () { create.disabled = false; });
    });
    var refresh = $('#an-backup-refresh');
    if (refresh) refresh.addEventListener('click', refreshBackups);
  }

  function refreshBackups() {
    var list = $('#an-backup-list');
    if (!list) return;
    list.innerHTML = '<div class="an-empty">Loading…</div>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/backups')
      .then(function (data) {
        var rows = data.backups || [];
        if (!rows.length) { list.innerHTML = '<div class="an-empty">No snapshots yet.</div>'; return; }
        list.innerHTML = rows.map(function (b) {
          return '<div class="an-backup-row" data-id="' + esc(b.id) + '">' +
            '<div class="an-backup-main"><div class="an-backup-name">' + esc(b.name || ('Backup #' + b.id)) + '</div>' +
            '<div class="an-backup-meta">' + esc(fmtTs(b.createdAt)) + ' · ' + esc((b.counts && b.counts.roles) || 0) + ' roles · ' + esc((b.counts && b.counts.channels) || 0) + ' channels</div></div>' +
            '<div class="an-backup-actions">' +
            '<button class="btn btn-mini an-backup-compare" data-id="' + esc(b.id) + '">Compare</button>' +
            '<button class="btn btn-mini an-backup-preview" data-id="' + esc(b.id) + '">Restore preview</button>' +
            '<button class="btn btn-danger btn-mini an-backup-restore" data-id="' + esc(b.id) + '">Restore</button>' +
            '<button class="btn btn-mini an-backup-delete" data-id="' + esc(b.id) + '">Delete</button>' +
            '</div></div>';
        }).join('');
        $$('.an-backup-compare', list).forEach(function (btn) { btn.addEventListener('click', function () { backupCompare(btn.dataset.id); }); });
        $$('.an-backup-preview', list).forEach(function (btn) { btn.addEventListener('click', function () { backupPreview(btn.dataset.id); }); });
        $$('.an-backup-restore', list).forEach(function (btn) { btn.addEventListener('click', function () { backupRestore(btn.dataset.id); }); });
        $$('.an-backup-delete', list).forEach(function (btn) { btn.addEventListener('click', function () { backupDelete(btn.dataset.id); }); });
      })
      .catch(function (err) { list.innerHTML = '<div class="an-empty">Could not load backups: ' + esc(err.message) + '</div>'; });
  }

  function backupReport(html) {
    var list = $('#an-backup-list');
    if (list) list.insertAdjacentHTML('afterbegin', '<div class="an-backup-report card">' + html + '</div>');
  }

  function backupCompare(id) {
    api('/api/guilds/' + GUILD_ID + '/antinuke/backups/' + id + '/compare')
      .then(function (data) {
        var d = data.diff || {};
        backupReport('<div class="card-title"><span>Comparison for #' + esc(id) + '</span></div>' +
          '<ul class="an-diff-list">' +
          '<li>' + esc((d.missingRoles || []).length) + ' role(s) missing</li>' +
          '<li>' + esc((d.modifiedRoles || []).length) + ' role(s) modified</li>' +
          '<li>' + esc((d.missingChannels || []).length) + ' channel(s) missing</li>' +
          '</ul>');
      })
      .catch(function (err) { toast('Compare failed: ' + err.message, 'error'); });
  }

  function backupPreview(id) {
    api('/api/guilds/' + GUILD_ID + '/antinuke/backups/' + id + '/restore-preview')
      .then(function (data) {
        var ops = (data.plan && data.plan.ops) || [];
        backupReport('<div class="card-title"><span>Restore preview for #' + esc(id) + '</span></div>' +
          (ops.length ? '<ul class="an-diff-list">' + ops.slice(0, 50).map(function (op) {
            return '<li>' + esc(op.kind) + ' → ' + esc(op.payload && (op.payload.name || op.target) || op.target) + '</li>';
          }).join('') + '</ul>' : '<div class="an-empty">Nothing to restore — structure matches the snapshot.</div>') +
          '<div class="field-hint">Recreated roles/channels receive NEW ids.</div>');
      })
      .catch(function (err) { toast('Preview failed: ' + err.message, 'error'); });
  }

  function backupRestore(id) {
    if (!window.confirm('Restore snapshot #' + id + '? Missing roles/channels will be recreated with NEW ids. This is a bulk operation.')) return;
    api('/api/guilds/' + GUILD_ID + '/antinuke/backups/' + id + '/restore', { method: 'POST', body: JSON.stringify({ confirm: true }) })
      .then(function (data) {
        var r = data.report || {};
        toast('Restore complete', 'success');
        backupReport('<div class="card-title"><span>Restore report for #' + esc(id) + '</span></div>' +
          '<ul class="an-diff-list"><li>' + esc(r.summary.rolesCreated) + ' roles created</li><li>' + esc(r.summary.rolesUpdated) + ' roles updated</li>' +
          '<li>' + esc(r.summary.channelsCreated) + ' channels created</li><li>' + esc(r.summary.failed) + ' failed</li></ul>' +
          '<div class="field-hint">' + esc(r.note || '') + '</div>');
      })
      .catch(function (err) { toast('Restore failed: ' + err.message, 'error'); });
  }

  function backupDelete(id) {
    if (!window.confirm('Delete snapshot #' + id + '?')) return;
    api('/api/guilds/' + GUILD_ID + '/antinuke/backups/' + id, { method: 'DELETE' })
      .then(function () { toast('Snapshot deleted', 'success'); refreshBackups(); })
      .catch(function (err) { toast('Delete failed: ' + err.message, 'error'); });
  }

  // ── Health ────────────────────────────────────────────────────────────────

  function initHealth() {
    var run = $('#an-health-run');
    if (run) run.addEventListener('click', refreshHealth);
  }

  function refreshHealth() {
    var out = $('#an-health-result');
    if (!out) return;
    out.innerHTML = '<div class="an-empty">Running scan…</div>';
    api('/api/guilds/' + GUILD_ID + '/antinuke/health')
      .then(function (scan) {
        var checks = (scan && scan.checks) || [];
        if (!checks.length) { out.innerHTML = '<div class="an-empty">No checks returned.</div>'; return; }
        out.innerHTML = '<div class="an-health-list">' + checks.map(function (c) {
          var result = c.result || (c.ok ? 'PASS' : 'FAILED');
          var cls = result === 'PASS' ? 'pass' : (result === 'WARNING' ? 'warn' : 'fail');
          return '<div class="an-health-row an-health-' + cls + '">' +
            '<span class="an-health-badge">' + esc(cls.toUpperCase()) + '</span>' +
            '<span class="an-health-label">' + esc(c.label || c.key) + '</span>' +
            '<span class="an-health-detail">' + esc(c.note || c.detail || c.message || '') + '</span>' +
            (c.recommendation ? '<span class="an-health-fix">' + svg('wrench') + ' ' + esc(c.recommendation) + '</span>' : '') +
            '</div>';
        }).join('') + '</div>';
      })
      .catch(function (err) { out.innerHTML = '<div class="an-empty">Health scan failed: ' + esc(err.message) + '</div>'; });
  }

  // ── Lockdown profiles ─────────────────────────────────────────────────────

  function initLockdownProfiles() {
    $$('.an-lockdown-preview').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var profile = btn.dataset.profile;
        api('/api/guilds/' + GUILD_ID + '/antinuke/lockdown/profile/' + profile)
          .then(function (plan) {
            var ul = $('#an-profile-ops-' + profile);
            if (ul) ul.innerHTML = (plan.ops || []).slice(0, 40).map(function (op) {
              return '<li>' + esc(op.kind) + (op.name ? ' → ' + esc(op.name) : '') + '</li>';
            }).join('') || '<li>No changes needed.</li>';
          })
          .catch(function (err) { toast('Preview failed: ' + err.message, 'error'); });
      });
    });
    $$('.an-lockdown-engage-profile').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var profile = btn.dataset.profile;
        if (!window.confirm('Engage the ' + profile + ' lockdown profile? It saves what it changes so it can be restored.')) return;
        btn.disabled = true;
        api('/api/guilds/' + GUILD_ID + '/antinuke/lockdown', { method: 'POST', body: JSON.stringify({ action: 'engage', profile: profile }) })
          .then(function (data) {
            toast('Lockdown engaged', 'success');
            if (data && data.warnings && data.warnings.length) toast(data.warnings.join('; '), 'error');
            window.location.reload();
          })
          .catch(function (err) { btn.disabled = false; toast('Lockdown failed: ' + err.message, 'error'); });
      });
    });
  }

  // ── Incident filters ──────────────────────────────────────────────────────

  function initIncidentFilters() {
    var sev = $('#an-inc-severity');
    var act = $('#an-inc-action');
    var exec = $('#an-inc-executor');
    var range = $('#an-inc-range');
    var search = $('#an-inc-search');
    [sev, act, range].forEach(function (el) { if (el) el.addEventListener('change', function () { INCIDENT_FILTERS.page = 0; refreshIncidents(); }); });
    if (exec) exec.addEventListener('change', function () { INCIDENT_FILTERS.page = 0; refreshIncidents(); });
    if (search) {
      var t = null;
      search.addEventListener('input', function () {
        clearTimeout(t);
        t = setTimeout(function () { INCIDENT_FILTERS.search = search.value; INCIDENT_FILTERS.page = 0; refreshIncidents(); }, 300);
      });
    }
    var exp = $('#an-inc-export');
    if (exp) exp.addEventListener('click', exportIncidents);
  }

  function exportIncidents() {
    var qs = incidentQuery(100);
    api('/api/guilds/' + GUILD_ID + '/antinuke/incidents?' + qs)
      .then(function (data) {
        var rows = data.incidents || [];
        var head = ['id', 'createdAt', 'action', 'severity', 'executorId', 'executorName', 'count', 'threshold', 'windowSeconds', 'responseTaken', 'responseOk', 'attribution'];
        var csv = [head.join(',')].concat(rows.map(function (r) {
          return head.map(function (h) {
            var v = r[h];
            if (Array.isArray(v)) v = v.join('|');
            return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
          }).join(',');
        })).join('\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'antinuke-incidents.csv';
        document.body.appendChild(a); a.click(); a.remove();
        toast('Exported ' + rows.length + ' incidents', 'success');
      })
      .catch(function (err) { toast('Export failed: ' + err.message, 'error'); });
  }

  function incidentQuery(limit) {
    var params = ['limit=' + (limit || 25), 'offset=' + (INCIDENT_FILTERS.page * 25)];
    var sev = $('#an-inc-severity'); if (sev && sev.value) params.push('severity=' + encodeURIComponent(sev.value));
    var act = $('#an-inc-action'); if (act && act.value) params.push('action=' + encodeURIComponent(act.value));
    var exec = $('#an-inc-executor'); if (exec && exec.value) params.push('executorId=' + encodeURIComponent(exec.value));
    var range = $('#an-inc-range'); if (range && range.value) params.push('sinceDays=' + encodeURIComponent(range.value));
    if (INCIDENT_FILTERS.search) params.push('search=' + encodeURIComponent(INCIDENT_FILTERS.search));
    return params.join('&');
  }

  var INCIDENT_FILTERS = { page: 0, search: '' };

  // Patch the existing init functions to also start polling / render access.
  var _origInitSetup = initSetupView;
  initSetupView = function () {
    _origInitSetup();
    if (SETUP.status === 'in_progress' || SETUP.status === 'failed') startProgressPolling();
  };
  var _origInitConsole = initConsoleView;
  initConsoleView = function () {
    _origInitConsole();
    initConsoleViewExtra();
  };

  if (VIEW === 'wizard') initWizardView();
  else if (VIEW === 'console') initConsoleView();
  else initSetupView();
})();
