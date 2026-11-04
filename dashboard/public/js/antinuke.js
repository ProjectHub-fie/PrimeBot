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

  var ACTIONS = window.__ANTINUKE_ACTIONS || [];
  var MODULES = window.__ANTINUKE_MODULES || [];
  var SETTINGS = window.__ANTINUKE_SETTINGS || {};
  var SETUP = window.__ANTINUKE_SETUP || { status: 'not_started' };
  var VIEW = window.__ANTINUKE_VIEW || 'setup';

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

  /* Drive the automatic setup one step at a time, rendering real progress after
   * each step. Stops on a failed step so the admin can see it and retry. */
  function runAutomaticSteps() {
    setSetupButtonsBusy(true);
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/step', { method: 'POST', body: JSON.stringify({ method: 'automatic' }) })
      .then(function (data) {
        renderProgress(data.progress);
        if (data.done) {
          toast('Anti-Nuke setup completed', 'success');
          window.location.href = window.location.pathname;
          return;
        }
        if (data.progress && data.progress.failed > 0) {
          // Retain the last accurate progress and surface a retry action.
          var failed = (data.progress.steps || []).filter(function (s) { return s.status === 'failed'; });
          setSetupButtonsBusy(false);
          var resume = $('#an-resume-setup'); if (resume) resume.hidden = false;
          var reset = $('#an-reset-setup'); if (reset) reset.hidden = false;
          toast((failed.length ? ('Step failed: ' + failed[0].label) : 'A setup step failed.') +
            (failed.length && failed[0].error ? (' — ' + failed[0].error) : '') +
            ' Press Resume setup to retry.', 'error');
          return;
        }
        runAutomaticSteps();
      })
      .catch(function (err) {
        setSetupButtonsBusy(false);
        var resume = $('#an-resume-setup'); if (resume) resume.hidden = false;
        toast('Setup step failed: ' + err.message, 'error');
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
        var required = key !== 'trust';
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
    // Resume at the first section that is not yet completed (so a return to the
    // wizard picks up where the admin left off rather than restarting at 1).
    var firstIncomplete = 0;
    for (var i = 0; i < sections.length; i++) {
      if (!completed[sections[i].getAttribute('data-section')]) { firstIncomplete = i; break; }
      if (i === sections.length - 1) firstIncomplete = i;
    }
    show(firstIncomplete);
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

  function initActivity() {
    var body = $('#an-activity-body');
    if (!body) return;
    var offset = 0, limit = 25, total = 0;
    function load() {
      api('/api/guilds/' + GUILD_ID + '/antinuke/incidents?limit=' + limit + '&offset=' + offset)
        .then(function (data) {
          total = data.total || 0;
          var rows = data.incidents || [];
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="an-empty">No incidents detected yet.</td></tr>';
          } else {
            body.innerHTML = rows.map(function (inc) {
              var exec = inc.executorId ? ('<@' + inc.executorId + '>') : '<span class="an-muted">unknown</span>';
              var resp = (inc.responseTaken || []).join(', ') || '—';
              var result = inc.responseOk ? '<span class="an-ok">ok</span>' : '<span class="an-bad">partial/failed</span>';
              var mode = inc.dryRun ? 'dry-run' : 'live';
              return '<tr>' +
                '<td>' + esc(new Date(inc.createdAt).toLocaleString()) + '</td>' +
                '<td>' + exec + '</td>' +
                '<td><span class="an-sev an-sev-' + esc(inc.severity) + '">' + esc(inc.severity) + '</span></td>' +
                '<td>' + esc(inc.count) + ' / ' + esc(inc.threshold) + ' in ' + esc(inc.windowSeconds) + 's</td>' +
                '<td>' + esc(resp) + '</td>' +
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
          body.innerHTML = '<tr><td colspan="7" class="an-empty">Could not load activity: ' + esc(err.message) + '</td></tr>';
        });
    }
    var prev = $('#an-activity-prev');
    if (prev) prev.addEventListener('click', function () { offset = Math.max(0, offset - limit); load(); });
    var next = $('#an-activity-next');
    if (next) next.addEventListener('click', function () { offset += limit; load(); });
    load();
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
    return {
      enabled: $('#an-enabled') ? $('#an-enabled').checked : (SETTINGS.enabled === true),
      dryRun: $('#an-dry-run') ? $('#an-dry-run').checked : (SETTINGS.dryRun !== false),
      alertChannelId: ($('#an-alert-channel') && $('#an-alert-channel').value) || null,
      responses: $$('.an-response-cb').filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; }),
      dangerousPermissions: $$('.an-danger-perm').filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; }),
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

  // ── Boot ──────────────────────────────────────────────────────────────────

  if (VIEW === 'wizard') initWizardView();
  else if (VIEW === 'console') initConsoleView();
  else initSetupView();
})();
