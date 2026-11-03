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

  function renderProgress(progress) {
    if (!progress) return;
    var fill = $('.an-progress-fill');
    if (fill) fill.style.width = (progress.percent || 0) + '%';
    var meta = $('.an-progress-meta');
    if (meta) {
      meta.innerHTML = '<strong>' + (progress.percent || 0) + '%</strong> · ' +
        (progress.completed || 0) + ' of ' + (progress.total || 0) + ' required steps completed';
    }
    renderStepList($('.an-step-list'), progress.steps);
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
  }

  function startSetup(method) {
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/start', {
      method: 'POST', body: JSON.stringify({ method: method }),
    }).then(function () {
      toast('Setup started', 'success');
      if (method === 'manual') window.location.href = window.location.pathname + '?view=wizard';
      else runAutomaticSteps();
    }).catch(function (err) { toast('Could not start setup: ' + err.message, 'error'); });
  }

  function resumeSetup() {
    var method = (SETUP && SETUP.method) || 'automatic';
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/resume', { method: 'POST', body: JSON.stringify({ method: method }) })
      .then(function () {
        if (method === 'manual') window.location.href = window.location.pathname + '?view=wizard';
        else runAutomaticSteps();
      })
      .catch(function (err) { toast('Could not resume: ' + err.message, 'error'); });
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
    var btn = $('#an-resume-setup');
    if (btn) btn.disabled = true;
    api('/api/guilds/' + GUILD_ID + '/antinuke/setup/step', { method: 'POST', body: JSON.stringify({ method: 'automatic' }) })
      .then(function (data) {
        renderProgress(data.progress);
        if (data.done) {
          toast('Anti-Nuke setup completed', 'success');
          window.location.href = window.location.pathname;
          return;
        }
        if (data.progress && data.progress.failed > 0) {
          var failed = (data.progress.steps || []).filter(function (s) { return s.status === 'failed'; });
          toast((failed.length ? ('Step failed: ' + failed[0].label) : 'A setup step failed.') + ' — fix it and press Resume setup to retry.', 'error');
          if (btn) btn.disabled = false;
          return;
        }
        runAutomaticSteps();
      })
      .catch(function (err) {
        toast('Setup step failed: ' + err.message, 'error');
        if (btn) btn.disabled = false;
      });
  }

  // ── Manual wizard ─────────────────────────────────────────────────────────

  function initWizardView() {
    var sections = $$('.an-wizard-section');
    if (!sections.length) return;
    var index = 0;
    var completed = {};

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
        var status = completed[key] ? 'completed' : (n === index ? 'running' : 'pending');
        return { key: key, label: sectionLabel(sec, n), required: required, status: status };
      });
      var required = steps.filter(function (s) { return s.required; });
      var done = required.filter(function (s) { return s.status === 'completed'; }).length;
      var percent = required.length ? Math.round((done / required.length) * 100) : 0;
      var fill = $('#an-wizard-fill'); if (fill) fill.style.width = percent + '%';
      var pct = $('#an-wizard-percent'); if (pct) pct.textContent = percent + '%';
      var count = $('#an-wizard-count'); if (count) count.textContent = done + ' of ' + required.length + ' sections completed';
      renderStepList($('#an-wizard-steps'), steps);
    }

    function markCurrentComplete() {
      completed[sections[index].getAttribute('data-section')] = true;
      persistManualProgress();
    }

    function persistManualProgress() {
      api('/api/guilds/' + GUILD_ID + '/antinuke/setup/progress', {
        method: 'PATCH', body: JSON.stringify({ method: 'manual', completed: Object.keys(completed) }),
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
    show(0);
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
