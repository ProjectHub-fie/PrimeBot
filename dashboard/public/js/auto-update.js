/* PrimeBot Dashboard — automatic deployment update detector.
 *
 * When a new Vercel deployment ships, an already-open tab must pick up the new
 * build WITHOUT the user manually refreshing. This script polls the deployed
 * `/version.json` (served with `Cache-Control: no-store`) every 60 seconds,
 * compares its `version` against the version this HTML was rendered from
 * (`window.__PRIMEBOT_DEPLOY__.version`), and reloads the page when they differ.
 *
 * Design goals / invariants:
 *   • No infinite reload loops. A reload is attempted at most once per new
 *     version; the version we reloaded to is remembered in sessionStorage, and
 *     a minimum cooldown guards against rapid cycling.
 *   • No duplicate reloads. A single in-flight/`reloading` flag means several
 *     concurrent checks can never trigger two reloads.
 *   • Route + query preserved. `location.reload()` re-requests the exact current
 *     URL (path, query and hash), so the user stays on the page they were on.
 *   • Never interrupt unsaved work. While `document.body.dataset.unsaved === '1'`
 *     (set by the floating Save bar) the reload is deferred and retried until the
 *     user saves/discards — no silent data loss.
 *   • Cheap when idle. Polling pauses entirely while the tab is hidden and
 *     resumes with an immediate check on `visibilitychange`/`focus`/`pageshow`.
 *   • Resilient. Network/parse errors never throw; the next tick retries.
 *
 * The factory is exported on `window.PrimeBotAutoUpdate` and accepts injected
 * dependencies so the behaviour is unit-testable in a vm sandbox (no real
 * network, timers, or DOM).
 */
(function () {
  'use strict';

  var DEFAULT_INTERVAL_MS = 60 * 1000;        // poll cadence (visible tab)
  var UNSAVED_RETRY_MS = 15 * 1000;           // re-check while unsaved edits exist
  var RELOAD_COOLDOWN_MS = 30 * 1000;         // minimum gap between reload attempts
  var STORAGE_APPLIED = 'primebot.update.applied';
  var STORAGE_RELOADED_AT = 'primebot.update.reloadedAt';

  function factory(opts) {
    opts = opts || {};
    var win = opts.window || (typeof window !== 'undefined' ? window : null);
    var doc = opts.document || (win && win.document) || (typeof document !== 'undefined' ? document : null);
    var loc = opts.location || (win && win.location) || (typeof location !== 'undefined' ? location : null);
    var fetchFn = opts.fetchFn || (win && win.fetch ? win.fetch.bind(win) : (typeof fetch !== 'undefined' ? fetch : null));
    var setTimeoutFn = opts.setTimeoutFn || (win && win.setTimeout ? win.setTimeout.bind(win) : setTimeout);
    var clearTimeoutFn = opts.clearTimeoutFn || (win && win.clearTimeout ? win.clearTimeout.bind(win) : clearTimeout);
    var nowFn = opts.nowFn || function () { return Date.now(); };
    var storage = opts.storage || safeSessionStorage(win);
    var versionUrl = opts.versionUrl || '/version.json';
    var intervalMs = opts.intervalMs || DEFAULT_INTERVAL_MS;
    var logger = opts.logger || function () {};

    // The version this page was rendered from. Never invent one — without it we
    // cannot compare, so detection is disabled (the server always injects it).
    var deploy = (win && win.__PRIMEBOT_DEPLOY__) || {};
    var loadedVersion = opts.loadedVersion != null ? opts.loadedVersion : (deploy.version || null);

    var timer = null;
    var running = false;
    var reloading = false;       // a reload is scheduled/underway
    var consecutiveErrors = 0;

    var state = {
      checks: 0,
      lastVersion: loadedVersion,
      pendingVersion: null,
      reloads: 0,
      errors: 0,
      hidden: false,
      paused: false,
    };

    function safeSessionStorage(w) {
      try {
        var s = w && w.sessionStorage;
        // Touch it — Safari private mode throws on access.
        if (s) { s.getItem(STORAGE_APPLIED); return s; }
      } catch (_) { /* fall through */ }
      var mem = {};
      return {
        getItem: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },
        setItem: function (k, v) { mem[k] = String(v); },
        removeItem: function (k) { delete mem[k]; },
      };
    }

    function isHidden() {
      return !!(doc && doc.hidden);
    }

    function hasUnsavedChanges() {
      try {
        var body = doc && doc.body;
        return !!(body && body.dataset && body.dataset.unsaved === '1');
      } catch (_) { return false; }
    }

    function clearTimer() {
      if (timer != null) {
        try { clearTimeoutFn(timer); } catch (_) { /* ignore */ }
        timer = null;
      }
    }

    function schedule(ms) {
      clearTimer();
      if (!running) return;
      timer = setTimeoutFn(tick, ms);
    }

    // A reload for `target` is only allowed once, and only after the cooldown.
    function alreadyReloadedTo(target) {
      try {
        var applied = storage.getItem(STORAGE_APPLIED);
        if (applied && applied === String(target)) return true;
      } catch (_) { /* ignore */ }
      return false;
    }

    function cooldownElapsed() {
      try {
        var last = parseInt(storage.getItem(STORAGE_RELOADED_AT), 10);
        if (!Number.isFinite(last)) return true;
        return (nowFn() - last) >= RELOAD_COOLDOWN_MS;
      } catch (_) { return true; }
    }

    function performReload(target) {
      if (reloading) return false;
      if (!loc) return false;
      if (alreadyReloadedTo(target)) {
        // We already reloaded for this version but are still on the old one —
        // e.g. an intermediate cache served stale HTML. Do NOT reload again
        // (that would loop). Leave it to the next real deployment.
        logger('[auto-update] already reloaded to ' + target + ' — skipping to avoid a loop');
        return false;
      }
      if (!cooldownElapsed()) {
        logger('[auto-update] reload cooldown active — deferring');
        return false;
      }
      reloading = true;
      state.reloads++;
      try {
        storage.setItem(STORAGE_APPLIED, String(target));
        storage.setItem(STORAGE_RELOADED_AT, String(nowFn()));
      } catch (_) { /* ignore */ }
      logger('[auto-update] new deployment ' + target + ' — reloading current route');
      // reload() re-requests the current URL (path + query + hash), preserving
      // the user's route and query parameters.
      try {
        if (typeof loc.reload === 'function') loc.reload();
        else if (typeof loc.assign === 'function') loc.assign(loc.href);
      } catch (_) { /* ignore */ }
      return true;
    }

    // Evaluate a freshly-fetched version. Returns true when a reload was
    // triggered (or is pending on unsaved changes).
    function evaluate(fetchedVersion) {
      state.lastVersion = fetchedVersion;
      if (!loadedVersion || !fetchedVersion) return false;
      if (String(fetchedVersion) === String(loadedVersion)) {
        // Back on the version we expect — clear any stale applied marker.
        try { storage.removeItem(STORAGE_APPLIED); } catch (_) { /* ignore */ }
        state.pendingVersion = null;
        return false;
      }
      // A different, non-empty version means a new deployment is live.
      state.pendingVersion = fetchedVersion;
      if (hasUnsavedChanges()) {
        // Never yank the page out from under unsaved edits. Keep the pending
        // version and retry soon (the user may save/discard at any moment).
        logger('[auto-update] update pending but there are unsaved changes — deferring');
        return false;
      }
      return performReload(fetchedVersion);
    }

    function tick() {
      if (!running) return;
      if (isHidden()) {
        // Tab is hidden: stop polling to save battery/bandwidth. We re-check
        // immediately when it becomes visible again.
        state.hidden = true;
        return;
      }
      state.hidden = false;
      if (reloading) return;
      if (!fetchFn) { schedule(intervalMs); return; }

      var url = versionUrl + (versionUrl.indexOf('?') === -1 ? '?' : '&') + '_=' + nowFn();
      var promise;
      try {
        promise = fetchFn(url, {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' },
        });
      } catch (err) {
        state.errors++;
        consecutiveErrors++;
        logger('[auto-update] fetch threw: ' + (err && err.message));
        schedule(intervalMs);
        return;
      }

      Promise.resolve(promise).then(function (res) {
        if (!res || res.ok === false || (typeof res.status === 'number' && res.status >= 400)) {
          throw new Error('bad status ' + (res && res.status));
        }
        return res.json();
      }).then(function (data) {
        consecutiveErrors = 0;
        state.checks++;
        var v = data && (data.version != null ? data.version : data.commit);
        if (v == null) return;
        var reloaded = evaluate(v);
        // If an update is pending (e.g. deferred for unsaved changes), retry
        // sooner than the full interval so the reload happens promptly once the
        // user finishes.
        if (state.pendingVersion && !reloaded) {
          schedule(UNSAVED_RETRY_MS);
        } else {
          schedule(intervalMs);
        }
      }).catch(function (err) {
        // Network error / non-JSON / offline — never throw; retry later.
        state.errors++;
        consecutiveErrors++;
        logger('[auto-update] check failed: ' + (err && err.message));
        schedule(intervalMs);
      });
    }

    function onVisibility() {
      if (!running) return;
      if (isHidden()) {
        state.hidden = true;
        clearTimer();     // pause polling while hidden
        return;
      }
      // Became visible — check right away, then resume the normal cadence.
      state.hidden = false;
      clearTimer();
      tick();
    }

    function start() {
      if (running) return manager;
      running = true;
      if (doc && typeof doc.addEventListener === 'function') {
        doc.addEventListener('visibilitychange', onVisibility);
      }
      if (win && typeof win.addEventListener === 'function') {
        win.addEventListener('focus', onVisibility);
        win.addEventListener('pageshow', onVisibility);
      }
      // Clear a stale "applied" marker once we are actually running that version.
      try {
        if (loadedVersion && storage.getItem(STORAGE_APPLIED) === String(loadedVersion)) {
          storage.removeItem(STORAGE_APPLIED);
        }
      } catch (_) { /* ignore */ }
      // First check after a short delay so it never competes with page load.
      schedule(intervalMs);
      return manager;
    }

    function stop() {
      running = false;
      clearTimer();
      if (doc && typeof doc.removeEventListener === 'function') {
        doc.removeEventListener('visibilitychange', onVisibility);
      }
      if (win && typeof win.removeEventListener === 'function') {
        win.removeEventListener('focus', onVisibility);
        win.removeEventListener('pageshow', onVisibility);
      }
      return manager;
    }

    function checkNow() { tick(); }

    var manager = {
      start: start,
      stop: stop,
      checkNow: checkNow,
      evaluate: evaluate,
      state: state,
      loadedVersion: loadedVersion,
      get reloading() { return reloading; },
    };
    return manager;
  }

  if (typeof window !== 'undefined') {
    window.PrimeBotAutoUpdate = factory;
    // Auto-start on a real page (a test harness sets the opt-out flag).
    if (!window.__PRIMEBOT_AUTOUPDATE_TEST__ && window.document) {
      try { factory().start(); } catch (_) { /* never break the page */ }
    }
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory;
  }
})();
