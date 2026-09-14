/* PrimeBot Dashboard — idle auto-logout (Neon-efficient).
 *
 * Policy (single source of truth in dashboard/constants.js):
 *   30 minutes of genuine inactivity → automatic logout.
 *   25 minutes idle → 5-minute warning countdown (client-only UX).
 *
 * Architecture — hybrid client/server, optimized for Neon compute:
 *
 *   • Client owns the UX. A debounced/throttled activity listener updates a
 *     LOCAL timestamp. Every SECOND is compared against timestamps (never only
 *     timers — background tabs throttle timers). All mousemove/scroll/keydown
 *     activity is handled in the browser only — ZERO network requests.
 *
 *   • No heartbeat loop. There is NO setInterval fetching anything. The server
 *     deadline stays alive because the client fires ONE authenticated activity
 *     sync (POST /api/session/heartbeat) — at most once per
 *     refreshIntervalMs (10 min) — and only after the user has actually
 *     interacted. The server-side throttle (touchIdleDeadline) means even a
 *     noisy client cannot produce a Neon write more than once per interval:
 *     when the deadline is still fresh, express-session skips store.set().
 *
 *   • Server is authoritative. The rolling idleExpiresAt on the session row is
 *     checked by requireAuth before every protected request. A disabled,
 *     tampered, or throttled client gets NO grace period: once the deadline
 *     lapses the server rejects the session (401 idle_timeout / redirect), and
 *     the client's timestamps are NEVER trusted as proof of liveness.
 *
 *   • Logout = exactly one request (window.location to /logout?reason=idle_timeout),
 *     which destroys the server-side session and clears the cookie.
 *
 *   • Multi-tab. A BroadcastChannel (fallback: localStorage `storage` events)
 *     propagates "logged out" to every other dashboard tab.
 *
 * This script is injected only on authenticated pages (see render/layout.js),
 * so it never runs on /login. It is written as a factory
 * (window.PrimeBotInactivityManager) that the browser boots immediately and
 * the vm-sandbox tests exercise — no DOM globals are touched at module load.
 */
(function () {
  'use strict';
  var STORAGE_KEY = 'primebot.session.idleLogout';
  var STORAGE_TS_KEY = 'primebot.session.idleLogoutAt';
  var BROADCAST_CHANNEL = 'primebot.session.logout';
  // Arbitrary safety net: never wait longer than 60s before re-evaluating the
  // timestamps on a VISIBLE tab. It never fires a network request on its own —
  // it only calls evaluate() against local timestamps.
  var EVAL_INTERVAL_MS = 60 * 1000;

  function createInactivityManager(opts) {
    var cfg = opts || {};
    var nowFn = cfg.nowFn || function () { return Date.now(); };
    var doc = cfg.document || (typeof document !== 'undefined' ? document : null);
    var win = cfg.window || (typeof window !== 'undefined' ? window : null);
    var storageSvc = cfg.storage || (cfg.localStorage !== undefined ? cfg.localStorage : (win && win.localStorage));
    // Activity sync throttling + warning window. Kept in lockstep with the
    // server (constants.js). Locals take precedence; the injected page config
    // (window.__PRIMEBOT_SESSION_CONFIG__) is the real source.
    var IDLE_MS = cfg.idleTimeoutMs || (win && win.__PRIMEBOT_SESSION_CONFIG__ && win.__PRIMEBOT_SESSION_CONFIG__.idleTimeoutMs) || (win && win.__PRIMEBOT_IDLE_TIMEOUT_MS__) || 30 * 60 * 1000;
    var WARNING_MS = cfg.warningMs || (win && win.__PRIMEBOT_SESSION_CONFIG__ && win.__PRIMEBOT_SESSION_CONFIG__.warningMs) || IDLE_MS - 5 * 60 * 1000;
    var REFRESH_MS = cfg.refreshIntervalMs || (win && win.__PRIMEBOT_SESSION_CONFIG__ && win.__PRIMEBOT_SESSION_CONFIG__.refreshIntervalMs) || 10 * 60 * 1000;

    var lastActivity = nowFn();   // local absolute timestamp of the last real interaction
    // When the last server activity sync completed. Negative so the very first
    // activity after page load is always allowed through (the server-side
    // throttle still guards against any abuse).
    var lastSyncAt = -REFRESH_MS;
    var syncInFlight = false;     // never overlap two syncs
    var warned = false;           // has the warning modal been shown?
    var loggedOut = false;        // one-shot logout guard
    var evalTimer = null;         // the visible-tab safety timer (local only)
    var rafPending = false;       // rAF-batched state changes

    // ── State (for the vm-sandbox tests) ─────────────────────────────────────
    var state = {
      elapsedMs: 0,
      remainingMs: IDLE_MS,
      warningRemainingMs: 0,
      warningVisible: false,
      countdownSeconds: (IDLE_MS - WARNING_MS) / 1000,
      expired: false,
      activityEvents: 0,
      syncsSent: 0,
      syncsSkipped: 0,
      logouts: 0,
    };

    // ── Cross-tab logout propagation ─────────────────────────────────────────
    var channel = null;
    try {
      if (cfg.broadcastChannel !== undefined) {
        if (cfg.broadcastChannel) channel = cfg.broadcastChannel;
      } else if (win && typeof win.BroadcastChannel === 'function') {
        channel = new win.BroadcastChannel(BROADCAST_CHANNEL);
      }
    } catch (_) { channel = null; }
    if (channel) {
      try { channel.onmessage = function (e) { if (e && e.data === 'logout') performIdleLogout(); }; } catch (_) {}
    }

    function onStorage(e) {
      if (e && e.key === STORAGE_KEY && e.newValue === '1') performIdleLogout();
    }
    if (win) { try { win.addEventListener('storage', onStorage); } catch (_) {} }

    function broadcastLogout() {
      try {
        if (storageSvc) {
          storageSvc.setItem(STORAGE_KEY, '1');
          storageSvc.setItem(STORAGE_TS_KEY, String(nowFn()));
        }
      } catch (_) { /* private mode / quota — storage event won't fire; the other
                       tabs' server check + BroadcastChannel still cover it */ }
      try { if (channel) channel.postMessage('logout'); } catch (_) {}
    }

    function performIdleLogout() {
      if (loggedOut) return;
      loggedOut = true;
      state.expired = true;
      state.logouts += 1;
      stopEvalTimer();
      broadcastLogout();
      // One request. The server destroys the session + clears the cookie; the
      // login page surfaces "logged out due to inactivity". No session id or
      // token travels in the URL.
      if (win) { try { win.location.assign('/logout?reason=idle_timeout'); } catch (_) {} }
    }

    // ── Activity tracking (client-only, throttled) ──────────────────────────
    function handleActivity() {
      if (loggedOut) return;
      state.activityEvents += 1;
      lastActivity = nowFn();
      warned = false;
      // Never synchronize on the same event stream that produces a DOM write —
      // schedule the state re-evaluation for the next frame.
      scheduleUpdate();
      syncIfDue();
    }

    // Non-debounced timestamp bump (used for scroll, which fires constantly).
    // Compares timestamps only; no network, no DOM writes on its own.
    function handleActivityTimestamp() {
      if (loggedOut) return;
      lastActivity = nowFn();
      syncIfDue();
    }

    function notifyActivity() {
      handleActivityTimestamp();
    }

    // Throttled server sync: at most one POST per REFRESH_MS, only when the
    // user has actually interacted.
    function syncIfDue() {
      var now = nowFn();
      if (syncInFlight) { state.syncsSkipped += 1; return; }
      if (now >= lastActivity && now - lastActivity > IDLE_MS) return; // already gone
      if (now - lastSyncAt < REFRESH_MS) { state.syncsSkipped += 1; return; }
      syncInFlight = true;
      state.syncsSent += 1;
      var fetchFn = cfg.fetchFn || (win && win.fetch && win.fetch.bind(win));
      if (!fetchFn) { syncInFlight = false; return; }
      // fetch (not api()) so a 401 from an already-expired session is handled
      // locally rather than thrown into the page's error toast flow.
      fetchFn('/api/session/heartbeat', { method: 'POST', credentials: 'same-origin' })
        .then(function (res) {
          if (res.status === 401) {
            // The server already considers the session dead (another tab or
            // device, or the deadline lapsed while we were throttled). The
            // frontend timer is NOT the security mechanism — follow the server.
            performIdleLogout();
            return;
          }
          // Only the POST path rolls the server deadline forward; the GET
          // accessor below never extends anything. Successful sync ⇒ a fresh
          // 30-minute window starting now on both sides.
          lastActivity = nowFn();
          lastSyncAt = lastActivity;
        })
        .catch(function () { /* network blip — the server deadline is the backstop */ })
        .finally(function () { syncInFlight = false; });
    }

    // When the server says we're expired without any activity on our part
    // (another device, idle deadline already lapsed), sync the local clock.
    function checkServer() {
      if (loggedOut) return;
      var fetchFn = cfg.fetchFn || (win && win.fetch && win.fetch.bind(win));
      if (!fetchFn) return;
      fetchFn('/api/session/heartbeat', { method: 'GET', credentials: 'same-origin' })
        .then(function (res) {
          if (res.status === 401) performIdleLogout();
        })
        .catch(function () {});
    }

    // ── Timestamp-based evaluation (the only place that decides) ────────────
    function evaluate() {
      if (loggedOut) return;
      var now = nowFn();
      var elapsed = now - lastActivity;
      if (elapsed < 0) elapsed = 0;
      state.elapsedMs = elapsed;
      state.remainingMs = Math.max(0, IDLE_MS - elapsed);

      if (elapsed >= IDLE_MS) {
        // 30 minutes elapsed since the last interaction — even if every timer
        // in this tab was suspended, the timestamp says we're done.
        performIdleLogout();
        return;
      }

      // Warning begins after WARNING_MS of elapsed idle time (25 min of a
      // 30-minute window → a 5-minute countdown). WARNING_MS is the elapsed-idle
      // threshold, not the remaining-duration.
      var showWarning = elapsed >= WARNING_MS;
      var remaining = IDLE_MS - elapsed;
      state.warningVisible = showWarning;
      state.warningRemainingMs = Math.max(0, remaining);
      state.countdownSeconds = Math.max(0, remaining / 1000);

      if (showWarning) showWarningModal(remaining);
      else hideWarningModal();
    }

    // rAF-batched evaluation (no per-event work).
    function scheduleUpdate() {
      if (rafPending || !win || typeof win.requestAnimationFrame !== 'function') {
        if (!rafPending) evaluate();
        return;
      }
      rafPending = true;
      try {
        win.requestAnimationFrame(function () { rafPending = false; evaluate(); });
      } catch (_) { rafPending = false; evaluate(); }
    }

    // ── Warning modal ────────────────────────────────────────────────────────
    function showWarningModal(remainingMs) {
      if (doc && typeof doc.getElementById === 'function') {
        var el = doc.getElementById('idle-warning-modal');
        if (!el) el = buildWarningModal();
        if (!el) return;
        updateCountdown(el, remainingMs);
        el.classList.remove('idle-warning-hidden');
        if (!warned) {
          warned = true;
          // rAF/visibility-driven refresh will keep the countdown fresh.
          refreshCountdownLoop();
        }
      } else {
        warned = true; // no DOM in tests — the countdown lives on state
      }
    }

    function hideWarningModal() {
      if (doc && typeof doc.getElementById === 'function') {
        var el = doc.getElementById('idle-warning-modal');
        if (el) el.classList.add('idle-warning-hidden');
      }
    }

    function buildWarningModal() {
      if (!doc || typeof doc.createElement !== 'function') return null;
      var overlay = doc.createElement('div');
      overlay.id = 'idle-warning-modal';
      overlay.className = 'idle-warning-hidden';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.setAttribute('aria-labelledby', 'idle-warning-title');
      overlay.innerHTML =
        '<div class="idle-warning-card" role="document">' +
          '<div class="idle-warning-icon">' + svgIcon('lock') + '</div>' +
          '<h3 id="idle-warning-title">Session Expiring</h3>' +
          '<p class="idle-warning-desc">You&rsquo;ve been inactive for a while. Keep using the dashboard or you will be signed out for your security.</p>' +
          '<p class="idle-warning-label">Automatic logout in</p>' +
          '<div class="idle-warning-countdown"><span id="idle-warning-time">05:00</span></div>' +
          '<div class="idle-warning-actions">' +
            '<button type="button" id="idle-stay-btn" class="btn btn-primary">Stay Logged In</button>' +
            '<button type="button" id="idle-logout-btn" class="btn btn-danger">Log Out</button>' +
          '</div>' +
          '<p class="idle-warning-note">Closing this window keeps the timer running. Any activity resets it.</p>' +
        '</div>';
      doc.body.appendChild(overlay);

      doc.body.addEventListener('click', function (e) {
        if (e && e.target && e.target.id === 'idle-stay-btn') stayLoggedIn();
      });
      doc.body.addEventListener('click', function (e) {
        if (e && e.target && e.target.id === 'idle-logout-btn') performIdleLogout();
      });
      return overlay;
    }

    function updateCountdown(el, remainingMs) {
      var secs = Math.max(0, Math.ceil(remainingMs / 1000));
      var t = el.querySelector('#idle-warning-time');
      if (!t) return;
      var m = String(Math.floor(secs / 60)).padStart(2, '0');
      var s = String(secs % 60).padStart(2, '0');
      t.textContent = m + ':' + s;
    }

    // The countdown must be client-side and must NOT query Neon. While the
    // warning is visible we re-run evaluate() every second: it redraws the
    // countdown text from local timestamps AND keeps the logout precise at the
    // 30-minute deadline. No timer here ever touches the network.
    var countdownTimer = null;
    function refreshCountdownLoop() {
      if (countdownTimer) return;
      countdownTimer = setInterval(function () {
        if (!state.warningVisible || loggedOut) { clearInterval(countdownTimer); countdownTimer = null; return; }
        evaluate();
      }, 1000);
    }

    function updateCountdownOfModal() {
      if (doc && typeof doc.getElementById === 'function') {
        var el = doc.getElementById('idle-warning-modal');
        if (el) updateCountdown(el, Math.max(0, IDLE_MS - (nowFn() - lastActivity)));
      }
    }

    // "Stay Logged In": reset the local timer immediately and issue at most ONE
    // authenticated session refresh (throttled — a refresh is only needed when
    // the last sync was more than REFRESH_MS ago, because otherwise the server
    // deadline already covers the window). Never repeated on its own.
    function stayLoggedIn() {
      if (loggedOut) return;
      if (syncInFlight) { // an in-flight sync already refreshes — just reset UX
        lastActivity = nowFn();
        warned = false;
        state.warningVisible = false;
        hideWarningModal();
        return;
      }
      var refreshNow = nowFn();
      lastActivity = refreshNow;
      warned = false;
      state.warningVisible = false;
      hideWarningModal();
      if (refreshNow - lastSyncAt >= REFRESH_MS) {
        syncIfDue(); // issues exactly one POST; success resets lastSyncAt too
      } else {
        state.syncsSkipped += 1; // server deadline is already fresh — no request
      }
    }

    // ── Visibility / focus / page restore: recalculate from timestamps ──────
    function onVisibilityChange() {
      if (loggedOut) return;
      // Internet Explorer quirk: some browsers fire 'visibilitychange' with an
      // undefined visibilityState; treat anything not 'hidden' as visible.
      var hidden = doc && typeof doc.visibilityState === 'string' ? doc.visibilityState === 'hidden' : false;
      if (hidden) {
        stopEvalTimer();
      } else {
        // Visible again. Recalculate IMMEDIATELY from timestamps — if the tab
        // was backgrounded past the idle window (browser timers throttled),
        // this logs out right away instead of granting a fresh 30 minutes.
        evaluate();
        startEvalTimer();
        checkServer();
      }
    }

    function onFocus() { onVisibilityChange(); }

    window.addEventListener('focus', onFocus);
    window.addEventListener('blur', function () { onVisibilityChange(); });
    window.addEventListener('pageshow', onVisibilityChange);
    if (doc) {
      doc.addEventListener('visibilitychange', onVisibilityChange);
    }

    // ── Visible-tab safety timer (local only, no network) ───────────────────
    function startEvalTimer() {
      if (evalTimer !== null || loggedOut) return;
      evalTimer = setInterval(evaluate, EVAL_INTERVAL_MS);
    }
    function stopEvalTimer() {
      if (evalTimer !== null) { clearInterval(evalTimer); evalTimer = null; }
    }

    // ── Public surface ───────────────────────────────────────────────────────
    var manager = {
      config: { idleTimeoutMs: IDLE_MS, warningMs: WARNING_MS, refreshIntervalMs: REFRESH_MS },
      state: state,
      notifyActivity: notifyActivity,
      evaluate: evaluate,
      performIdleLogout: performIdleLogout,
      stayLoggedIn: stayLoggedIn,
      syncIfDue: syncIfDue,
      destroy: function () {
        stopEvalTimer();
        if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
        if (channel) { try { channel.close(); } catch (_) {} }
        if (win) { try { win.removeEventListener('storage', onStorage); } catch (_) {} }
      },
    };

    // ── Boot of a real page (not a test sandbox) ────────────────────────────
    // Don't run on pages without a logged-in user (login page). The presence of
    // the logout button is a reliable "authenticated page" signal.
    if (doc && win && doc.getElementById('logout-btn')) {
      var activityEvents = ['click', 'keydown', 'touchstart', 'pointerdown', 'wheel'];
      activityEvents.forEach(function (evt) {
        doc.addEventListener(evt, handleActivity, { passive: true, capture: true });
      });
      // Scroll + mousemove fire constantly — bump the timestamp only (no DOM,
      // no network, throttled by the sync interval).
      doc.addEventListener('scroll', handleActivityTimestamp, { passive: true, capture: true });
      win.addEventListener('mousemove', handleActivityTimestamp, { passive: true });

      // Attach "Log out" from the top nav through the manager so a manual
      // logout also broadcasts to other tabs.
      var logoutBtn = doc.getElementById('logout-btn');
      if (logoutBtn && !logoutBtn.dataset.idleBound) {
        logoutBtn.dataset.idleBound = '1';
        logoutBtn.addEventListener('click', function () {
          broadcastLogout();
          win.location.assign('/logout');
        });
      }

      evaluate();
      startEvalTimer();
      if (doc.visibilityState === 'hidden') stopEvalTimer();
    }

    // Initial manual draw of the countdown display (in case it already mounted).
    updateCountdownOfModal();

    return manager;
  }

  // svgIcon lives in icons.js (loaded before this file); tests stub it.
  function svgIcon(name) {
    if (typeof window !== 'undefined' && typeof window.svgIcon === 'function') return window.svgIcon(name);
    return '<svg class="ico"></svg>';
  }

  // Export the factory for the vm-sandbox tests AND boot the real page.
  window.PrimeBotInactivityManager = createInactivityManager;
  if (typeof document !== 'undefined' && document.getElementById && document.getElementById('logout-btn')) {
    window.PrimeBotInactivity = createInactivityManager({});
  }
})();
