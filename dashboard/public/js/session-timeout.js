/* PrimeBot Dashboard — idle auto-logout.
 *
 * Goal: keep the session alive while the dashboard tab is actively visible, and
 * automatically log the user out when the tab has been inactive (hidden /
 * backgrounded / minimized) for SESSION_IDLE_TIMEOUT_MS (default 120s).
 *
 * How it works (two cooperating layers):
 *
 *   1. Client countdown (this file). The Page Visibility API tells us when the
 *      tab becomes hidden. At that moment we record `hiddenAt` and arm a
 *      setTimeout for the idle window. Browsers throttle background timers, so
 *      when the tab becomes visible again we ALSO compare now - hiddenAt: if it
 *      already exceeds the window we log out immediately, otherwise we cancel
 *      the pending timer (the user came back in time).
 *
 *   2. Server heartbeat. While the tab is visible we POST /api/session/heartbeat
 *      on a short interval, which refreshes the server-side idle deadline. This
 *      is the safety net: if the client JS can't run its timer (tab closed,
 *      process killed, timer throttled past the window), the server still
 *      expires the session and requireAuth bounces the next request to
 *      /login?error=idle_timeout.
 *
 * Multi-tab coordination: when one tab logs out (idle or manual), it writes a
 * `storage` event that the other tabs hear and follow, so a session isn't left
 * half-alive across windows. We also re-check the server deadline on focus so a
 * session expired in another tab/device is caught promptly.
 *
 * This script is injected only on authenticated pages (see render/layout.js),
 * so it never runs on /login.
 */
(function () {
  const IDLE_MS = parseInt(window.__PRIMEBOT_IDLE_TIMEOUT_MS__, 10) || 120000;
  // Heartbeat at ~1/4 of the idle window, clamped to [10s, 60s]. Frequent
  // enough to keep the server deadline fresh, sparse enough to avoid noise.
  const HEARTBEAT_MS = Math.min(60000, Math.max(10000, Math.floor(IDLE_MS / 4)));
  const STORAGE_KEY = 'primebot.session.idleLogout';
  const STORAGE_TS_KEY = 'primebot.session.idleLogoutAt';

  let hideTimer = null;        // setTimeout id for the background countdown
  let hiddenAt = null;         // timestamp when the tab last became hidden
  let heartbeatTimer = null;   // setInterval id for the visible-tab heartbeat
  let loggingOut = false;      // guard so we only fire the logout once

  function isHidden() {
    return document.visibilityState === 'hidden';
  }

  // Navigate to /logout?reason=idle_timeout so the server destroys the session
  // and the login page shows the "logged out due to inactivity" message.
  function performIdleLogout() {
    if (loggingOut) return;
    loggingOut = true;
    try {
      // Tell other tabs (same browser) to log out too — they share the session
      // cookie, so leaving them half-logged-in would just 401 on the next call.
      localStorage.setItem(STORAGE_KEY, '1');
      localStorage.setItem(STORAGE_TS_KEY, String(Date.now()));
    } catch (_) { /* localStorage may be unavailable (private mode) — ignore */ }
    window.location.assign('/logout?reason=idle_timeout');
  }

  function clearHideTimer() {
    if (hideTimer !== null) { clearTimeout(hideTimer); hideTimer = null; }
    hiddenAt = null;
  }

  function startHeartbeat() {
    if (heartbeatTimer !== null) return;
    // Fire one immediately (sync the server deadline), then on the interval.
    sendHeartbeat();
    heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_MS);
  }

  function stopHeartbeat() {
    if (heartbeatTimer !== null) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
  }

  function sendHeartbeat() {
    if (loggingOut || isHidden()) return;
    // fetch (not api()) so a 401 from an already-expired session is handled
    // locally here rather than thrown into the page's error toast flow.
    fetch('/api/session/heartbeat', { method: 'POST', credentials: 'same-origin' })
      .then((res) => {
        if (res.status === 401) {
          // Server already expired the session (e.g. another device logged out,
          // or the deadline lapsed while the tab was throttled). Follow it.
          performIdleLogout();
        }
      })
      .catch(() => { /* network blip — the server deadline is the backstop */ });
  }

  function onVisibilityChange() {
    if (isHidden()) {
      // Tab just went inactive: stop refreshing the server deadline and arm the
      // local countdown.
      stopHeartbeat();
      hiddenAt = Date.now();
      clearHideTimer();
      hideTimer = setTimeout(performIdleLogout, IDLE_MS);
    } else {
      // Tab is visible again. If it was hidden long enough that the window
      // already elapsed (browsers throttle background timers, so the setTimeout
      // above may not have fired yet), log out now. Otherwise cancel the timer
      // — the user came back in time — and resume heartbeating.
      if (hiddenAt !== null && Date.now() - hiddenAt >= IDLE_MS) {
        performIdleLogout();
        return;
      }
      clearHideTimer();
      startHeartbeat();
    }
  }

  // Cross-tab: another tab logged out (idle or manual). Follow it so no tab is
  // left showing stale authenticated UI.
  function onStorage(e) {
    if (e.key === STORAGE_KEY && e.newValue === '1') {
      performIdleLogout();
    }
  }

  // Conservative guard: also log out if there's been no user interaction at all
  // for the idle window while the tab is visible (truly idle, not just hidden).
  // This catches "tab visible but user walked away" which visibilitychange
  // alone wouldn't. Activity (mousemove/keydown/click/scroll/touch) resets it.
  let activityTimer = null;
  function resetActivityTimer() {
    if (activityTimer !== null) clearTimeout(activityTimer);
    activityTimer = setTimeout(() => {
      // No interaction for IDLE_MS while visible → treat as idle.
      performIdleLogout();
    }, IDLE_MS);
  }

  // ── Boot ───────────────────────────────────────────────────────────────────
  // Don't run on pages without a logged-in user (login page). The presence of
  // the logout button is a reliable "authenticated page" signal.
  if (!document.getElementById('logout-btn')) return;

  document.addEventListener('visibilitychange', onVisibilityChange);
  window.addEventListener('storage', onStorage);
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach((evt) =>
    document.addEventListener(evt, resetActivityTimer, { passive: true })
  );

  resetActivityTimer();
  if (!isHidden()) startHeartbeat();

  // If the tab loaded while already hidden (e.g. restored into a background
  // tab), arm the countdown immediately rather than waiting for a visibility
  // transition that may never come.
  if (isHidden()) {
    hiddenAt = Date.now();
    hideTimer = setTimeout(performIdleLogout, IDLE_MS);
  }
})();
