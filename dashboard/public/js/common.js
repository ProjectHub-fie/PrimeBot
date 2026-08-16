/* PrimeBot Dashboard — shared client helpers (multi-page version).
 *
 * Loaded on every page. Provides api(), toast(), and the small interactive
 * primitives (color-picker sync, dynamic-row removal) the per-page scripts use.
 * The old single-page app.js did everything globally; now each route is its own
 * HTML page with a focused script, and this file holds the common glue.
 */

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });
  let body = null;
  const text = await res.text();
  if (text) { try { body = JSON.parse(text); } catch { body = text; } }
  if (!res.ok) {
    const msg = (body && body.error) || `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

const toastEl = document.getElementById('toast');
function toast(message, type = 'success') {
  if (!toastEl) return;
  toastEl.textContent = message;
  // Swap the type class without wiping the hidden-state class — overwriting
  // className would drop `toast-hidden` mid-transition and cut the animation.
  toastEl.classList.remove('success', 'error');
  if (type) toastEl.classList.add(type);
  // Slide/fade in: drop the hidden state class so the CSS transition plays.
  toastEl.classList.remove('toast-hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toastEl.classList.add('toast-hidden'), 2600);
}

function esc(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// Bind every `.reaction-remove` (✕) button to drop its row. Idempotent.
function bindReactionRemovals(scope = document) {
  scope.querySelectorAll('.reaction-remove').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => btn.closest('.reaction-row')?.remove());
  });
}

// Keep a color <input type="color"> and a sibling text input in sync.
function bindColorSync(colorId, textId) {
  const picker = document.getElementById(colorId);
  const text = document.getElementById(textId);
  if (!picker || !text) return;
  picker.addEventListener('input', () => { text.value = picker.value; });
  text.addEventListener('input', () => {
    if (/^#[0-9a-fA-F]{6}$/.test(text.value)) picker.value = text.value;
  });
}

// Generic "[data-save]" button wiring: calls a saver fn, shows a toast.
function bindSaveButtons(scope, saver) {
  scope.querySelectorAll('[data-save]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const kind = btn.dataset.save;
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = 'Saving…';
      try {
        await saver(kind);
        toast('Saved successfully', 'success');
      } catch (err) {
        toast(err.message || 'Failed to save', 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  });
}

// ── Discord-style floating "Save changes" bar ──────────────────────────────
// Replaces the per-section Save buttons on settings pages. Instead of a static
// Save button under each form, a single floating bar slides up from the bottom
// whenever the user has unsaved edits. It shows a "You have unsaved changes"
// label with a green "Save" box button and a borderless red "Reset" text link —
// the same pattern Discord uses in its settings panels.
//
// Each settings page registers one or more async savers and a "tracking root"
// (the form area to watch for changes). On load we snapshot the original state
// of every form control inside the root, plus the innerHTML of the dynamic
// row containers (auto-reactions / automod rules / leveling rewards / …). On
// every input/change we re-compare the live state to that snapshot: matching
// again (e.g. after backspacing to the original value) hides the bar, so it
// only stays visible while there are genuine unsaved changes.
//
// Save runs every registered saver in order (toast on success/fail) then hides
// the bar. Reset restores the form controls and dynamic rows from the snapshot
// in-place (a plain reload would restore the browser's edited field state, so
// it wouldn't actually discard the edits) and hides the bar.
//
// Show/hide uses a dedicated `.save-bar-hidden` class (transform + opacity +
// pointer-events) rather than the global `.hidden { display:none }`, so the
// slide-up-in / slide-down-out animation actually plays instead of being cut
// off by display:none. Success/error toasts use the same approach.
const SaveBar = (() => {
  let barEl = null;
  let saveBtn = null;
  let resetBtn = null;
  const savers = [];
  let dirty = false;
  let saving = false;
  const trackedRoots = [];
  let snapshot = null;       // { controls: Map<el, {value, checked}>, containers: Map<el, html> }
  let rafScheduled = false;
  let recheckToken = 0;      // bumped by markClean/reset so a stale rAF can't re-show the bar

  // Dynamic row containers whose innerHTML can change (add/remove rows). All
  // per-page dynamic lists share the `.reactions-list` class; the leveling
  // rewards list uses a bare `#lev-rewards-list`. We snapshot + restore both.
  function dynamicContainers(root) {
    return Array.from(root.querySelectorAll('.reactions-list, #lev-rewards-list'));
  }

  function captureState(root) {
    const controls = new Map();
    const inputs = root.querySelectorAll('input, textarea, select');
    inputs.forEach(el => {
      // Skip buttons — they aren't editable values.
      if (el.type === 'button' || el.type === 'submit') return;
      controls.set(el, { value: el.value, checked: el.checked });
    });
    const containers = new Map();
    dynamicContainers(root).forEach(el => containers.set(el, el.innerHTML));
    return { controls, containers };
  }

  function isStateDifferent(root, snap) {
    if (!snap) return false;
    for (const [el, orig] of snap.controls) {
      // An element that existed at snapshot time may have been removed (e.g.
      // a dynamic row's input was deleted) — that's a structural change.
      if (!root.contains(el)) return true;
      if (el.type === 'checkbox' || el.type === 'radio') {
        if (el.checked !== orig.checked) return true;
      } else if (el.value !== orig.value) {
        return true;
      }
    }
    for (const [el, html] of snap.containers) {
      if (!root.contains(el)) return true;
      if (el.innerHTML !== html) return true;
    }
    return false;
  }

  function ensureBar() {
    if (barEl) return;
    barEl = document.createElement('div');
    barEl.className = 'save-bar save-bar-hidden';
    barEl.setAttribute('role', 'status');
    barEl.setAttribute('aria-live', 'polite');
    barEl.innerHTML = `
      <span class="save-bar-label">You have unsaved changes</span>
      <div class="save-bar-actions">
        <button type="button" class="save-bar-reset">Reset</button>
        <button type="button" class="save-bar-save">Save</button>
      </div>`;
    document.body.appendChild(barEl);
    saveBtn = barEl.querySelector('.save-bar-save');
    resetBtn = barEl.querySelector('.save-bar-reset');
    saveBtn.addEventListener('click', runSave);
    resetBtn.addEventListener('click', runReset);
  }

  function show() {
    ensureBar();
    if (saving) return;
    barEl.classList.remove('save-bar-hidden');
  }
  function hide() {
    if (!barEl) return;
    barEl.classList.add('save-bar-hidden');
  }

  // Re-evaluate dirty against the snapshot. Cheap, so we run it on every
  // input/change (rAF-batched to avoid duplicate work within a frame).
  function recheck() {
    if (saving || !snapshot) return;
    if (rafScheduled) return;
    rafScheduled = true;
    const token = recheckToken;
    requestAnimationFrame(() => {
      rafScheduled = false;
      // If markClean/reset ran while we were waiting, drop this stale check.
      if (token !== recheckToken) return;
      let changed = false;
      for (const root of trackedRoots) {
        if (isStateDifferent(root, snapshot)) { changed = true; break; }
      }
      dirty = changed;
      if (changed) show(); else hide();
    });
  }

  function markDirty() {
    // Explicit dirty signal (e.g. after adding a dynamic row). Still re-eval so
    // an add-then-remove sequence correctly clears the bar.
    recheck();
  }
  function markClean() {
    recheckToken++;
    dirty = false;
    hide();
  }

  // After a successful save, re-snapshot so the just-saved values become the
  // new "original" baseline (prevents the bar immediately reappearing).
  function resnapshot() {
    snapshot = { controls: new Map(), containers: new Map() };
    for (const root of trackedRoots) {
      const s = captureState(root);
      s.controls.forEach((v, k) => snapshot.controls.set(k, v));
      s.containers.forEach((v, k) => snapshot.containers.set(k, v));
    }
  }

  async function runSave() {
    if (saving) return;
    saving = true;
    saveBtn.disabled = true;
    const orig = saveBtn.textContent;
    saveBtn.textContent = 'Saving…';
    try {
      for (const saver of savers) {
        await saver();
      }
      toast('Saved successfully', 'success');
      resnapshot();
      markClean();
    } catch (err) {
      toast(err.message || 'Failed to save', 'error');
    } finally {
      saving = false;
      saveBtn.disabled = false;
      saveBtn.textContent = orig;
    }
  }

  function runReset() {
    if (!snapshot) return;
    // Restore form controls to their snapshot values.
    for (const [el, orig] of snapshot.controls) {
      if (!document.body.contains(el)) continue;
      if (el.type === 'checkbox' || el.type === 'radio') {
        if (el.checked !== orig.checked) el.checked = orig.checked;
      } else if (el.value !== orig.value) {
        el.value = orig.value;
      }
    }
    // Restore dynamic row containers, then rebind their remove buttons.
    for (const [el, html] of snapshot.containers) {
      if (!document.body.contains(el)) continue;
      if (el.innerHTML !== html) el.innerHTML = html;
    }
    if (typeof window.bindReactionRemovals === 'function') {
      window.bindReactionRemovals();
    }
    // Re-init custom <select> UI (channel + role selects) after restoring
    // dynamic row containers, so their option lists + chosen value are correct.
    if (typeof window.populateRoleSelects === 'function') window.populateRoleSelects();
    if (typeof window.populateChannelSelects === 'function') window.populateChannelSelects();
    // Re-sync color pickers with their text inputs after restore.
    if (typeof window.bindColorSync === 'function') {
      window.bindColorSync('welcome-color', 'welcome-color-text');
      window.bindColorSync('logging-color', 'logging-color-text');
    }
    markClean();
  }

  function track(root) {
    if (!root || trackedRoots.includes(root)) return;
    trackedRoots.push(root);
    if (!snapshot) snapshot = { controls: new Map(), containers: new Map() };
    const s = captureState(root);
    s.controls.forEach((v, k) => snapshot.controls.set(k, v));
    s.containers.forEach((v, k) => snapshot.containers.set(k, v));
    root.addEventListener('input', recheck);
    root.addEventListener('change', recheck);
  }

  function register(saver) {
    if (typeof saver === 'function') savers.push(saver);
  }

  return { register, track, markDirty, markClean };
})();

window.api = api;
window.toast = toast;
window.esc = esc;
window.bindReactionRemovals = bindReactionRemovals;
window.bindColorSync = bindColorSync;
window.bindSaveButtons = bindSaveButtons;
window.saveBar = SaveBar;
