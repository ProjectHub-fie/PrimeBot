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
  toastEl.className = `toast ${type}`;
  toastEl.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toastEl.classList.add('hidden'), 2600);
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
// whenever the user edits any tracked field. It shows a "Save changes" label
// with a green "Save" box button and a borderless red "Reset" text link — the
// same pattern Discord uses in its settings panels.
//
// Each settings page registers one or more async savers and a "tracking root"
// (the form area to watch for changes). When a change is detected the bar
// appears; Save runs every registered saver in order (toast on success/fail)
// then hides; Reset reloads the page to discard edits.
const SaveBar = (() => {
  let barEl = null;
  let saveBtn = null;
  let resetBtn = null;
  const savers = [];
  let dirty = false;
  let saving = false;
  const trackedRoots = [];

  function ensureBar() {
    if (barEl) return;
    barEl = document.createElement('div');
    barEl.className = 'save-bar hidden';
    barEl.setAttribute('role', 'status');
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
    barEl.classList.remove('hidden');
  }
  function hide() {
    if (!barEl) return;
    barEl.classList.add('hidden');
  }

  function markDirty() {
    if (saving) return;
    dirty = true;
    show();
  }
  function markClean() {
    dirty = false;
    hide();
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
    // Discard edits by reloading the page from the server-rendered defaults.
    window.location.reload();
  }

  function track(root) {
    if (!root || trackedRoots.includes(root)) return;
    trackedRoots.push(root);
    root.addEventListener('input', markDirty);
    root.addEventListener('change', markDirty);
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
