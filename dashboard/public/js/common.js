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

window.api = api;
window.toast = toast;
window.esc = esc;
window.bindReactionRemovals = bindReactionRemovals;
window.bindColorSync = bindColorSync;
window.bindSaveButtons = bindSaveButtons;
