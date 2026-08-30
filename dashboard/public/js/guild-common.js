/* Guild settings pages — shared across all per-tab pages.
 *
 * Each tab (/guild/:id/welcome, /leveling, /prefix, …) is its own server-rendered
 * HTML page. They share:
 *   - a tab navigation bar (real links, no JS routing)
 *   - lazy-loaded channel & role <option> lists for <select data-channel-select>
 *     and <select data-role-select> elements
 *   - the breadcrumb
 *
 * The server passes the guild id + the available channel/role lists to the page
 * via a small JSON blob in #guild-data so we can populate selects without an
 * extra round-trip (mirrors the old SPA's lazy /api/.../channels|roles calls,
 * but inlined into the initial HTML).
 */
const guildDataEl = document.getElementById('guild-data');
const guildData = guildDataEl ? JSON.parse(guildDataEl.textContent) : { guildId: '', channels: [], roles: [] };

function preserveSelected(sel, current) {
  if (current && !sel.querySelector(`option[value="${CSS.escape(current)}"]`)) {
    const isChannel = sel.hasAttribute('data-channel-select');
    const option = document.createElement('option');
    option.value = current;
    option.textContent = isChannel ? `#${current} (kept — not visible to bot)` : `${current} (kept — not in role list)`;
    option.selected = true;
    sel.appendChild(option);
  }
}

function populateChannelSelects() {
  const opts = (guildData.channels || []).map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
  document.querySelectorAll('select[data-channel-select]').forEach(sel => {
    const current = sel.value;
    // Preserve a leading "— None —"-style option if present.

    const first = sel.querySelector('option[value=""]');
    sel.innerHTML = (first ? first.outerHTML : '<option value="">— None / default —</option>') + opts;
    if (current) sel.value = current;
    preserveSelected(sel, current);
  });
}

function populateRoleSelects() {
  const opts = (guildData.roles || []).map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('');
  document.querySelectorAll('select[data-role-select]').forEach(sel => {
    const current = sel.value;
    const placeholder = sel.dataset.placeholder || '— None —';
    sel.innerHTML = `<option value="">${esc(placeholder)}</option>` + opts;
    if (current) sel.value = current;
    preserveSelected(sel, current);
  });
}

populateChannelSelects();
populateRoleSelects();

// ── Slide-in sidebar menu ("turn left" animation) ─────────────────────────
// The menu bar button opens a drawer that slides in from the left; the
// backdrop + close button (and Escape) close it again.
(function setupSideMenu() {
  const menu = document.getElementById('side-menu');
  const toggle = document.getElementById('menu-toggle');
  const backdrop = document.getElementById('menu-backdrop');
  const closeBtn = document.getElementById('side-menu-close');
  if (!menu || !toggle) return;

  function open() {
    menu.classList.add('open');
    menu.setAttribute('aria-hidden', 'false');
    toggle.setAttribute('aria-expanded', 'true');
    if (backdrop) backdrop.classList.add('show');
  }
  function close() {
    menu.classList.remove('open');
    menu.setAttribute('aria-hidden', 'true');
    toggle.setAttribute('aria-expanded', 'false');
    if (backdrop) backdrop.classList.remove('show');
  }
  toggle.addEventListener('click', () => {
    menu.classList.contains('open') ? close() : open();
  });
  closeBtn?.addEventListener('click', close);
  backdrop?.addEventListener('click', close);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });
})();

window.guildData = guildData;
window.populateChannelSelects = populateChannelSelects;
window.populateRoleSelects = populateRoleSelects;
