/* Ticket panel full-page editor — /guild/:guildId/tickets/:panelId/edit.
 * Reached from the "Create a panel" button (after an Untitled-N panel is auto-
 * created) or a panel card's "Edit" button. Renders a horizontal SPA-style
 * tab bar (Panel, Buttons, Message, Permission, Logging, Animation,
 * Transcript, Input) — clicking a tab swaps the visible panel client-side,
 * no page reload. All editor fields save with the floating "Save changes" bar
 * (PATCH /api/guilds/:guildId/tickets/:id). The quick actions (Send/Resend,
 * Update message, Clone, Rename, Delete) post to their existing endpoints.
 */

const GUILD_ID = window.guildData?.guildId;
const PANEL_ID = (window.location.pathname.match(/\/tickets\/(\d+)\/edit/) || [])[1] || null;

// ── Horizontal tab bar (SPA style) ──────────────────────────────────────
function bindEditorTabs() {
  const tabs = document.querySelectorAll('.tk-editor-tab');
  const panels = document.querySelectorAll('.tk-editor-panels .tab-panel');
  if (!tabs.length) return;
  const select = (idx) => {
    tabs.forEach((t, i) => {
      const active = i === idx;
      t.classList.toggle('active', active);
      t.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    panels.forEach((p, i) => p.classList.toggle('active', i === idx));
  };
  tabs.forEach((t, i) => t.addEventListener('click', () => select(i)));
  // Keyboard: arrow keys move between tabs (SPA feel).
  tabs.forEach((t, i) => t.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const dir = e.key === 'ArrowRight' ? 1 : -1;
      const next = (i + dir + tabs.length) % tabs.length;
      select(next);
      tabs[next].focus();
    }
  }));
}

// ── Role rows (support/ping) ──────────────────────────────────────────────
function ticketRoleRowHTML(prefix) {
  return `
    <div class="reaction-row" data-index="">
      <select class="${prefix}-role" data-role-select data-placeholder="Role"><option value="">Role</option></select>
      <button class="reaction-remove" type="button">✕</button>
    </div>`;
}

// ── Message-tab extras: counters, URL validation, save-state pill, reset, unsaved guard.
const EDB_URL_FIELDS = [
  { id: 'tk-author-url', note: '.edb-url-note-near-author-url' , label: 'Author URL' },
  { id: 'tk-author-icon', note: '.edb-note-after-author-icon' , label: 'Author icon URL' },
  { id: 'tk-title-url', note: '.edb-note-after-title-url' , label: 'Title URL' },
  { id: 'tk-thumbnail', note: '.edb-note-after-thumbnail' , label: 'Thumbnail URL' },
  { id: 'tk-image', note: '.edb-note-after-image' , label: 'Image URL' },
  { id: 'tk-footer-icon', note: '.edb-note-after-footer-icon' , label: 'Footer icon URL' },
];
const EDB_COUNTERS = [
  { id: 'tk-author-name', max: 256 },
  { id: 'tk-title', max: 256 },
  { id: 'tk-description', max: 4000 },
  { id: 'tk-footer', max: 2048 },
  { id: 'tk-button-label', max: 80 },
];
const RE_URL = /^https?:\/\/[^\s]+$/i;

function edbInputLabel(el) {
  if (!el) return '';
  const label = el.closest('.edb-field')?.querySelector('.edb-label');
  return label ? label.textContent.trim() : '';
}

function validateEdbUrl(el) {
  if (!el) return;
  const v = el.value.trim();
  const noteEl = el.closest('.edb-field')?.querySelector('.edb-note');
  const lbl = edbInputLabel(el);
  if (noteEl) {
    if (v && !RE_URL.test(v) && !/^data:image\//i.test(v)) {
      noteEl.textContent = `⚠ Please enter a valid URL for ${lbl}.`;
      noteEl.classList.add('edb-url-error');
      el.setAttribute('aria-invalid', 'true');
    } else {
      noteEl.textContent = '';
      noteEl.classList.remove('edb-url-error');
      el.removeAttribute('aria-invalid');
    }
  }
}

function updateEdbCounters() {
  for (const c of EDB_COUNTERS) {
    const el = document.getElementById(c.id);
    const counter = el?.closest('.edb-field')?.querySelector('.edb-counter');
    if (!el || !counter) continue;
    const n = el.value.length;
    counter.textContent = `${n} / ${c.max}`;
    counter.classList.toggle('edb-over', n > c.max);
    if (n > c.max) {
      el.setAttribute('aria-invalid', 'true');
      counter.setAttribute('role', 'alert');
    } else {
      el.removeAttribute('aria-invalid');
      counter.removeAttribute('role');
    }
  }
}

function bindEdbMessageExtras() {
  for (const f of EDB_URL_FIELDS) {
    const el = document.getElementById(f.id);
    if (el) el.addEventListener('input', () => validateEdbUrl(el));
  }
  const countersRoot = document.querySelector('.edb-builder-cols');
  if (countersRoot) {
    countersRoot.addEventListener('input', updateEdbCounters);
    countersRoot.addEventListener('change', updateEdbCounters);
  }
  // Reset embed (only the embed/message fields — never the whole panel.)
  const resetBtn = document.getElementById('edb-reset-embed');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (!window.confirm('Reset the embed and message content to defaults? This does not touch the rest of the panel.')) return;
      const vals = {
        '#tk-content': '', '#tk-color': '#5865F2', '#tk-color-text': '#5865F2',
        '#tk-author-name': '', '#tk-author-url': '', '#tk-author-icon': '',
        '#tk-title': '', '#tk-title-url': '',
        '#tk-description': '', '#tk-thumbnail': '', '#tk-image': '',
        '#tk-footer': '', '#tk-footer-icon': '',
        '#tk-timestamp': '',
      };
      for (const [sel, v] of Object.entries(vals)) {
        const el = document.querySelector(sel);
        if (!el) continue;
        if (sel === '#tk-timestamp') el.checked = false; else el.value = v;
      }
      window.saveBar?.markDirty?.();
      renderTicketPreview();
      updateEdbCounters();
    });
  }
}

function bindEdbSaveState() {
  const pill = document.getElementById('edb-save-state');
  if (!pill) return;
  const text = pill.querySelector('.edb-save-text');
  const setState = (state) => {
    pill.classList.toggle('dirty', state === 'dirty');
    pill.classList.toggle('saving', state === 'saving');
    pill.classList.toggle('saved', state === 'saved');
    if (text) {
      text.textContent = state === 'dirty' ? '● Unsaved changes' : state === 'saving' ? 'Saving…' : '✓ All changes saved';
    }
  };
  const mark = (dirty) => setState(dirty ? 'dirty' : 'saved');
  // Hook into the floating save bar when available.

  if (typeof setInterval !== 'function') return;
  const watchSaveBar = setInterval(() => {
    const sb = window.saveBar;
    if (!sb) return;
    clearInterval(watchSaveBar);
    const origMarkDirty = sb.markDirty?.bind(sb);
    const origMarkClean = sb.markClean?.bind(sb);
    if (origMarkDirty) sb.markDirty = (...a) => { origMarkDirty(...a); mark(true); };
    if (origMarkClean) sb.markClean = (...a) => { origMarkClean(...a); mark(false); };
    const origRegister = sb.register?.bind(sb);
    if (origRegister) {
      sb.register = (saver, ...rest) => {
        const wrapped = async (...args) => {
          setState('saving');
          try {
            const r = await saver(...args);
            mark(false);
            return r;
          } catch (e) {
            setState('dirty');
            throw e;
          }
        };
        return origRegister(wrapped, ...rest);
      };
    }
  }, 50);
}

function bindEdbNavigationGuard() {
  if (typeof window.addEventListener !== 'function') return;
  window.addEventListener('beforeunload', (e) => {
    if (window.saveBar?._dirty) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
}

// Track unsaved changes in the save bar (the floating bar already marks dirty/clean).
function patchSaveBarDirtyTracking() {
  const sb = window.saveBar;
  if (!sb || sb.__edbPatched) return;
  sb.__edbPatched = true;
  const origMarkDirty = sb.markDirty?.bind(sb);
  const origMarkClean = sb.markClean?.bind(sb);
  if (origMarkDirty) sb.markDirty = (...a) => { origMarkDirty(...a); sb._dirty = true; };
  if (origMarkClean) sb.markClean = (...a) => { origMarkClean(...a); sb._dirty = false; };
}

function collectTicketRoles(listSelector, roleClass) {
  const out = [];
  document.querySelectorAll(`${listSelector} .${roleClass}`).forEach(sel => {
    const v = sel.value;
    if (v) out.push(v);
  });
  return out;
}

function readTicketForm() {
  const q = id => document.querySelector(id)?.value ?? '';
  const chk = id => document.querySelector(id)?.checked ?? false;
  const btn = (key, extra = {}) => ({
    label: q(`#tk-btn-${key}-label`) ?? null,
    emoji: q(`#tk-btn-${key}-emoji`) ?? null,
    style: q(`#tk-btn-${key}-style`) || 'Primary',
    ...extra,
  });
  const roleGroup = (prefix) => {
    const enabled = Boolean(document.querySelector(`.trole-${prefix}-enabled`)?.checked ?? false);
    return {
      enabled,
      channelName: document.querySelector(`.trole-${prefix}-name`)?.value.trim() || null,
      addRoleId: document.querySelector(`.trole-${prefix}-add`)?.value.trim() || null,
      removeRoleId: document.querySelector(`.trole-${prefix}-remove`)?.value.trim() || null,
      showUserName: !!document.querySelector(`.trole-${prefix}-user`)?.checked,
      showCount: !!document.querySelector(`.trole-${prefix}-count`)?.checked,
    };
  };
  return {
    name: q('#tk-name').trim() || 'Support Ticket',
    messageType: q('#tk-message-type') || 'embed',
    authorName: q('#tk-author-name').trim() || null,
    authorUrl: q('#tk-author-url').trim() || null,
    authorIconUrl: q('#tk-author-icon').trim() || null,
    title: q('#tk-title').trim() || null,
    titleUrl: q('#tk-title-url').trim() || null,
    description: q('#tk-description').trim() || null,
    content: q('#tk-content').trim() || null,
    footerText: q('#tk-footer').trim() || null,
    footerIconUrl: q('#tk-footer-icon').trim() || null,
    thumbnailUrl: q('#tk-thumbnail').trim() || null,
    imageUrl: q('#tk-image').trim() || null,
    timestamp: !!document.querySelector('#tk-timestamp')?.checked,
    color: q('#tk-color') || '#5865F2',
    buttonLabel: document.querySelector('#tk-button-label')?.value.trim() || 'Open Ticket',
    buttonEmoji: document.querySelector('#tk-button-emoji')?.value.trim() || null,
    buttonStyle: document.querySelector('#tk-button-style')?.value || 'Primary',
    category: q('#tk-category') || 'general',
    ticketName: q('#tk-ticket-name') || null,
    openNameTemplate: q('#tk-open-name') || null,
    claimedNameTemplate: q('#tk-claimed-name') || null,
    closedNameTemplate: q('#tk-closed-name') || null,
    supportRoleIds: collectTicketRoles('#tk-support-list', 'tk-support-role'),
    pingRoleIds: collectTicketRoles('#tk-ping-list', 'tk-ping-role'),
    ticketCategoryId: q('#tk-ticket-category-id') || null,
    maxOpenPerUser: parseInt(q('#tk-max-open'), 10) || 1,
    askReason: chk('#tk-ask-reason'),
    welcomeMessage: q('#tk-welcome') || null,
    closeButtonLabel: q('#tk-btn-close-label') || 'Close Ticket',
    closeButtonEmoji: q('#tk-btn-close-emoji') || '🔒',
    closeButtonStyle: q('#tk-btn-close-style') || 'Danger',
    claimButtonLabel: q('#tk-btn-claim-label') || null,
    claimButtonEmoji: q('#tk-btn-claim-emoji') || null,
    claimButtonStyle: q('#tk-btn-claim-style') || 'Secondary',
    claimEnabled: Boolean(document.querySelector('#tk-claim-enabled')?.checked ?? true),
    roleSettings: {
      open: roleGroup('open'),
      close: roleGroup('close'),
    },
    closeFlow: {
      confirmYes: btn('confirm'),
      confirmNo: btn('cancel'),
      closeEmbed: {
        enabled: chk('#tk-cf-embed-enabled'),
        title: q('#tk-cf-embed-title') || 'Ticket Closed',
        description: q('#tk-cf-embed-desc') || null,
        color: q('#tk-cf-embed-color') || '#ED4245',
        footer: q('#tk-cf-embed-footer') || null,
      },
      transcript: {
        enabled: chk('#tk-cf-transcript-enabled'),
        channelId: q('#tk-cf-transcript-channel') || null,
      },
      buttons: {
        transcript: btn('transcript'),
        reopen: btn('reopen'),
        delete: btn('delete'),
      },
    },
    enabled: chk('#tk-enabled'),
    components: document.querySelector('#tk-builder-enabled')?.checked ? collectPanelComponents() : [],
  };
}

// ── Panel components.builder (Panel tab) ─────────────────────────────────
// Reads the editable component rows into the PATCH payload. Each button /
// dropdown carries an explicit position (DOM order), a per-input ticket
// configuration (category, staff roles, name template, limits) — and, for
// dropdowns, a list of labeled/described options (each with its own config)..
// Validation mirrors Discord limits: 5 action rows,≤5 buttons/row,
// select ≤25 options,≤1 select/row (enforced component-side by splitting
// buttons only into 5-per-row groups; selects each own row). `present` rows
// with empty labels are dropped; a select with no options/next empty rows excluded.
function collectPanelComponents() {
  const nodes = Array.from(document.querySelectorAll('.pcomp-row'));
  const out = [];
  nodes.forEach((n, i) => {
    const type = n.dataset.compType === 'select' ? 'select' : 'button';
    const pos = i;
    if (type === 'select') {
      const minV = parseInt(n.querySelector('.pcomp-min')?.value, 10) || 0;
      const maxV = parseInt(n.querySelector('.pcomp-max')?.value,  10) || 1;
      const opts = [];
      n.querySelectorAll('.pcomp-opt-row').forEach((o, oi) => {
        const label = (o.querySelector('.pcomp-opt-label')?.value || '').trim();
        const desc = (o.querySelector('.pcomp-opt-desc')?.value || '').trim();
        const emoji = (o.querySelector('.pcomp-opt-emoji')?.value || '').trim();
        const value = (o.querySelector('.pcomp-opt-value')?.value || '' ).trim();
        if (!label && !desc && !emoji && !value) return;
        const cfg = window.__pcompCfg?.[`opt:${o.dataset.optIdx}`] || window.__pcompCfg?.[o.dataset.optIdx] || null;
        opts.push({ label: label || 'Option', value: value || ('opt-' + (oi + 1)), description: desc || null, emoji: emoji || null, ticketConfiguration: cfg });
      });
      if (!opts.length) return;
      out.push({
        type, position: pos,
        placeholder: (n.querySelector('.pcomp-label')?.value || '' ).trim() || null,
        minValues: Math.max(0, Math.min(25, minV)),
        maxValues: Math.min(25, Math.max(1, Math.max(minV, maxV))),
        ticketConfiguration: window.__pcompCfg?.comp?.[String(n.dataset.compIdx)] || window.__pcompCfg?.comp?.[String(n.dataset.compId)] || null,
        options: opts,
      });
    } else {
      const label = (n.querySelector('.pcomp-label')?.value || '' ).trim();
      if (!label) return;
      const cfg = window.__pcompCfg?.comp?.[String(n.dataset.compIdx)] || window.__pcompCfg?.comp?.[String(n.dataset.compId)] || null;
      out.push({
        type, position: pos,
        label: label.slice(0, 80),
        emoji: (n.querySelector('.pcomp-emoji')?.value || '').trim() || null,
        style: (n.querySelector('.pcomp-style')?.value || 'Primary'),
        action: 'ticket',
        ticketConfiguration: cfg,
      });
    }
  });
  return out;
}

function pcompRowHTML(type) {
  const grip = window.svgIcon ? window.svgIcon('grip') : '⋮⋮';
  const x = window.svgIcon ? window.svgIcon('x') : '✕';
  if (type === 'select') {
    return `
      <div class="reaction-row pcomp-row" data-comp-idx="${Date.now()}" data-comp-id="" data-comp-type="select">
        <span class="pcomp-grip">${grip}</span>
        <span class="pcomp-type">🔽 Dropdown</span>
        <input type="text" class="pcomp-label" placeholder="Dropdown placeholder (shown as the select's label)" maxlength="150" />
        <div class="pcomp-range">
          <label>Min <input type="number" class="pcomp-min" min="0" max="25" value="0" /></label>
          <label>Max <input type="number" class="pcomp-max" min="1" max="25" value="1" /></label>
        </div>
        <span class="pcomp-summary"><span class="pcomp-type-tag">Dropdown</span></span>
        <button class="reaction-remove pcomp-del" type="button" title="Remove component">${x}</button>
        <div class="pcomp-options">
          <div class="reaction-row pcomp-opt-row" data-opt-idx="0">
            <input type="text" class="pcomp-opt-label" placeholder="Label" maxlength="80" />
            <input type="text" class="pcomp-opt-emoji" placeholder="emoji" maxlength="100" />
            <input type="text" class="pcomp-opt-desc" placeholder="Option description (shown under the label)" maxlength="150" />
            <input type="text" class="pcomp-opt-value" placeholder="value" maxlength="100" />
            <button class="reaction-remove pcomp-opt-del" type="button" title="Remove option">${x}</button>
            <span class="pcomp-cfg-summary"></span>
            <button type="button" class="btn btn-secondary btn-sm pcomp-cfg pcomp-opt-cfg">${window.svgIcon ? window.svgIcon('sliders') : ''} Config</button>
          </div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm pcomp-add-opt">+ Add option</button>
      </div>`;
  }
  return `
      <div class="reaction-row pcomp-row" data-comp-idx="${Date.now()}" data-comp-id="" data-comp-type="button">
        <span class="pcomp-grip">${grip}</span>
        <span class="pcomp-type">🔘 Button</span>
        <input type="text" class="pcomp-label" placeholder="Button label" maxlength="80" />
        <input type="text" class="pcomp-emoji" placeholder="emoji" maxlength="100" />
        <select class="pcomp-style">
          <option value="Primary">Primary</option>
          <option value="Secondary">Secondary</option>
          <option value="Success">Success</option>
          <option value="Danger">Danger</option>
          <option value="Link">Link</option>
        </select>
        <span class="pcomp-summary"><span class="pcomp-type-tag">Primary</span></span>
        <button type="button" class="btn btn-secondary btn-sm pcomp-cfg">${window.svgIcon ? window.svgIcon('sliders') : ''} Config</button>
        <button class="reaction-remove pcomp-del" type="button" title="Remove component">${x}</button>
      </div>`;
}

function bindPanelComponentsBuilder() {
  const list = document.querySelector('.pcomp-list');
  if (!list) return;
  window.__pcompCfg = {};
  // Slide-out per-input ticket configuration editor (modal). Fields map to the
  // existing ticket engine's per-ticket override set.

  const showCfg = async (target, holderKey, inputKey, current) => {
    const mkField = (id, label, val, ph = '') => `
      <div class="field">
        <label class="field-label">${label}</label>
        <input type="text" id="${id}" value="${(val || '' ).replace(/"/g, '&quot;')}" placeholder="${ph}" />
      </div>`;
    const mkCheck = (id, label, chked) => `
      <label class="check"><input type="checkbox" id="${id}" ${chked ? 'checked' : ''}/> ${label}</label>`;
    const c = current || {};
    const roles = Array.isArray(c.supportRoleIds) ? c.supportRoleIds : [];
    const proles = Array.isArray(c.pingRoleIds) ? c.pingRoleIds : [];
    const body = `
      ${mkField('pcfg-cat', 'Category', c.category, 'general')}
      ${mkField('pcfg-name', 'Channel name format', c.ticketName, '(open) {name}')}
      ${mkField('pcfg-catid', 'Category ID (Discord category, optional)', c.ticketCategoryId, '123456789012345678')}
      ${mkField('pcfg-support', 'Support role IDs (comma-separated)', (roles.length ? roles.join(', ') : '' ), '')}
      ${mkField('pcfg-ping', 'Ping role IDs (comma-separated)', (proles.length ? proles.join(', ') : '' ), '')}
      ${mkField('pcfg-max', 'Max open tickets per user', c.maxOpenPerUser != null ? String(c.maxOpenPerUser) : '', '1')}
      ${mkField('pcfg-ask', 'Ask for reason (true/false)', typeof c.askReason === 'boolean' ? String(c.askReason) : '', 'false')}
      <div class="field">
        <button type="button" class="btn btn-secondary btn-sm" id="pcfg-clear">Clear this ticket configuration</button>
      </div>`;
    // Modal via the existing floating-window classes.
    let overlay = document.querySelector('.pcfg-modal');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'modal floating-window pcfg-modal';
      overlay.innerHTML = '<div class="modal-card">...</div>';
      document.body.appendChild(overlay);
    }
    overlay.querySelector('.modal-card').innerHTML = `
      <h3>Ticket configuration</h3>
      <p class="card-hint">Per-input overrides applied when this button/option opens a ticket. Blank fields fall back to the panel + ticket table defaults.</p>
      ${body}
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" id="pcfg-cancel">Cancel</button>
        <button class="btn btn-primary btn-sm" id="pcfg-save">Save configuration</button>
      </div>`;
    overlay.classList.add('open');
    const hide = () => overlay.classList.remove('open');
    overlay.querySelector('#pcfg-cancel').onclick = hide;
    overlay.querySelector('.modal-card').addEventListener('click', (e) => e.stopPropagation());
    overlay.onclick = (e) => { if (e.target === overlay) hide; };
    overlay.querySelector('#pcfg-clear').onclick = () => { window.__pcompCfg[holderKey] = null; if (window.saveBar) window.saveBar.markDirty(); hide; };
    overlay.querySelector('#pcfg-save').onclick = () => {
      const v = id => document.getElementById(id)?.value.trim() || null;
      const split = s => s ? s.split(',').map(x => x.trim().replace(/^<@&?|>$/g, '')).filter(Boolean) : [];
      const cfg = {};
      const cat = v('pcfg-cat');
      if (cat) cfg.category = cat;
      const nm = v('pcfg-name');
      if (nm) cfg.ticketName = nm;
      const cid = v('pcfg-catid');
      if (cid) cfg.ticketCategoryId = cid;
      const sp = split(v('pcfg-support'));
      if (sp.length) cfg.supportRoleIds = sp;
      const pg = split(v('pcfg-ping'));
      if (pg.length) cfg.pingRoleIds = pg;
      const mx = parseInt(v('pcfg-max'), 10);
      if (Number.isFinite(mx) && mx > 0) cfg.maxOpenPerUser = mx;
      const ar = v('pcfg-ask');
      if (ar === 'true') cfg.askReason = true;
      else if (ar === 'false') cfg.askReason = false;
      if (Object.keys(cfg).length === 0) { window.__pcompCfg[holderKey] = null; refreshSummary(target); if (window.saveBar) window.saveBar.markDirty(); hide; return; }
      window.__pcompCfg[holderKey] = cfg;
      refreshSummary(target);
      if (window.saveBar) window.saveBar.markDirty();
      hide;
    };
  };
  const refreshSummary = (target) => {
    const s = target?.closest('.pcomp-row')?.querySelector('.pcomp-cfg-summary,.pcomp-summary');
    if (!s) return;
    if (target.classList.contains('pcomp-opt-cfg')) {
      const idx = target.closest('.pcomp-opt-row')?.dataset.optIdx;
      const cfg = window.__pcompCfg?.[`opt:${idx}`] || window.__pcompCfg?.[idx];
      s.textContent = cfg ? summarizeCfg(cfg) : '';
    } else {
      const idx = target.closest('.pcomp-row')?.dataset.compIdx;
      const cfg = window.__pcompCfg?.comp?.[idx];
      s.textContent = cfg ? summarizeCfg(cfg) : '';
    }
  };
  const summarizeCfg = (cfg) => {
    if (!cfg) return '';
    const bits = [];
    if (cfg.category) bits.push('cat: ' + cfg.category);
    if (cfg.ticketName) bits.push('name: ' + cfg.ticketName);
    if (Array.isArray(cfg.supportRoleIds) && cfg.supportRoleIds.length) bits.push(cfg.supportRoleIds.length + ' support role(s)');
    if (Array.isArray(cfg.pingRoleIds) && cfg.pingRoleIds.length) bits.push(cfg.pingRoleIds.length + ' ping role(s)');
    if (cfg.ticketCategoryId) bits.push('category id: ' + cfg.ticketCategoryId);
    if (cfg.maxOpenPerUser) bits.push('max ' + cfg.maxOpenPerUser + ' open');
    if (cfg.askReason === true) bits.push('asks reason');
    else if (cfg.askReason === false) bits.push('no reason prompt');
    return bits.join(' · ');
  };

  // Drag-reorder rows: each `position` is captured from DOM order on save,
  // so this just moves the row node (and its nested option rows along).
  const rowsWrap = list;
  let dragSrc = null;
  list.querySelectorAll('.pcomp-row').forEach(r => r.setAttribute('draggable', 'true'));
  list.addEventListener('dragstart', (e) => {
    const row = e.target.closest('.pcomp-row');
    if (!row) return;
    dragSrc = row;
    row.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  });
  list.addEventListener('dragover', (e) => {
    e.preventDefault();
    const row = e.target.closest('.pcomp-row');
    if (!row || row === dragSrc) return;
    const after = e.clientY > row.getBoundingClientRect().top + row.getBoundingClientRect().height / 2;
    if (after) row.after(dragSrc);
    else { row.before(dragSrc); }
  });
  list.addEventListener('dragend', () => {
    rowsWrap.querySelectorAll('.pcomp-row')?.forEach(r => r.classList.remove('dragging'));
    dragSrc = null;
  });

  list.addEventListener('click', (e) => {
    const cfgBtn = e.target.closest('.pcomp-cfg');
    if (cfgBtn) { e.preventDefault();
      const row = cfgBtn.closest('.pcomp-row');
      const isOpt = cfgBtn.classList.contains('pcomp-opt-cfg');
      const holderKey = isOpt ? `opt:${cfgBtn.closest('.pcomp-opt-row')?.dataset.optIdx}` : `comp:${row?.dataset.compIdx}`;
      const current = window.__pcompCfg?.[holderKey] || null;
      showCfg(cfgBtn, holderKey, isOpt ? 'option' : 'component', current);
      return;
    }
    const del = e.target.closest('.pcomp-del');
    if (del) { del.closest('.pcomp-row')?.remove(); if (window.saveBar) window.saveBar.markDirty(); return; }
    const optDel = e.target.closest('.pcomp-opt-del');
    if (optDel) { optDel.closest('.pcomp-opt-row')?.remove(); if (window.saveBar) window.saveBar.markDirty(); return; }
    const addOpt = e.target.closest('.pcomp-add-opt');
    if (addOpt) {
      const wrap = addOpt.closest('.pcomp-row')?.querySelector('.pcomp-options');
      if (!wrap) return;
      if (wrap.querySelectorAll('.pcomp-opt-row').length >= 25) { toast('A dropdown can contain a maximum of 25 options.', 'error'); return; }
      if (window.saveBar) window.saveBar.markDirty();
      const idx = wrap.querySelectorAll('.pcomp-opt-row').length;
      wrap.insertAdjacentHTML('beforeend', `
        <div class="reaction-row pcomp-opt-row" data-opt-idx="${idx}">
          <input type="text" class="pcomp-opt-label" placeholder="Label" maxlength="80" />
          <input type="text" class="pcomp-opt-emoji" placeholder="emoji" maxlength="100" />
          <input type="text" class="pcomp-opt-desc" placeholder="Option description (shown under the label)" maxlength="150" />
          <input type="text" class="pcomp-opt-value" placeholder="value" maxlength="100" />
          <button class="reaction-remove pcomp-opt-del" type="button" title="Remove option">${window.svgIcon ? window.svgIcon('x') : '✕'}</button>
          <span class="pcomp-cfg-summary"></span>
          <button type="button" class="btn btn-secondary btn-sm pcomp-cfg pcomp-opt-cfg">${window.svgIcon ? window.svgIcon('sliders') : ''} Config</button>
        </div>`);
      return;
    }
  });
  const addBtn = document.getElementById('tk-add-button');
  if (addBtn) addBtn.addEventListener('click', () => { list.insertAdjacentHTML('beforeend', pcompRowHTML('button')); bindReactionRemovals(); if (window.saveBar) window.saveBar.markDirty(); });
  const addSel = document.getElementById('tk-add-select');
  if (addSel) addSel.addEventListener('click', () => { list.insertAdjacentHTML('beforeend', pcompRowHTML('select')); bindReactionRemovals(); if (window.saveBar) window.saveBar.markDirty(); });
}

// ── Save (floating Save changes bar → PATCH) ─────────────────────────────
async function saveTicketPanel() {
  if (!GUILD_ID || !PANEL_ID) throw new Error('Missing ticket panel context.');
  const body = readTicketForm();
  await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}`, { method: 'PATCH', body: JSON.stringify(body) });
  // Keep the page's heading + panel-id chip fresh after a rename.

  if (window.refreshPanelActions) window.refreshPanelActions();
}

// ── Button chips (slide open / slide shut embed-builder dropdowns) ────────
// Each Buttons-tab chip owns a collapsible builder panel. Tapping the header
// slides it open with a CSS transition (grid-template-rows trick); tapping it
// again (or another chip) slides it shut. Fields stay mounted (only height
// animates) so focus is preserved while typing. The chip's live label/emoji
// preview updates as you type, mirroring the embed builder's live regions.
function bindButtonsBuilder() {
  const heads = document.querySelectorAll('.tk-btn-trigger');
  if (!heads.length) return;
  const panels = {};
  document.querySelectorAll('.tk-btn-dropdown').forEach(d => { panels[d.dataset.btnPanel] = d; });
  const toggle = (key, open) => {
    const panel = panels[key];
    if (!panel) return;
    const chip = document.querySelector(`.tk-btn-chip[data-btn-key="${key}"]`);
    const head = document.querySelector(`.tk-btn-trigger[data-btn-trigger="${key}"]`);
    const shouldOpen = open ?? panel.classList.contains('open') === false;
    panel.classList.toggle('open', shouldOpen);
    panel.style.height = shouldOpen ? panel.scrollHeight + 'px' : '0px';
    chip?.classList.toggle('open', shouldOpen);
    head?.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
  };
  heads.forEach(head => head.addEventListener('click', () => {
    const key = head.dataset.btnTrigger;
    toggle(key);
  }));
  // Only one chip open at a time (accordion feel, Ticket Tool style).
  heads.forEach(head => head.addEventListener('click', () => {
    const key = head.dataset.btnTrigger;
    if (!panelIsOpen(key)) return;
    heads.forEach(h => { if (h.dataset.btnTrigger !== key) toggle(h.dataset.btnTrigger, false); });
  }));
  const panelIsOpen = (key) => panels[key]?.classList.contains('open') ?? false;
  // Re-measure heights when a dropdown's fields reflow (e.g. after a save
  // re-renders the page, or the embed builder re-layouts).
  window.addEventListener('resize', () => {
    Object.values(panels).forEach(p => { if (p.classList.contains('open')) p.style.height = p.scrollHeight + 'px'; });
  });
}

// Live chip preview: update the button chip's label/emoji as you type in its
// fields (mirrors the embed-builder live rows).
const BTN_CHIP_KEYS = ['open', 'close', 'confirm', 'cancel', 'reopen', 'claim', 'delete', 'transcript'];
function renderButtonsChips() {
  for (const key of BTN_CHIP_KEYS) {
    const live = document.querySelector(`.tk-btn-chip-live[data-btn-live="${key}"]`);
    if (!live) continue;
    const label = document.querySelector(`#tk-btn-${key}-label`)?.value?.trim();
    const emoji = document.querySelector(`#tk-btn-${key}-emoji`)?.value?.trim();
    const labelEl = live.querySelector('.tk-btn-chip-label');
    if (labelEl) labelEl.textContent = label || (key === 'open' ? 'Open' : key.charAt(0).toUpperCase() + key.slice(1));
    let emojiEl = live.querySelector('.tk-btn-chip-emoji');
    if (emoji) {
      if (!emojiEl) {
        emojiEl = document.createElement('span');
        emojiEl.className = 'tk-btn-chip-emoji';
        live.insertBefore(emojiEl, labelEl); // labelEl is always present
      }
      emojiEl.textContent = emoji;
    } else if (emojiEl) {
      emojiEl.remove();
    }
  }
}
let _btnChipTimer = null;
function scheduleButtonsChips() {
  clearTimeout(_btnChipTimer);
  _btnChipTimer = setTimeout(renderButtonsChips, 40);
}

// ── Quick actions (Send / Resend, Update, Clone, Rename, Delete ────────
function bindQuickActions() {
  document.querySelectorAll('.tk-send').forEach(btn => btn.addEventListener('click', async () => {
    const channelId = prompt('Channel ID to send its panel to:', '');
    if (channelId === null) return;
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}/send`, { method: 'POST', body: JSON.stringify({ channelId: channelId.trim() }) });
      toast('Panel sent to channel', 'success');
    } catch (err) { toast(err.message || 'Failed to send', 'error'); }
  }));
  document.querySelectorAll('.tk-update').forEach(btn => btn.addEventListener('click', async () => {
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}/update`, { method: 'POST', body: JSON.stringify({ }) });
      toast('Panel message updated', 'success');
    } catch (err) { toast(err.message || 'Failed to update', 'error'); }
  }));
  document.querySelectorAll('.tk-clone').forEach(btn => btn.addEventListener('click', async () => {
    const name = prompt('Name for the cloned panel (leave blank for "<name> (copy)"):', '');
    if (name === null) return;
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}/clone`, { method: 'POST', body: JSON.stringify({ name: name || undefined }) });
      toast('Panel cloned', 'success');
      if (data.ticketPanel?.id) window.location.href = `/guild/${GUILD_ID}/tickets/${data.ticketPanel.id}/edit`;
    } catch (err) { toast(err.message || 'Failed to clone', 'error'); }
  }));
  document.querySelectorAll('.tk-rename').forEach(btn => btn.addEventListener('click', async () => {
    const name = prompt('New panel name:', '');
    if (name === null || !name.trim()) return;
    try {
      const data = await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}/rename`, { method: 'POST', body: JSON.stringify({ name }) });
      toast('Panel renamed', 'success');
      if (data.ticketPanel?.id) window.location.href = `/guild/${GUILD_ID}/tickets/${data.ticketPanel.id}/edit`;
    } catch (err) { toast(err.message || 'Failed to rename', 'error'); }
  }));
  document.querySelectorAll('.tk-delete').forEach(btn => btn.addEventListener('click', async () => {
    if (!confirm('Delete this ticket panel? The panel message will be removed if the bot sent it.')) return;
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}`, { method: 'DELETE' });
      toast('Panel deleted', 'success');
      setTimeout(() => { window.location.href = `/guild/${GUILD_ID}/tickets`; }, 600);
    } catch (err) { toast(err.message || 'Failed to delete', 'error'); }
  }));
}

// ── Embed-builder live output ("fields show as the embed") ────────────────────
// The Ticket Tool-style builder renders each embed region's editing field(s)
// attached to the region, with a tiny Discord-styled live render beneath the input.
// On input we update ONLY the live output nodes — the input controls are never
// rebuilt, so the field you're typing in keeps focus. Mirrors the server-render
// initial state in guild-pages.js ticketEmbedBuilderHTML.
function renderTicketPreview() {
    const q = id => document.querySelector(id)?.value ?? '';
    const authorName = q('#tk-author-name').trim();
    const authorIcon = q('#tk-author-icon').trim();
    const title = q('#tk-title').trim();
    const desc = q('#tk-description').trim();
    const content = q('#tk-content').trim();
    const footer = q('#tk-footer').trim();
    const thumb = q('#tk-thumbnail').trim();
    const image = q('#tk-image').trim();
    const color = /^#[0-9a-fA-F]{6}$/.test(q('#tk-color') || '') ? q('#tk-color') : '#5865F2';
    const btnEmoji = q('#tk-button-emoji');
    const btnLabel = q('#tk-button-label') || 'Open Ticket';
    const styleClass = (q('#tk-button-style') || 'Primary').toLowerCase();
    const showTs = !!document.querySelector('#tk-timestamp')?.checked;
    const authorUrl = q('#tk-author-url').trim() || null;
    const titleUrl = q('#tk-title-url').trim() || null;
    const footerIcon = q('#tk-footer-icon').trim() || null;

    const setText = (id, text, emptyKeep = false) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (text) {
            el.textContent = text;
            el.classList.remove('hidden');
            if (el.classList.contains('edb-empty')) el.classList.remove('edb-empty');
        } else {
            el.textContent = '';
            if (!emptyKeep) el.classList.add('edb-empty');
        }
    };
    const setImg = (id, src) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (src) {
            el.src = src;
            el.classList.remove('hidden');
        } else {
            el.removeAttribute('src');
            el.classList.add('hidden');
        }
    };
    const setLink = (el, href) => {
        if (!el) return;
        if (href) el.setAttribute('href', href);
        else el.removeAttribute('href');
    };

    // Content / plain body (above the embed).
    setText('edb-content', content);

    // Author row — icon + name (or a placeholder when empty).
    for (const px of ['', 'pv-']) {
        const authorEl = document.getElementById(`edb-${px}author`);
        if (!authorEl) continue;
        const nameEl = document.getElementById(`edb-${px}author-name`);
        if (nameEl) {
            nameEl.textContent = authorName;
            nameEl.classList.toggle('edb-empty', !authorName);
        }
        const iconEl = document.getElementById(`edb-${px}author-icon`);
        if (iconEl) {
            if (authorIcon) {
                iconEl.src = authorIcon;
                iconEl.classList.remove('hidden');
            } else {
                iconEl.removeAttribute('src');
                iconEl.classList.add('hidden');
            }
        }
        const hasAuthor = !!(authorName || authorIcon);
        authorEl.classList.toggle('edb-empty', !hasAuthor);
        // In the detached preview an empty author row is removed entirely so it
        // never leaves a stray gap (the embed just starts at title/description).
        if (px === 'pv-') authorEl.classList.toggle('hidden', !hasAuthor);
        if (px === 'pv-') {
            const linkEl = document.getElementById('edb-pv-author-link');
            setLink(linkEl, authorUrl);
        }
    }

    // Title / description live rows (in-region + preview).
    setText('edb-title', title);
    setText('edb-desc', desc);
    const pvTitleEl = document.getElementById('edb-pv-title');
    if (pvTitleEl) {
        const linkEl = document.getElementById('edb-pv-title-link');
        if (linkEl) linkEl.textContent = title;
        pvTitleEl.classList.toggle('hidden', !title);
        setLink(linkEl, titleUrl);
    }
    setText('edb-pv-desc', desc);
    const pvDescEl = document.getElementById('edb-pv-desc');
    if (pvDescEl) pvDescEl.classList.toggle('hidden', !desc);

    // Footer (text + time + optional icon).
    const footerText = document.getElementById('edb-footer')?.querySelector('.tk-preview-embed-footer-text') || document.getElementById('edb-pv-footer-text');
    if (footerText) footerText.textContent = footer;
    const pvFooterText = document.getElementById('edb-pv-footer-text');
    if (pvFooterText) {
        pvFooterText.textContent = footer;
        pvFooterText.classList.toggle('hidden', !footer);
    }
    // Show/hide the little timestamp in both footer rows.
    for (const timeEl of document.querySelectorAll('.edb-live-footer .tk-preview-embed-time, #edb-pv-time')) {
        if (!timeEl) continue;
        timeEl.textContent = showTs ? 'now' : '';
        timeEl.classList.toggle('hidden', !showTs);
    }
    const fIcon = document.getElementById('edb-pv-footer-icon');
    if (fIcon) {
        if (footerIcon) { fIcon.src = footerIcon; fIcon.classList.remove('hidden'); }
        else { fIcon.removeAttribute('src'); fIcon.classList.add('hidden'); }
    }
    // Hide the whole footer in the right-column preview when there is nothing
    // to show (no text, no icon, timestamp disabled) — a clean empty state.
    const pvFooter = document.getElementById('edb-pv-footer');
    if (pvFooter) {
        const hasFooter = footer || footerIcon || showTs;
        pvFooter.classList.toggle('hidden', !hasFooter);
        pvFooter.classList.toggle('edb-empty', !hasFooter);
    }

    // Thumbnail + large image (in-region + preview).
    setImg('edb-thumb', thumb);
    setImg('edb-image', image);
    setImg('edb-pv-thumb', thumb);
    setImg('edb-pv-image', image);
    // Preview rows: hide the whole wrapper when no image is configured so the
    // embed preview matches Discord exactly (nothing rendered, no gap).
    for (const imgId of ['edb-pv-thumb', 'edb-pv-image']) {
        const img = document.getElementById(imgId);
        if (!img) continue;
        const hasSrc = !!img.src && !img.classList.contains('hidden');
        const row = img.closest?.('.edb-live-thumb, .edb-live-image');
        if (row) {
            row.classList.toggle('hidden', !hasSrc);
            row.classList.remove('edb-empty');
        }
    }

    // Embed color bar.
    const bar = document.getElementById('edb-bar');
    if (bar) bar.style.background = color;

    // Open-ticket button (label + emoji + style class).
    const btn = document.getElementById('edb-button');
    if (btn) {
        const labelEl = document.getElementById('edb-button-label');
        if (labelEl) labelEl.textContent = btnLabel;
        let emojiEl = btn.querySelector('.edb-btn-emoji');
        if (btnEmoji) {
            if (!emojiEl) {
                emojiEl = document.createElement('span');
                emojiEl.className = 'edb-btn-emoji';
                btn.insertBefore(emojiEl, btn.firstChild);
            }
            emojiEl.textContent = btnEmoji;
        } else if (emojiEl) {
            emojiEl.remove();
        }
        btn.classList.remove(
            'tk-preview-button-primary', 'tk-preview-button-secondary',
            'tk-preview-button-success', 'tk-preview-button-danger', 'tk-preview-button-link'
        );
        btn.classList.add(`tk-preview-button-${styleClass}`);
        btn.classList.toggle('edb-empty', !btnEmoji && !btnLabel);
    }
}

let _previewTimer = null;
function scheduleTicketPreview() {
    clearTimeout(_previewTimer);
    _previewTimer = setTimeout(renderTicketPreview, 60);
}

// Re-render when any editor field changes (live WYSIWYG builder). Event
// delegation covers every input on every tab — including the embed builder).
const _tkPanels = document.querySelector('.tk-editor-panels');
if (_tkPanels) {
    _tkPanels.addEventListener('input', scheduleTicketPreview);
    _tkPanels.addEventListener('change', scheduleTicketPreview);
    _tkPanels.addEventListener('input', scheduleButtonsChips);
    _tkPanels.addEventListener('change', scheduleButtonsChips);
}

// ── Init ─────────────────────────────────────────────────────────────────────
bindEditorTabs();
bindButtonsBuilder();
bindQuickActions();
renderButtonsChips();
bindEdbMessageExtras();
bindEdbSaveState();
patchSaveBarDirtyTracking();
bindEdbNavigationGuard();
updateEdbCounters();

document.getElementById('tk-support-add')?.addEventListener('click', () => {
  const ml = document.querySelector('#tk-support-list');
  if (!ml) return;
  ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML('tk-support'));
  bindReactionRemovals();
  window.populateRoleSelects();
});
document.getElementById('tk-ping-add')?.addEventListener('click', () => {
  const ml = document.querySelector('#tk-ping-list');
  if (!ml) return;
  ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML('tk-ping'));
  bindReactionRemovals();
  window.populateRoleSelects();
});

if (typeof bindColorSync === 'function') {
    bindColorSync('tk-color', 'tk-color-text');
    bindColorSync('tk-cf-embed-color', 'tk-cf-embed-color-text');
}
window.populateRoleSelects();
window.populateChannelSelects();

// Pre-fill the Role tab's add/remove selects from the panel's saved role settings.

function preselectTicketRoleSettings() {
  const node = document.getElementById('panel-data');
  if (!node || !node.textContent) return;
  let parsed = null;
  try { parsed = JSON.parse(node.textContent); } catch (_) { return; }
  const rs = (parsed || {}).panel?.roleSettings || {};
  if (rs.open) {
    const o = rs.open;
    const oa = document.querySelector('.trole-open-add');
    if (oa && o.addRoleId) oa.value = o.addRoleId;
    const orm = document.querySelector('.trole-open-remove');
    if (orm && o.removeRoleId) orm.value = o.removeRoleId;
  }
  if (rs.close) {
    const c = rs.close;
    const ca = document.querySelector('.trole-close-add');
    if (ca && c.addRoleId) ca.value = c.addRoleId;
    const crm = document.querySelector('.trole-close-remove');
    if (crm && c.removeRoleId) crm.value = c.removeRoleId;
  }
}

preselectTicketRoleSettings();

window.__pcompCfg = {};
(function seedPcompCfg() {
  const node = document.getElementById('panel-data');
  if (!node || !node.textContent) return;
  let parsed = null;
  try { parsed = JSON.parse(node.textContent); } catch (_) { return; }
  const comps = (parsed || {}).panel?.components || [];
  comps.forEach((c, idx) => {
    const idKey = c.id != null ? String(c.id) : String(idx);
    if (c.ticketConfiguration) window.__pcompCfg[`comp:${idx}`] = c.ticketConfiguration;
    if (c.ticketConfiguration) window.__pcompCfg[`comp:${idKey}`] = c.ticketConfiguration;
    if (c.type === 'select') {
      (c.options || []).forEach((o, oi) => {
        if (o.ticketConfiguration) window.__pcompCfg[`opt:${oi}`] = o.ticketConfiguration;
      });
    }
  });
})();

bindPanelComponentsBuilder();

window.saveBar.register(saveTicketPanel);
window.saveBar.track(document.body);

// Paint the live preview once (and whenever the form is mutated — bound above).
renderTicketPreview();
