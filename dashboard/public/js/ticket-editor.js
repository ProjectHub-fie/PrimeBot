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
  return {
    name: q('#tk-name').trim() || 'Support Ticket',
    messageType: q('#tk-message-type') || 'embed',
    title: q('#tk-title').trim() || null,
    description: q('#tk-description').trim() || null,
    content: q('#tk-content').trim() || null,
    footerText: q('#tk-footer').trim() || null,
    thumbnailUrl: q('#tk-thumbnail').trim() || null,
    imageUrl: q('#tk-image').trim() || null,
    color: q('#tk-color') || '#5865F2',
    buttonLabel: q('#tk-button-label') || 'Open Ticket',
    buttonEmoji: q('#tk-button-emoji') || null,
    buttonStyle: q('#tk-button-style') || 'Primary',
    category: q('#tk-category') || 'general',
    ticketName: q('#tk-ticket-name') || null,
    openNameTemplate: q('#tk-open-name') || null,
    claimedNameTemplate: q('#tk-claimed-name') || null,
    closedNameTemplate: q('#tk-closed-name') || null,
    supportRoleIds: collectTicketRoles('#tk-support-list', 'tk-support-role'),
    pingRoleIds: collectTicketRoles('#tk-ping-list', 'tk-ping-role'),
    ticketCategoryId: q('#tk-ticket-category-id') || null,
    maxOpenPerUser: parseInt(q('#tk-max-open'), 10) || 1,
    askReason: document.querySelector('#tk-ask-reason')?.checked ?? false,
    welcomeMessage: q('#tk-welcome') || null,
    closeButtonLabel: q('#tk-close-label') || 'Close Ticket',
    closeButtonEmoji: q('#tk-close-emoji') || '🔒',
    closeButtonStyle: q('#tk-close-style') || 'Danger',
    claimButtonLabel: q('#tk-claim-label') || null,
    claimButtonEmoji: q('#tk-claim-emoji') || null,
    closeFlow: readCloseFlowForm(),
    enabled: document.querySelector('#tk-enabled')?.checked ?? true,
  };
}

function readCloseFlowForm() {
  const q = id => document.querySelector(id)?.value ?? '';
  const chk = id => document.querySelector(id)?.checked ?? false;
  const btn = (key) => ({
    label: q(`#tk-cf-btn-${key}-label`) || key.charAt(0).toUpperCase() + key.slice(1),
    emoji: q(`#tk-cf-btn-${key}-emoji`) || null,
    style: q(`#tk-cf-btn-${key}-style`) || 'Primary',
  });
  return {
    confirmYes: {
      label: q('#tk-cf-yes-label') || 'Yes',
      emoji: q('#tk-cf-yes-emoji') || null,
      style: q('#tk-cf-yes-style') || 'Success',
    },
    confirmNo: {
      label: q('#tk-cf-no-label') || 'No',
      emoji: q('#tk-cf-no-emoji') || null,
      style: q('#tk-cf-no-style') || 'Danger',
    },
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
  };
}

// ── Save (floating Save changes bar → PATCH) ─────────────────────────────
async function saveTicketPanel() {
  if (!GUILD_ID || !PANEL_ID) throw new Error('Missing ticket panel context.');
  const body = readTicketForm();
  await api(`/api/guilds/${GUILD_ID}/tickets/${PANEL_ID}`, { method: 'PATCH', body: JSON.stringify(body) });
  // Keep the page's heading + panel-id chip fresh after a rename.

  if (window.refreshPanelActions) window.refreshPanelActions();
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

// ── Live embed preview ("edit in embed") ───────────────────────────────────
// Re-renders the Discord-style preview beside the form as the user types. Matches
// the server-render initial state in guild-pages.js ticketPreviewHTML.
function renderTicketPreview() {
    const q = id => document.querySelector(id)?.value ?? '';
    const isPlain = (q('#tk-message-type') || 'embed') === 'plain';
    const color = /^#[0-9a-fA-F]{6}$/.test(q('#tk-color') || '') ? q('#tk-color') : '#5865F2';
    const styleClass = (q('#tk-button-style') || 'Primary').toLowerCase();
    const btnEmoji = q('#tk-button-emoji');
    const btnLabel = q('#tk-button-label') || 'Open Ticket';
    const hasThumb = !!q('#tk-thumbnail').trim();
    const hasImage = !!q('#tk-image').trim();
    const body = isPlain
        ? `<div class="tk-preview-plain">${esc(q('#tk-content') || q('#tk-description') || 'Click the button below to open a support ticket.')}</div>`
        : `
      <div class="tk-preview-embed">
        <div class="tk-preview-embed-bar" style="background:${esc(color)}"></div>
        <div class="tk-preview-embed-body">
          ${q('#tk-title') ? `<div class="tk-preview-embed-title">${esc(q('#tk-title'))}</div>` : ''}
          ${q('#tk-description') ? `<div class="tk-preview-embed-desc">${esc(q('#tk-description'))}</div>` : ''}
          ${hasThumb ? `<div class="tk-preview-embed-thumb-wrap"><img class="tk-preview-embed-thumb" src="${esc(q('#tk-thumbnail'))}" alt="" /></div>` : ''}
          ${hasImage ? `<div class="tk-preview-embed-img-wrap"><img class="tk-preview-embed-img" src="${esc(q('#tk-image'))}" alt="" /></div>` : ''}
          <div class="tk-preview-embed-footer">
            ${q('#tk-footer') ? `<span class="tk-preview-embed-footer-text">${esc(q('#tk-footer'))}</span>` : ''}
            <span class="tk-preview-embed-time">now</span>
          </div>
        </div>
      </div>`;
    const host = document.getElementById('tk-live-preview');
    if (!host) return;
    host.innerHTML = `
    <div class="tk-preview-discord">
      ${q('#tk-content') ? `<div class="tk-preview-content-line">${esc(q('#tk-content'))}</div>` : ''}
      ${body}
      <div class="tk-preview-button tk-preview-button-${esc(styleClass)}">${btnEmoji ? esc(btnEmoji) + ' ' : ''}${esc(btnLabel)}</div>
    </div>`;
}

let _previewTimer = null;
function scheduleTicketPreview() {
    clearTimeout(_previewTimer);
    _previewTimer = setTimeout(renderTicketPreview, 60);
}

// Re-render when any editor field changes (live WYSIWYG). Event delegation
// covers fields spawned later (e.g. nothing needed here — all inputs exist at load).
const _tkGrid = document.querySelector('.tk-editor-grid');
if (_tkGrid) {
    _tkGrid.addEventListener('input', scheduleTicketPreview);
    _tkGrid.addEventListener('change', scheduleTicketPreview);
}

// ── Init ─────────────────────────────────────────────────────────────────────
bindEditorTabs();
bindQuickActions();

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

bindColorSync('tk-color', 'tk-color-text');
bindColorSync('tk-cf-embed-color', 'tk-cf-embed-color-text');
window.populateRoleSelects();
window.populateChannelSelects();

window.saveBar.register(saveTicketPanel);
window.saveBar.track(document.body);

// Paint the live preview once (and whenever the form is mutated — bound above).
renderTicketPreview();
