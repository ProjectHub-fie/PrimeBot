/* Tickets page — panel list + create/clone/rename/send/update/edit.
 * The editor form lives in the #tk-modal overlay: it opens in "create" mode
 * from the "Create a panel" button, and in "edit" mode from a panel card's
 * "Edit" button. Create → POST; Edit → PATCH.
 */

const GUILD_ID = window.guildData?.guildId;

// Tickets is currently an "upcoming" feature (see ticketsPage
// upcoming-locked-wrap) — the page renders a blurred "Coming Soon" overlay for
// ALL servers. In that case this script exits early — no API calls, no
// bindings — so the overlay is the only thing that works.
if (document.querySelector('.upcoming-locked-wrap.locked, .beta-locked-wrap.locked')) {
  // Nothing to wire — the overlay covers the panel.
} else {

const TICKET_BUTTON_STYLES = [
  { value: 'Primary', label: 'Blurple (Primary)' },
  { value: 'Secondary', label: 'Grey (Secondary)' },
  { value: 'Success', label: 'Green (Success)' },
  { value: 'Danger', label: 'Red (Danger)' },
];
const TICKET_MESSAGE_TYPES = [
  { value: 'embed', label: 'Embed message' },
  { value: 'plain', label: 'Plain text message' },
];

// null = create mode (POST); a panel object = edit mode (PATCH).
let editingPanel = null;

function ticketPanelCardHTML(panel) {
  const supportRoles = (panel.supportRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const pingRoles = (panel.pingRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const msgType = panel.messageType === 'plain' ? 'Plain text' : 'Embed';
  return `
    <div class="card rr-menu-card" data-panel="${panel.id}">
      <div class="card-title">
        <span><span class="icon">🎫</span> ${esc(panel.name)} <span class="tag ${panel.enabled ? 'on' : 'off'}">#${panel.id}</span></span>
        <span style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm tk-edit" data-panel="${panel.id}">Edit</button>
          <button class="btn btn-secondary btn-sm tk-send" data-panel="${panel.id}">Send / Resend</button>
          <button class="btn btn-secondary btn-sm tk-update" data-panel="${panel.id}">Update message</button>
          <button class="btn btn-secondary btn-sm tk-rename" data-panel="${panel.id}">Rename</button>
          <button class="btn btn-secondary btn-sm tk-clone" data-panel="${panel.id}">Clone</button>
          <button class="btn btn-secondary btn-sm tk-delete" data-panel="${panel.id}">Delete</button>
        </span>
      </div>
      <div class="rr-meta">
        <span><strong>Type:</strong> ${esc(msgType)}</span>
        <span><strong>Channel:</strong> ${panel.channelId ? `<#${esc(panel.channelId)}>` : 'not sent'}</span>
        <span><strong>Message:</strong> <code>${esc(panel.messageId || '—')}</code></span>
        <span><strong>Button:</strong> ${esc(panel.buttonEmoji || '')} ${esc(panel.buttonLabel)}</span>
        <span><strong>Max/user:</strong> ${esc(panel.maxOpenPerUser)}</span>
      </div>
      <div class="rr-mappings">
        <strong>Title:</strong> ${esc(panel.title || '—')}<br/>
        <strong>Support roles:</strong> ${supportRoles}<br/>
        <strong>Ping roles:</strong> ${pingRoles}
      </div>
      ${panel.claimButtonLabel ? `<div class="field-hint">Claim button: ${esc(panel.claimButtonLabel)}</div>` : ''}
    </div>`;
}

function ticketRoleRowHTML(selected = {}, prefix = 'tk-support') {
  const roleOpt = selected.roleId ? `<option value="${esc(selected.roleId)}" selected>Role</option>` : '';
  return `
    <div class="reaction-row" data-index="">
      <select class="${prefix}-role" data-role-select data-placeholder="Role">${roleOpt}</select>
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

// ── Modal open/close + form fill/reset ─────────────────────────────────────

function closeEditor() {
  const modal = document.getElementById('tk-modal');
  if (modal) modal.classList.add('hidden');
  editingPanel = null;
}

function setTextValue(id, value) {
  const el = document.querySelector(id);
  if (el) el.value = value ?? '';
}

function setChecked(id, value) {
  const el = document.querySelector(id);
  if (el) el.checked = !!value;
}

function resetTicketForm() {
  editingPanel = null;
  setTextValue('#tk-name', '');
  setTextValue('#tk-message-type', 'embed');
  setTextValue('#tk-title', '');
  setTextValue('#tk-description', '');
  setTextValue('#tk-content', '');
  setTextValue('#tk-footer', '');
  setTextValue('#tk-thumbnail', '');
  setTextValue('#tk-image', '');
  setTextValue('#tk-color', '#5865F2');
  setTextValue('#tk-color-text', '#5865F2');
  setTextValue('#tk-button-label', 'Open Ticket');
  setTextValue('#tk-button-emoji', '');
  setTextValue('#tk-button-style', 'Primary');
  setTextValue('#tk-category', 'general');
  setTextValue('#tk-ticket-name', '');
  setTextValue('#tk-open-name', '');
  setTextValue('#tk-claimed-name', '');
  setTextValue('#tk-closed-name', '');
  const supportList = document.querySelector('#tk-support-list');
  if (supportList) supportList.innerHTML = ticketRoleRowHTML({}, 'tk-support');
  const pingList = document.querySelector('#tk-ping-list');
  if (pingList) pingList.innerHTML = ticketRoleRowHTML({}, 'tk-ping');
  setTextValue('#tk-ticket-category-id', '');
  setTextValue('#tk-max-open', '1');
  setChecked('#tk-ask-reason', false);
  setTextValue('#tk-welcome', '');
  setTextValue('#tk-close-label', 'Close Ticket');
  setTextValue('#tk-close-emoji', '🔒');
  setTextValue('#tk-close-style', 'Danger');
  setTextValue('#tk-claim-label', '');
  setTextValue('#tk-claim-emoji', '');
  // Close flow
  setTextValue('#tk-cf-yes-label', 'Yes');
  setTextValue('#tk-cf-yes-emoji', '✅');
  setTextValue('#tk-cf-yes-style', 'Success');
  setTextValue('#tk-cf-no-label', 'No');
  setTextValue('#tk-cf-no-emoji', '✖️');
  setTextValue('#tk-cf-no-style', 'Danger');
  setChecked('#tk-cf-embed-enabled', false);
  setTextValue('#tk-cf-embed-title', '🔒 Ticket Closed');
  setTextValue('#tk-cf-embed-desc', '');
  setTextValue('#tk-cf-embed-footer', '{panel} · PrimeBot');
  setTextValue('#tk-cf-embed-color', '#ED4245');
  setTextValue('#tk-cf-embed-color-text', '#ED4245');
  setChecked('#tk-cf-transcript-enabled', false);
  setTextValue('#tk-cf-transcript-channel', '');
  for (const key of ['transcript', 'reopen', 'delete']) {
    setTextValue(`#tk-cf-btn-${key}-label`, key.charAt(0).toUpperCase() + key.slice(1));
    setTextValue(`#tk-cf-btn-${key}-emoji`, '');
    setTextValue(`#tk-cf-btn-${key}-style`, 'Primary');
  }
  setChecked('#tk-enabled', true);
  bindReactionRemovals();
}

function fillTicketForm(panel) {
  editingPanel = panel;
  setTextValue('#tk-name', panel.name);
  setTextValue('#tk-message-type', panel.messageType === 'plain' ? 'plain' : 'embed');
  setTextValue('#tk-title', panel.title);
  setTextValue('#tk-description', panel.description);
  setTextValue('#tk-content', panel.content);
  setTextValue('#tk-footer', panel.footerText);
  setTextValue('#tk-thumbnail', panel.thumbnailUrl);
  setTextValue('#tk-image', panel.imageUrl);
  setTextValue('#tk-color', panel.color || '#5865F2');
  setTextValue('#tk-color-text', panel.color || '#5865F2');
  setTextValue('#tk-button-label', panel.buttonLabel || 'Open Ticket');
  setTextValue('#tk-button-emoji', panel.buttonEmoji);
  setTextValue('#tk-button-style', panel.buttonStyle || 'Primary');
  setTextValue('#tk-category', panel.category || 'general');
  setTextValue('#tk-ticket-name', panel.ticketName);
  setTextValue('#tk-open-name', panel.openNameTemplate);
  setTextValue('#tk-claimed-name', panel.claimedNameTemplate);
  setTextValue('#tk-closed-name', panel.closedNameTemplate);
  const supportList = document.querySelector('#tk-support-list');
  if (supportList) {
    const roles = panel.supportRoleIds?.length ? panel.supportRoleIds : [null];
    supportList.innerHTML = roles.map(id => ticketRoleRowHTML({ roleId: id }, 'tk-support')).join('');
  }
  const pingList = document.querySelector('#tk-ping-list');
  if (pingList) {
    const roles = panel.pingRoleIds?.length ? panel.pingRoleIds : [null];
    pingList.innerHTML = roles.map(id => ticketRoleRowHTML({ roleId: id }, 'tk-ping')).join('');
  }
  setTextValue('#tk-ticket-category-id', panel.ticketCategoryId);
  setTextValue('#tk-max-open', String(panel.maxOpenPerUser ?? 1));
  setChecked('#tk-ask-reason', panel.askReason);
  setTextValue('#tk-welcome', panel.welcomeMessage);
  setTextValue('#tk-close-label', panel.closeButtonLabel || 'Close Ticket');
  setTextValue('#tk-close-emoji', panel.closeButtonEmoji ?? '🔒');
  setTextValue('#tk-close-style', panel.closeButtonStyle || 'Danger');
  setTextValue('#tk-claim-label', panel.claimButtonLabel);
  setTextValue('#tk-claim-emoji', panel.claimButtonEmoji);
  const cf = panel.closeFlow || {};
  setTextValue('#tk-cf-yes-label', cf.confirmYes?.label ?? 'Yes');
  setTextValue('#tk-cf-yes-emoji', cf.confirmYes?.emoji ?? '✅');
  setTextValue('#tk-cf-yes-style', cf.confirmYes?.style ?? 'Success');
  setTextValue('#tk-cf-no-label', cf.confirmNo?.label ?? 'No');
  setTextValue('#tk-cf-no-emoji', cf.confirmNo?.emoji ?? '✖️');
  setTextValue('#tk-cf-no-style', cf.confirmNo?.style ?? 'Danger');
  setChecked('#tk-cf-embed-enabled', cf.closeEmbed?.enabled);
  setTextValue('#tk-cf-embed-title', cf.closeEmbed?.title ?? '🔒 Ticket Closed');
  setTextValue('#tk-cf-embed-desc', cf.closeEmbed?.description);
  setTextValue('#tk-cf-embed-footer', cf.closeEmbed?.footer);
  setTextValue('#tk-cf-embed-color', cf.closeEmbed?.color ?? '#ED4245');
  setTextValue('#tk-cf-embed-color-text', cf.closeEmbed?.color ?? '#ED4245');
  setChecked('#tk-cf-transcript-enabled', cf.transcript?.enabled);
  setTextValue('#tk-cf-transcript-channel', cf.transcript?.channelId);
  for (const key of ['transcript', 'reopen', 'delete']) {
    setTextValue(`#tk-cf-btn-${key}-label`, cf.buttons?.[key]?.label);
    setTextValue(`#tk-cf-btn-${key}-emoji`, cf.buttons?.[key]?.emoji);
    setTextValue(`#tk-cf-btn-${key}-style`, cf.buttons?.[key]?.style ?? 'Primary');
  }
  setChecked('#tk-enabled', panel.enabled !== false);
  bindReactionRemovals();
}

function openEditor(panel) {
  if (panel) fillTicketForm(panel); else resetTicketForm();
  const titleEl = document.getElementById('tk-modal-title');
  if (titleEl) titleEl.textContent = panel ? `Edit panel — ${panel.name}` : 'Create panel';
  const saveBtn = document.getElementById('tk-save');
  if (saveBtn) saveBtn.textContent = panel ? 'Save changes' : 'Create panel';
  const modal = document.getElementById('tk-modal');
  if (modal) modal.classList.remove('hidden');
  window.populateRoleSelects();
  window.populateChannelSelects();
}

async function refreshTicketList() {
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/tickets`);
    const listEl = document.querySelector('.rr-list');
    if (listEl) {
      const panels = data.ticketPanels || [];
      listEl.innerHTML = panels.length
        ? panels.map(ticketPanelCardHTML).join('')
        : `<div class="alert alert-warn">No ticket panels yet. Create one with the button below — panels can only be configured from the dashboard.</div>`;
      bindTicketCardActions();
    }
  } catch (_) { /* surfaced via toast elsewhere */ }
}

function bindTicketCardActions() {
  const action = (selector, fn) => {
    document.querySelectorAll(selector).forEach(btn => {
      if (btn.dataset.bound) return;
      btn.dataset.bound = '1';
      btn.addEventListener('click', () => fn(btn));
    });
  };

  action('.tk-edit', async (btn) => {
    const id = btn.dataset.panel;
    const panels = (await api(`/api/guilds/${GUILD_ID}/tickets`).catch(() => ({}))).ticketPanels || [];
    const panel = panels.find(p => String(p.id) === String(id));
    if (!panel) { toast('Could not load this panel.', 'error'); return; }
    openEditor(panel);
  });

  action('.tk-delete', async (btn) => {
    const id = btn.dataset.panel;
    if (!confirm('Delete this ticket panel? The panel message will be removed if the bot sent it.')) return;
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}`, { method: 'DELETE' });
      toast('Panel deleted', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to delete', 'error'); }
  });

  action('.tk-clone', async (btn) => {
    const id = btn.dataset.panel;
    const name = prompt('Name for the cloned panel (leave blank for "<name> (copy)"):', '');
    if (name === null) return;
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}/clone`, { method: 'POST', body: JSON.stringify({ name: name || undefined }) });
      toast('Panel cloned', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to clone', 'error'); }
  });

  action('.tk-rename', async (btn) => {
    const id = btn.dataset.panel;
    const panels = (await api(`/api/guilds/${GUILD_ID}/tickets`).catch(() => ({}))).ticketPanels || [];
    const panel = panels.find(p => String(p.id) === String(id));
    const name = prompt('New panel name:', panel ? panel.name : '');
    if (name === null || !name.trim()) return;
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}/rename`, { method: 'POST', body: JSON.stringify({ name }) });
      toast('Panel renamed', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to rename', 'error'); }
  });

  action('.tk-send', async (btn) => {
    const id = btn.dataset.panel;
    const channelId = prompt('Channel ID to send the panel to (or the panel channel if blank):', '');
    if (channelId === null) return;
    try {
      const body = channelId.trim() ? { channelId: channelId.trim() } : {};
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}/send`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel sent to channel', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to send', 'error'); }
  });

  action('.tk-update', async (btn) => {
    const id = btn.dataset.panel;
    const messageId = prompt('Message ID to update with this panel (leave blank to update the panel’s last sent message):', '');
    if (messageId === null) return;
    try {
      const body = messageId.trim() ? { messageId: messageId.trim() } : {};
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}/update`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel message updated', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to update', 'error'); }
  });
}

bindColorSync('tk-color', 'tk-color-text');
bindColorSync('tk-cf-embed-color', 'tk-cf-embed-color-text');

document.getElementById('tk-support-add')?.addEventListener('click', () => {
  const ml = document.querySelector('#tk-support-list');
  if (!ml) return;
  ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML({}, 'tk-support'));
  bindReactionRemovals();
  window.populateRoleSelects();
});
document.getElementById('tk-ping-add')?.addEventListener('click', () => {
  const ml = document.querySelector('#tk-ping-list');
  if (!ml) return;
  ml.insertAdjacentHTML('beforeend', ticketRoleRowHTML({}, 'tk-ping'));
  bindReactionRemovals();
  window.populateRoleSelects();
});
bindReactionRemovals();

// Modal wiring — open in create/edit mode, close on ×/Cancel/backdrop.
document.getElementById('tk-create-open')?.addEventListener('click', () => openEditor(null));
document.getElementById('tk-modal-close')?.addEventListener('click', closeEditor);
document.getElementById('tk-modal-cancel')?.addEventListener('click', closeEditor);
document.getElementById('tk-modal')?.addEventListener('click', (e) => {
  if (e.target === document.getElementById('tk-modal')) closeEditor();
});

document.getElementById('tk-save')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const body = readTicketForm();
  if (!body.name.trim()) { toast('A panel name is required.', 'error'); return; }
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = 'Saving…';
  const editing = editingPanel;
  try {
    if (editing) {
      await api(`/api/guilds/${GUILD_ID}/tickets/${editing.id}`, { method: 'PATCH', body: JSON.stringify(body) });
      toast('Panel updated', 'success');
    } else {
      await api(`/api/guilds/${GUILD_ID}/tickets`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel created', 'success');
    }
    closeEditor();
    refreshTicketList();
  } catch (err) {
    toast(err.message || 'Failed to save', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

bindTicketCardActions();

} // end upcoming/beta lock guard
