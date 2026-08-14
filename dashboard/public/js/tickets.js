/* Tickets page — panel list + create/edit/clone/rename/send/update.
 * Mirrors the old SPA bindTicketEvents + bindTicketCardActions + refreshTicketList.
 */

const GUILD_ID = window.guildData?.guildId;

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

function ticketPanelCardHTML(panel) {
  const supportRoles = (panel.supportRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const pingRoles = (panel.pingRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const msgType = panel.messageType === 'plain' ? 'Plain text' : 'Embed';
  return `
    <div class="card rr-menu-card" data-panel="${panel.id}">
      <div class="card-title">
        <span><span class="icon">🎫</span> ${esc(panel.name)} <span class="tag ${panel.enabled ? 'on' : 'off'}">#${panel.id}</span></span>
        <span style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm tk-send" data-panel="${panel.id}">Send / Resend</button>
          <button class="btn btn-secondary btn-sm tk-update" data-panel="${panel.id}">Update message</button>
          <button class="btn btn-secondary btn-sm tk-rename" data-panel="${panel.id}">Rename</button>
          <button class="btn btn-secondary btn-sm tk-clone" data-panel="${panel.id}">Clone</button>
          <button class="btn btn-secondary btn-sm tk-edit" data-panel="${panel.id}">Edit</button>
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
    categoryId: q('#tk-category') || 'general',
    ticketName: q('#tk-ticket-name') || null,
    openNameTemplate: q('#tk-open-name') || null,
    claimedNameTemplate: q('#tk-claimed-name') || null,
    closedNameTemplate: q('#tk-closed-name') || null,
    supportRoleIds: collectTicketRoles('#tk-support-list', 'tk-support-role'),
    pingRoleIds: collectTicketRoles('#tk-ping-list', 'tk-ping-role'),
    ticketCategoryId: q('#tk-ticket-category-id') || null,
    maxOpenPerUser: parseInt(q('#tk-max-open'), 10) || 1,
    askForReason: document.querySelector('#tk-ask-reason')?.checked ?? false,
    welcomeMessage: q('#tk-welcome') || null,
    closeButtonLabel: q('#tk-close-label') || 'Close Ticket',
    closeButtonEmoji: q('#tk-close-emoji') || '🔒',
    claimButtonLabel: q('#tk-claim-label') || null,
    claimButtonEmoji: q('#tk-claim-emoji') || null,
    enabled: document.querySelector('#tk-enabled')?.checked ?? true,
  };
}

function fillTicketForm(panel) {
  const set = (id, val) => { const el = document.querySelector(id); if (el) el.value = val ?? ''; };
  set('#tk-edit-id', panel.id);
  set('#tk-name', panel.name);
  set('#tk-message-type', panel.messageType);
  set('#tk-title', panel.title);
  set('#tk-description', panel.description);
  set('#tk-content', panel.content);
  set('#tk-footer', panel.footerText);
  set('#tk-thumbnail', panel.thumbnailUrl);
  set('#tk-image', panel.imageUrl);
  set('#tk-color', panel.color || '#5865F2');
  set('#tk-color-text', panel.color || '#5865F2');
  set('#tk-button-label', panel.buttonLabel);
  set('#tk-button-emoji', panel.buttonEmoji);
  set('#tk-button-style', panel.buttonStyle);
  set('#tk-category', panel.categoryId);
  set('#tk-ticket-name', panel.ticketName);
  set('#tk-open-name', panel.openNameTemplate);
  set('#tk-claimed-name', panel.claimedNameTemplate);
  set('#tk-closed-name', panel.closedNameTemplate);
  set('#tk-ticket-category-id', panel.ticketCategoryId);
  set('#tk-max-open', panel.maxOpenPerUser);
  set('#tk-welcome', panel.welcomeMessage);
  set('#tk-close-label', panel.closeButtonLabel);
  set('#tk-close-emoji', panel.closeButtonEmoji);
  set('#tk-claim-label', panel.claimButtonLabel);
  set('#tk-claim-emoji', panel.claimButtonEmoji);
  document.querySelector('#tk-ask-reason').checked = !!panel.askForReason;
  document.querySelector('#tk-enabled').checked = panel.enabled !== false;
  const supportList = document.querySelector('#tk-support-list');
  supportList.innerHTML = (panel.supportRoleIds && panel.supportRoleIds.length
    ? panel.supportRoleIds : [null]
  ).map(id => ticketRoleRowHTML(id ? { roleId: id } : {}, 'tk-support')).join('');
  const pingList = document.querySelector('#tk-ping-list');
  pingList.innerHTML = (panel.pingRoleIds && panel.pingRoleIds.length
    ? panel.pingRoleIds : [null]
  ).map(id => ticketRoleRowHTML(id ? { roleId: id } : {}, 'tk-ping')).join('');
  window.populateRoleSelects();
  const saveBtn = document.querySelector('#tk-save');
  saveBtn.textContent = 'Save panel';
  document.querySelector('#tk-cancel-edit').style.display = '';
}

function clearTicketForm() {
  document.querySelector('#tk-edit-id').value = '';
  document.querySelector('#tk-save').textContent = 'Create panel';
  document.querySelector('#tk-cancel-edit').style.display = 'none';
}

async function refreshTicketList() {
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/tickets`);
    const listEl = document.querySelector('.rr-list');
    if (listEl) {
      const panels = data.ticketPanels || [];
      listEl.innerHTML = panels.length
        ? panels.map(ticketPanelCardHTML).join('')
        : `<div class="alert alert-warn">No ticket panels yet. Create one below — panels can only be configured from the dashboard.</div>`;
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

  action('.tk-delete', async (btn) => {
    const id = btn.dataset.panel;
    if (!confirm('Delete this ticket panel? The panel message will be removed if the bot sent it.')) return;
    try {
      await api(`/api/guilds/${GUILD_ID}/tickets/${id}`, { method: 'DELETE' });
      toast('Panel deleted', 'success');
      refreshTicketList();
    } catch (err) { toast(err.message || 'Failed to delete', 'error'); }
  });

  action('.tk-edit', async (btn) => {
    const id = btn.dataset.panel;
    const panels = (await api(`/api/guilds/${GUILD_ID}/tickets`).catch(() => ({}))).ticketPanels || [];
    const panel = panels.find(p => String(p.id) === String(id));
    if (!panel) { toast('Panel not found', 'error'); return; }
    fillTicketForm(panel);
    document.getElementById('tab-tickets')?.scrollIntoView({ behavior: 'smooth' });
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

document.getElementById('tk-save')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const editId = document.querySelector('#tk-edit-id').value;
  const body = readTicketForm();
  if (!body.name.trim()) { toast('A panel name is required.', 'error'); return; }
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = 'Saving…';
  try {
    if (editId) {
      await api(`/api/guilds/${GUILD_ID}/tickets/${editId}`, { method: 'PATCH', body: JSON.stringify(body) });
      toast('Panel saved', 'success');
    } else {
      await api(`/api/guilds/${GUILD_ID}/tickets`, { method: 'POST', body: JSON.stringify(body) });
      toast('Panel created', 'success');
    }
    clearTicketForm();
    refreshTicketList();
  } catch (err) {
    toast(err.message || 'Failed to save', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

document.getElementById('tk-cancel-edit')?.addEventListener('click', clearTicketForm);
bindTicketCardActions();
