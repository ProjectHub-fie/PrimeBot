/* Tickets page — panel list + quick actions (create/clone/rename/send/update/delete).
 *
 * Editing a panel lives on a SEPARATE full-page editor
 * (/guild/:guildId/tickets/:panelId/edit) — there is no modal form on this page:
 *   - "Create a panel" posts to /api/guilds/:guildId/tickets/quickcreate,
 *     which auto-creates an "Untitled-N" panel, then redirects to the new
 *     panel's edit page (so editing before creation isn't ever needed).
 *   - a panel card's "Edit" navigates to that same edit page..

 * The editor page (ticket-editor.js) saves via PATCH and wired its own
 * Send / Resend / Update message / Clone / Rename / Delete quick actions..
 */

const GUILD_ID = window.guildData?.guildId;

// Tickets is currently an "upcoming" feature (see ticketsPage
// upcoming-locked-wrap) — the page renders a blurred "Coming Soon" overlay for
// ALL servers. In that case this script exits early — no API calls, no
// bindings — so the overlay is the only thing that works.
if (document.querySelector('.upcoming-locked-wrap.locked,.beta-locked-wrap.locked')) {

} else {

function ticketPanelCardHTML(panel) {
  const supportRoles = (panel.supportRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const pingRoles = (panel.pingRoleIds || []).map(id => `<@&${esc(id)}>`).join(', ') || '—';
  const msgType = panel.messageType === 'plain' ? 'Plain text' : 'Embed';
  return `
    <div class="card rr-menu-card" data-panel="${panel.id}">
      <div class="card-title">
        <span><span class="icon">${window.svgIcon('ticket')}</span> ${esc(panel.name)} <span class="tag ${panel.enabled ? 'on' : 'off'}">#${panel.id}</span></span>
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

// Quick-create — "Create a panel" auto-creates an "Untitled-N" panel and
// redirects to its edit page. There's no "edit before create" step..
document.getElementById('tk-create-open')?.addEventListener('click', async () => {
  const btn = document.getElementById('tk-create-open');
  if (!btn || btn.dataset.busy === '1') return;
  btn.dataset.busy = '1';
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = 'Creating…';
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/tickets/quickcreate`, { method: 'POST', body: JSON.stringify({ }) });
    const id = data.ticketPanel?.id;
    if (id) window.location.href = `/guild/${GUILD_ID}/tickets/${id}/edit`;
    else { toast('Panel created', 'success'); refreshTicketList(); }
  } catch (err) {
    toast(err.message || 'Failed to create panel', 'error');
  } finally {
    btn.dataset.busy = '0';
    btn.disabled = false;
    btn.textContent = orig;
  }
});

async function refreshTicketList() {
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/tickets`);
    const listEl = document.querySelector('.rr-list');
    if (listEl) {
      const panels = data.ticketPanels || [];
      listEl.innerHTML = panels.length
        ? panels.map(ticketPanelCardHTML).join('')
        : `<div class="alert alert-warn">No ticket panels yet.. Create one with the button below — panels can only be configured from the dashboard.</div>`;
      bindTicketCardActions();
    }
  } catch (err) { /* list renders server-side initially; refresh is best-effort */ }
}

function bindTicketCardActions() {
  const action = (selector, fn) => {
    document.querySelectorAll(selector).forEach(btn => {
      if (btn.dataset.bound) return;
      btn.dataset.bound = '1';
      btn.addEventListener('click', () => fn(btn));
    });
  };

  // Edit → the full-page editor (/guild/:guildId/tickets/:id/edit). No modal..
  action('.tk-edit', (btn) => {
    const id = btn.dataset.panel;
    if (!id) return;
    window.location.href = `/guild/${GUILD_ID}/tickets/${id}/edit`;
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
    const name = prompt('New panel name:', '');
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

bindTicketCardActions();

// The page renders an empty .rr-list when the server-side config contains
// panels (cards are rendered client-side — see ticketsPage), so refresh
// once on load so existing panels actually appear in the tab.
refreshTicketList();

} // end upcoming/beta lock guard
