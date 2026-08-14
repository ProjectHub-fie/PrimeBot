/* Reaction Roles page — create menus, list/edit/delete. Mirrors the old SPA
 * bindReactionRolesEvents + bindRrCardActions + refreshRrList.
 */

const GUILD_ID = window.guildData?.guildId;

function rrMappingRowHTML(m = {}) {
  const roleOpt = m.roleId ? `<option value="${esc(m.roleId)}" selected>Role</option>` : '';
  return `
    <div class="reaction-row" data-index="">
      <input type="text" class="r-emoji" value="${esc(m.emoji || '')}" placeholder="🎉 or <:name:id>" maxlength="100" />
      <select class="r-role" data-role-select data-placeholder="Role">${roleOpt}</select>
      <input type="text" class="r-label" value="${esc(m.label || '')}" placeholder="label (optional)" maxlength="100" />
      <button class="reaction-remove" type="button">✕</button>
    </div>`;
}

function rrMenuCardHTML(menu) {
  const mappings = (menu.mappings || []).map(m => {
    const e = /^\w+:\d+$/.test(m.emoji) ? `<:${m.emoji}>` : esc(m.emoji);
    return `${e} → <@&${esc(m.roleId)}>${m.label ? ' — ' + esc(m.label) : ''}`;
  }).join('<br/>');
  return `
    <div class="card rr-menu-card" data-menu="${menu.id}">
      <div class="card-title">
        <span><span class="icon">🎭</span> ${esc(menu.title || 'Untitled menu')} <span class="tag ${menu.enabled ? 'on' : 'off'}">#${menu.id}</span></span>
        <button class="btn btn-secondary btn-sm rr-delete" data-menu="${menu.id}">Delete</button>
      </div>
      <div class="rr-meta">
        <span><strong>Channel:</strong> <#${esc(menu.channelId)}></span>
        <span><strong>Message:</strong> <code>${esc(menu.messageId)}</code></span>
        <span><strong>Mode:</strong> <code>${esc(menu.mode)}</code></span>
        <span><strong>Persistent:</strong> ${menu.persistent ? '✅' : '⛔'}</span>
        <span><strong>Bot reactions:</strong> ${menu.includeBots ? '✅' : '⛔'}</span>
      </div>
      <div class="rr-mappings">${mappings || '<em>No mappings</em>'}</div>
      ${menu.requiredRoleId ? `<div class="field-hint">Requires <@&${esc(menu.requiredRoleId)}></div>` : ''}
      ${menu.exclusiveRoleId ? `<div class="field-hint">Removes <@&${esc(menu.exclusiveRoleId)}> on assign</div>` : ''}
      <button class="btn btn-secondary btn-sm rr-edit" data-menu="${menu.id}" style="margin-top:8px">Edit</button>
    </div>`;
}

function collectRrMappings() {
  const out = [];
  document.querySelectorAll('#rr-mappings-list .reaction-row').forEach(row => {
    const emoji = row.querySelector('.r-emoji')?.value.trim();
    const roleId = row.querySelector('.r-role')?.value;
    const label = row.querySelector('.r-label')?.value.trim();
    if (emoji && roleId) out.push({ emoji, roleId, label: label || null });
  });
  return out;
}

async function refreshRrList() {
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/reactionroles`);
    const listEl = document.querySelector('.rr-list');
    if (listEl) {
      const menus = data.reactionRoles || [];
      listEl.innerHTML = menus.length
        ? menus.map(rrMenuCardHTML).join('')
        : `<div class="alert alert-warn">No reaction-role menus yet. Create one below.</div>`;
      bindRrCardActions();
    }
  } catch (_) { /* surfaced via toast elsewhere */ }
}

function bindRrCardActions() {
  document.querySelectorAll('.rr-delete').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const id = btn.dataset.menu;
      if (!confirm('Delete this reaction-role menu? The bot will stop watching the message. Roles already granted stay.')) return;
      try {
        await api(`/api/guilds/${GUILD_ID}/reactionroles/${id}`, { method: 'DELETE' });
        toast('Menu deleted', 'success');
        refreshRrList();
      } catch (err) { toast(err.message || 'Failed to delete', 'error'); }
    });
  });
  document.querySelectorAll('.rr-edit').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const id = btn.dataset.menu;
      const menus = (await api(`/api/guilds/${GUILD_ID}/reactionroles`).catch(() => ({}))).reactionRoles || [];
      const menu = menus.find(m => String(m.id) === String(id));
      if (!menu) { toast('Menu not found', 'error'); return; }
      const nextTitle = prompt('Title (leave blank to keep):', menu.title || '');
      if (nextTitle !== null && nextTitle !== (menu.title || '')) {
        try {
          await api(`/api/guilds/${GUILD_ID}/reactionroles/${id}`, { method: 'PATCH', body: JSON.stringify({ title: nextTitle }) });
          toast('Updated', 'success');
          refreshRrList();
        } catch (err) { toast(err.message, 'error'); }
      }
    });
  });
}

// Attach vs bot-created toggle.
const attachToggle = document.getElementById('rr-attach');
if (attachToggle) {
  const sync = () => {
    const attach = attachToggle.checked;
    const msgField = document.getElementById('rr-message-field');
    const descField = document.getElementById('rr-description-field');
    if (msgField) msgField.style.display = attach ? '' : 'none';
    if (descField) descField.style.display = attach ? 'none' : '';
  };
  attachToggle.addEventListener('change', sync);
  sync();
}

bindColorSync('rr-color', 'rr-color-text');

document.getElementById('rr-mapping-add')?.addEventListener('click', () => {
  const ml = document.getElementById('rr-mappings-list');
  if (!ml) return;
  ml.insertAdjacentHTML('beforeend', rrMappingRowHTML());
  bindReactionRemovals();
  window.populateRoleSelects();
});
bindReactionRemovals();

document.getElementById('rr-create')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const attach = !!document.getElementById('rr-attach')?.checked;
  const channelId = document.getElementById('rr-channel')?.value;
  const messageId = document.getElementById('rr-message-id')?.value.trim();
  const mappings = collectRrMappings();
  if (mappings.length === 0) { toast('Add at least one emoji→role mapping.', 'error'); return; }
  if (!channelId) { toast('Select a channel.', 'error'); return; }
  if (attach && !messageId) { toast('Enter the message ID to attach to.', 'error'); return; }
  const body = {
    attach, channelId,
    messageId: attach ? messageId : undefined,
    title: document.getElementById('rr-title')?.value.trim() || null,
    description: document.getElementById('rr-description')?.value || null,
    color: document.getElementById('rr-color')?.value || '#5865F2',
    mode: document.getElementById('rr-mode')?.value || 'normal',
    persistent: document.getElementById('rr-persistent')?.checked !== false,
    includeBots: !!document.getElementById('rr-include-bots')?.checked,
    requiredRoleId: document.getElementById('rr-required-role')?.value || null,
    exclusiveRoleId: document.getElementById('rr-exclusive-role')?.value || null,
    mappings,
  };
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = 'Creating…';
  try {
    await api(`/api/guilds/${GUILD_ID}/reactionroles`, { method: 'POST', body: JSON.stringify(body) });
    toast('Reaction-role menu created', 'success');
    refreshRrList();
    document.getElementById('rr-title').value = '';
    document.getElementById('rr-description').value = '';
    document.getElementById('rr-message-id').value = '';
    const ml = document.getElementById('rr-mappings-list');
    if (ml) ml.innerHTML = rrMappingRowHTML();
    bindReactionRemovals();
    window.populateRoleSelects();
  } catch (err) {
    toast(err.message || 'Failed to create', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

bindRrCardActions();
