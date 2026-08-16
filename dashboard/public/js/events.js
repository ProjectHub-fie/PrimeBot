/* Events page — create event schedules with timed tasks, list/start/cancel/delete.
 * Mirrors the old SPA bindEventsTab + bindEventCardActions + loadEventSchedules.
 *
 * When the guild is not a beta server, the page renders a blurred, locked view
 * (see eventsPage beta-locked-wrap). In that case this script exits early — no
 * API calls, no bindings — so the overlay message is the only thing that works.
 */

const GUILD_ID = window.guildData?.guildId;

// Non-beta servers see a locked, read-only-blurred panel; do nothing.
if (document.querySelector('.beta-locked-wrap.locked')) {
  // Nothing to wire — the overlay covers the form.
} else {

const EVENT_ACTIONS = [
  { key: 'lock',      label: 'Lock channel(s)',        icon: '🔒', needs: 'channels' },
  { key: 'unlock',    label: 'Unlock channel(s)',      icon: '🔓', needs: 'channels' },
  { key: 'hide',      label: 'Hide channel(s)',        icon: '🙈', needs: 'channels' },
  { key: 'unhide',    label: 'Unhide channel(s)',      icon: '👀', needs: 'channels' },
  { key: 'addrole',   label: 'Add role to members',  icon: '➕', needs: 'roles' },
  { key: 'removerole',label: 'Remove role from members', icon: '➖', needs: 'roles' },
  { key: 'sendtext',  label: 'Send text message',    icon: '💬', needs: 'message' },
  { key: 'sendembed', label: 'Send embed message',   icon: '🖼️', needs: 'embed' },
];

function evTaskRowHTML(task = {}) {
  const actionOpts = EVENT_ACTIONS.map(x => `<option value="${x.key}" ${x.key === (task.action || 'sendtext') ? 'selected' : ''}>${x.icon} ${esc(x.label)}</option>`).join('');
  const selectedIds = Array.isArray(task.targetIds) ? task.targetIds.map(String) : [];
  const channelOpts = (window.guildData.channels || []).map(c => `<option value="${esc(c.id)}"${selectedIds.includes(String(c.id)) || String(c.id) === String(task.channelId) ? ' selected' : ''}>${esc(c.name)}</option>`).join('');
  const roleOpts = (window.guildData.roles || []).map(r => `<option value="${esc(r.id)}"${selectedIds.includes(String(r.id)) ? ' selected' : ''}>${esc(r.name)}</option>`).join('');
  return `
    <div class="ev-task-row" data-ev-task>
      <label>Offset (s)<input type="number" min="0" class="ev-offset" value="${task.offsetSeconds ?? 0}" /></label>
      <label>Action<select class="ev-action">${actionOpts}</select></label>
      <div class="ev-target">
        <label class="ev-tg-channels">Target channel(s) — pick one, or hold Ctrl/Cmd to select multiple<select class="ev-target-channels" multiple size="4">${channelOpts}</select></label>
        <label class="ev-tg-roles hidden">Target role(s) — hold Ctrl/Cmd to select multiple<select class="ev-target-roles" multiple size="4">${roleOpts}</select></label>
        <label class="ev-tg-message hidden">Message text <textarea class="ev-message" rows="2">${esc(task.messageContent || '')}</textarea></label>
        <div class="ev-tg-embed hidden">
          <label>Embed title <input type="text" class="ev-embed-title" value="${esc(task.embedTitle || '')}" /></label>
          <label>Embed description <textarea class="ev-embed-desc" rows="2">${esc(task.embedDescription || '')}</textarea></label>
          <label>Embed color <input type="color" class="ev-embed-color" value="${task.embedColor || '#5865F2'}" /></label>
          <label>Embed image URL <input type="text" class="ev-embed-image" value="${esc(task.embedImageUrl || '')}" /></label>
          <label class="ev-tg-channels">Send to channel(s)<select class="ev-target-embed-channels" multiple size="4">${channelOpts}</select></label>
        </div>
      </div>
      <button class="btn btn-secondary ev-remove-task" title="Remove task">✕</button>
    </div>`;
}

function bindEvTaskRow(row) {
  const updateVisibility = () => {
    const action = row.querySelector('.ev-action').value;
    const meta = EVENT_ACTIONS.find(x => x.key === action);
    const needs = meta ? meta.needs : 'channels';
    row.querySelector('.ev-tg-channels').classList.toggle('hidden', needs !== 'channels');
    row.querySelector('.ev-tg-roles').classList.toggle('hidden', needs !== 'roles');
    row.querySelector('.ev-tg-message').classList.toggle('hidden', needs !== 'message');
    row.querySelector('.ev-tg-embed').classList.toggle('hidden', needs !== 'embed');
  };
  row.querySelector('.ev-action').addEventListener('change', updateVisibility);
  row.querySelector('.ev-remove-task').addEventListener('click', () => row.remove());
  updateVisibility();
}

function readEventForm() {
  const tasks = [];
  document.querySelectorAll('#ev-tasks-list .ev-task-row').forEach(row => {
    const action = row.querySelector('.ev-action').value;
    const meta = EVENT_ACTIONS.find(x => x.key === action);
    const task = {
      offsetSeconds: parseInt(row.querySelector('.ev-offset').value, 10) || 0,
      action,
      targetType: meta && meta.needs === 'roles' ? 'role' : 'channel',
    };
    if (action === 'addrole' || action === 'removerole') {
      task.targetIds = Array.from(row.querySelector('.ev-target-roles').selectedOptions).map(o => o.value);
    } else if (action === 'sendtext') {
      task.messageContent = row.querySelector('.ev-message').value;
      task.targetIds = Array.from(row.querySelector('.ev-target-channels').selectedOptions).map(o => o.value);
    } else if (action === 'sendembed') {
      task.embedTitle = row.querySelector('.ev-embed-title').value;
      task.embedDescription = row.querySelector('.ev-embed-desc').value;
      task.embedColor = row.querySelector('.ev-embed-color').value;
      task.embedImageUrl = row.querySelector('.ev-embed-image').value;
      task.targetIds = Array.from(row.querySelector('.ev-target-embed-channels').selectedOptions).map(o => o.value);
    } else {
      task.targetIds = Array.from(row.querySelector('.ev-target-channels').selectedOptions).map(o => o.value);
    }
    tasks.push(task);
  });
  return {
    name: document.getElementById('ev-name').value,
    countdownSeconds: parseInt(document.getElementById('ev-countdown').value, 10) || 0,
    description: document.getElementById('ev-description').value,
    tasks,
  };
}

function clearEventForm() {
  document.getElementById('ev-name').value = '';
  document.getElementById('ev-countdown').value = '0';
  document.getElementById('ev-description').value = '';
  document.getElementById('ev-tasks-list').innerHTML = '';
}

function eventStatusBadge(status) {
  const map = {
    scheduled: { c: 'tag off', t: 'Scheduled' },
    running: { c: 'tag on', t: 'Running' },
    completed: { c: 'tag prefix', t: 'Completed' },
    cancelled: { c: 'tag off', t: 'Cancelled' },
  };
  const m = map[status] || map.scheduled;
  return `<span class="${m.c}">${m.t}</span>`;
}

function eventScheduleCardHTML(s) {
  const tasksHTML = (s.tasks || []).map(t => {
    const meta = EVENT_ACTIONS.find(x => x.key === t.action) || {};
    return `<li>${meta.icon || ''} ${esc(meta.label || t.action)} @ +${t.offsetSeconds}s</li>`;
  }).join('');
  const start = s.startAt ? new Date(s.startAt).toLocaleString() : '—';
  return `
    <div class="live-card ev-card" data-ev-id="${s.id}">
      <div class="live-card-title">${esc(s.name)}</div>
      <div class="live-card-meta">${eventStatusBadge(s.status)} • countdown ${s.countdownSeconds}s • start ${esc(start)}</div>
      ${s.description ? `<div class="live-card-opts">${esc(s.description)}</div>` : ''}
      <div class="ev-tasks"><strong>Tasks:</strong><ul>${tasksHTML || '<li>none</li>'}</ul></div>
      <div class="ev-actions">
        <button class="btn btn-primary ev-start" data-id="${s.id}">Start now</button>
        <button class="btn btn-secondary ev-cancel" data-id="${s.id}">Cancel</button>
        <button class="btn btn-secondary ev-delete" data-id="${s.id}">Delete</button>
      </div>
    </div>`;
}

async function loadEventSchedules() {
  const list = document.getElementById('ev-list');
  if (!list) return;
  try {
    const data = await api(`/api/guilds/${GUILD_ID}/events`);
    const schedules = data.schedules || [];
    list.innerHTML = schedules.length
      ? schedules.map(eventScheduleCardHTML).join('')
      : '<p class="live-empty">No events yet. Create one above.</p>';
    bindEventCardActions();
  } catch (err) {
    list.innerHTML = `<div class="alert alert-error">${esc(err.message || 'Failed to load events.')}</div>`;
  }
}

function bindEventCardActions() {
  document.querySelectorAll('#ev-list .ev-start').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${GUILD_ID}/events/${btn.dataset.id}/start`, { method: 'POST' }); toast('Event started.'); loadEventSchedules(); }
    catch (e) { toast(e.message, 'error'); }
  }));
  document.querySelectorAll('#ev-list .ev-cancel').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${GUILD_ID}/events/${btn.dataset.id}/cancel`, { method: 'POST' }); toast('Event cancelled.'); loadEventSchedules(); }
    catch (e) { toast(e.message, 'error'); }
  }));
  document.querySelectorAll('#ev-list .ev-delete').forEach(btn => btn.addEventListener('click', async () => {
    try { await api(`/api/guilds/${GUILD_ID}/events/${btn.dataset.id}`, { method: 'DELETE' }); toast('Event deleted.'); loadEventSchedules(); }
    catch (e) { toast(e.message, 'error'); }
  }));
}

document.getElementById('ev-add-task')?.addEventListener('click', () => {
  const row = document.createElement('div');
  row.innerHTML = evTaskRowHTML({});
  const el = row.firstElementChild;
  document.getElementById('ev-tasks-list').appendChild(el);
  bindEvTaskRow(el);
});
document.getElementById('ev-clear')?.addEventListener('click', clearEventForm);
document.getElementById('ev-save')?.addEventListener('click', async () => {
  const body = readEventForm();
  if (!body.name.trim()) { toast('Event name is required.', 'error'); return; }
  try {
    await api(`/api/guilds/${GUILD_ID}/events`, { method: 'POST', body: JSON.stringify(body) });
    toast('Event created.');
    clearEventForm();
    loadEventSchedules();
  } catch (e) { toast(e.message, 'error'); }
});

loadEventSchedules();

} // end beta-gated else block
