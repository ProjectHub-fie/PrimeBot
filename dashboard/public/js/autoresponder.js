/* Auto-Responder page — add/remove response rules (trigger → reply, optional
 * exact match) and save via the floating Save bar. Mirrors the auto-reactions
 * page (settings-basic.js) but with a response field + exact-match checkbox.
 *
 * The save bar tracks form state and runs the registered saver; on success it
 * re-snapshots so the bar hides again. Empty rows are dropped on save.
 */

const GUILD_ID = window.guildData?.guildId;

function arRowHTML() {
  return `
    <div class="reaction-row ar-row" data-index="">
      <input type="text" class="ar-trigger" value="" placeholder="trigger word or phrase" />
      <input type="text" class="ar-response" value="" placeholder="reply text" />
      <label class="ar-exact-wrap" title="Only fire when the message exactly equals the trigger">
        <input type="checkbox" class="ar-exact" /> Exact
      </label>
      <button class="reaction-remove ar-remove" type="button">✕</button>
    </div>`;
}

function bindArRemovals() {
  document.querySelectorAll('#ar-list .ar-remove').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => {
      btn.closest('.ar-row')?.remove();
      saveBar.markDirty();
    });
  });
}

bindArRemovals();

document.getElementById('ar-add')?.addEventListener('click', () => {
  const list = document.getElementById('ar-list');
  if (!list) return;
  list.insertAdjacentHTML('beforeend', arRowHTML());
  bindArRemovals();
  saveBar.markDirty();
  list.lastElementChild?.querySelector('.ar-trigger')?.focus();
});

async function saveAutoResponder() {
  const responses = [];
  document.querySelectorAll('#ar-list .ar-row').forEach(row => {
    const trigger = row.querySelector('.ar-trigger').value.trim();
    const response = row.querySelector('.ar-response').value.trim();
    const exactMatch = row.querySelector('.ar-exact').checked;
    if (trigger && response) responses.push({ trigger, response, caseSensitive: false, exactMatch });
  });
  const body = {
    autoResponder: {
      enabled: document.getElementById('ar-enabled').checked,
      responses,
    },
  };
  await api(`/api/guilds/${GUILD_ID}/server`, { method: 'PATCH', body: JSON.stringify(body) });
}

if (document.getElementById('ar-enabled')) {
  saveBar.register(() => saveAutoResponder());
  saveBar.track(document.body);
}
