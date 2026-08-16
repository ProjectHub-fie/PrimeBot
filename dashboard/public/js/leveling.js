/* Leveling page — role rewards editor.
 * Role rewards are persisted to the leveling database (LEVELING_DATABASE_URL)
 * and the bot re-reads them on its cache reload, so dashboard changes take
 * effect without a bot restart.
 */

const GUILD_ID = window.guildData?.guildId;

function levRewardRowHTML(r = {}) {
  const roles = (window.guildData.roles || []).map(role => `<option value="${esc(role.id)}"${String(role.id) === String(r.roleId) ? ' selected' : ''}>${esc(role.name)}</option>`).join('');
  return `
    <div class="reaction-row lev-reward-row">
      <label style="display:flex;align-items:center;gap:6px">Level <input type="number" class="lev-reward-level" min="1" max="200" value="${esc(r.level ?? '')}" style="width:80px" /></label>
      <select class="lev-reward-role" data-role-select data-placeholder="— Role —">${roles ? `<option value="">— Role —</option>${roles}` : '<option value="">No assignable roles</option>'}</select>
      <button class="reaction-remove lev-reward-remove" type="button">✕</button>
    </div>`;
}

function bindLevRewardRemovals() {
  document.querySelectorAll('#lev-rewards-list .lev-reward-remove').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => btn.closest('.lev-reward-row')?.remove());
  });
}

document.getElementById('lev-reward-add')?.addEventListener('click', () => {
  const list = document.getElementById('lev-rewards-list');
  if (!list) return;
  const tpl = document.createElement('div');
  tpl.innerHTML = levRewardRowHTML();
  list.appendChild(tpl.firstElementChild);
  window.populateRoleSelects?.();
  bindLevRewardRemovals();
  saveBar.markDirty();
});

// Collect the current role-reward rows into a deduped, ordered list.
function readRoleRewards() {
  const rewards = [];
  const seen = new Set();
  document.querySelectorAll('#lev-rewards-list .lev-reward-row').forEach(row => {
    const level = parseInt(row.querySelector('.lev-reward-level')?.value, 10);
    const roleId = row.querySelector('.lev-reward-role')?.value;
    if (Number.isFinite(level) && level > 0 && roleId && !seen.has(level)) {
      seen.add(level);
      rewards.push({ level, roleId });
    }
  });
  return rewards;
}

async function saveRoleRewards() {
  const rewards = readRoleRewards();
  await api(`/api/guilds/${GUILD_ID}/leveling/rolerewards`, { method: 'PUT', body: JSON.stringify({ roleRewards: rewards }) });
  // Re-render from the collected values so the list reflects dedupe + order.
  const list = document.getElementById('lev-rewards-list');
  if (list) {
    list.innerHTML = rewards.slice().sort((a, b) => a.level - b.level).map(levRewardRowHTML).join('');
    window.populateRoleSelects?.();
    bindLevRewardRemovals();
  }
}

// Register with the floating save bar (the leveling page also registers the
// main leveling-settings saver via settings-basic.js).
saveBar.register(saveRoleRewards);
saveBar.track(document.body);

bindLevRewardRemovals();
