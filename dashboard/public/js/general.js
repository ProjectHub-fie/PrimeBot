/* General page — loads the per-server website log (dashboard admin-action audit
 * trail) into the table beside the prefix editor.
 *
 * The website log rows come from GET /api/guilds/:id/logs/website. Each row is
 * rendered as a table row: serial number, admin username, content, and time.
 */

const GUILD_ID = window.guildData?.guildId;

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

function renderWebsiteLogs(logs) {
  const body = document.getElementById('wlog-body');
  if (!body) return;
  if (!Array.isArray(logs) || logs.length === 0) {
    body.innerHTML = `<tr><td colspan="4" class="wlog-empty">No dashboard actions logged yet.</td></tr>`;
    return;
  }
  body.innerHTML = logs.map((log, i) => `
    <tr>
      <td class="wlog-sl">${i + 1}</td>
      <td class="wlog-admin">${esc(log.adminUsername || 'Unknown')}</td>
      <td class="wlog-content">${esc(log.content || '')}</td>
      <td class="wlog-time">${esc(formatTime(log.createdAt))}</td>
    </tr>`).join('');
}

async function loadWebsiteLogs() {
  try {
    const { logs } = await api(`/api/guilds/${GUILD_ID}/logs/website?limit=100`);
    renderWebsiteLogs(logs);
  } catch (err) {
    const body = document.getElementById('wlog-body');
    if (body) body.innerHTML = `<tr><td colspan="4" class="wlog-empty">Failed to load website log.</td></tr>`;
  }
}

// Refresh the table after a successful prefix save so the just-recorded entry
// appears without a manual page reload. The save handler records the website
// log asynchronously (fire-and-forget), so give the write a moment to land
// before re-fetching. We use SaveBar's onSaved hook (fired after a successful
// save) rather than overriding markClean — runSave uses internal closures, so
// a markClean override on window.saveBar would never fire.
if (window.saveBar && typeof window.saveBar.onSaved === 'function') {
  window.saveBar.onSaved(() => {
    setTimeout(loadWebsiteLogs, 400);
  });
}

loadWebsiteLogs();
