/* General page — loads the per-server audit log (dashboard admin-action audit
 * trail) into the table beside the prefix editor.
 *
 * The audit log rows come from GET /api/guilds/:id/logs/website. Rows are
 * rendered 10 per page; a pagination bar (Prev / numbered pages / Next) sits
 * under the table so a long history doesn't blow up the page length.
 */

// Both this file and settings-basic.js are loaded on the General page, and both
// used to declare a top-level `const GUILD_ID`. A duplicate top-level
// declaration is a SyntaxError that kills the ENTIRE second script — which is
// why the audit log was stuck on "Loading…". Wrap this script in an IIFE so its
// bindings stay local and it runs regardless.
(() => {
  const GUILD_ID = window.guildData?.guildId;
  const PAGE_SIZE = 10;
  let allLogs = [];
  let currentPage = 1;

  function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString();
  }

  function renderRows() {
    const body = document.getElementById('wlog-body');
    if (!body) return;
    if (!Array.isArray(allLogs) || allLogs.length === 0) {
      body.innerHTML = `<tr><td colspan="4" class="wlog-empty">No dashboard actions logged yet.</td></tr>`;
      return;
    }
    const start = (currentPage - 1) * PAGE_SIZE;
    const slice = allLogs.slice(start, start + PAGE_SIZE);
    body.innerHTML = slice.map((log, i) => `
      <tr>
        <td class="wlog-sl">${start + i + 1}</td>
        <td class="wlog-admin">${esc(log.adminUsername || 'Unknown')}</td>
        <td class="wlog-content">${esc(log.content || '')}</td>
        <td class="wlog-time">${esc(formatTime(log.createdAt))}</td>
      </tr>`).join('');
  }

  function renderPagination() {
    const pg = document.getElementById('wlog-pagination');
    if (!pg) return;
    const totalPages = Math.ceil(allLogs.length / PAGE_SIZE);
    if (!allLogs.length || totalPages <= 1) { pg.innerHTML = ''; return; }
    // Windowed numbered buttons: first/last + current±2, with ellipses.
    const pages = new Set([1, totalPages]);
    for (let p = currentPage - 2; p <= currentPage + 2; p++) {
      if (p >= 1 && p <= totalPages) pages.add(p);
    }
    let html = `<button class="wlog-page-btn wlog-prev" ${currentPage === 1 ? 'disabled' : ''}>‹ Prev</button>`;
    let last = 0;
    for (const p of [...pages].sort((a, b) => a - b)) {
      if (last && p - last > 1) html += `<span class="wlog-ellipsis">…</span>`;
      html += `<button class="wlog-page-btn ${p === currentPage ? 'active' : ''}" data-page="${p}">${p}</button>`;
      last = p;
    }
    html += `<button class="wlog-page-btn wlog-next" ${currentPage === totalPages ? 'disabled' : ''}>Next ›</button>`;
    pg.innerHTML = html;

    pg.querySelectorAll('.wlog-page-btn[data-page]').forEach(b => {
      b.addEventListener('click', () => {
        currentPage = Number(b.dataset.page);
        renderRows();
        renderPagination();
      });
    });
    pg.querySelector('.wlog-prev')?.addEventListener('click', () => {
      if (currentPage > 1) { currentPage -= 1; renderRows(); renderPagination(); }
    });
    pg.querySelector('.wlog-next')?.addEventListener('click', () => {
      if (currentPage < totalPages) { currentPage += 1; renderRows(); renderPagination(); }
    });
  }

  async function loadAuditLogs() {
    try {
      const { logs } = await api(`/api/guilds/${GUILD_ID}/logs/website?limit=500`);
      allLogs = logs || [];
      currentPage = 1;
      renderRows();
      renderPagination();
    } catch (err) {
      allLogs = [];
      const body = document.getElementById('wlog-body');
      if (body) body.innerHTML = `<tr><td colspan="4" class="wlog-empty">Failed to load audit log.</td></tr>`;
      renderPagination();
    }
  }

  // Refresh the table after a successful save so the just-recorded entry
  // appears without a manual page reload. The save handler records the audit
  // entry asynchronously (fire-and-forget), so give the write a moment to land
  // before re-fetching. We use SaveBar's onSaved hook (fired after a successful
  // save) rather than overriding markClean — runSave uses internal closures, so
  // a markClean override on window.saveBar would never fire.
  if (window.saveBar && typeof window.saveBar.onSaved === 'function') {
    window.saveBar.onSaved(() => {
      setTimeout(loadAuditLogs, 400);
    });
  }

  loadAuditLogs();
})();
