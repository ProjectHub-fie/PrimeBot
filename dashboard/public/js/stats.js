/* Stats page — bot stats + shardnode node health.
 * Fetches /api/stats/bot and /api/stats/nodes and renders them into the
 * #stats-bot / #stats-nodes shells the page boots with.
 */

function statCardHTML(icon, value, label, primary) {
  return `
    <div class="stat-card${primary ? ' stat-primary' : ''}">
      <span class="stat-icon">${icon}</span>
      <span class="stat-value">${esc(value)}</span>
      <span class="stat-label">${esc(label)}</span>
    </div>`;
}

// A conic-gradient ring whose fill = percent of servers that adopted a feature.
function donutHTML(percent, label) {
  const p = Math.max(0, Math.min(100, Math.round(percent)));
  const deg = Math.round(p * 3.6);
  const fg = p >= 50 ? 'var(--green)' : p > 0 ? 'var(--blurple)' : 'var(--text-faint)';
  return `
    <div class="donut-item">
      <div class="donut" style="background:conic-gradient(${fg} ${deg}deg, var(--border-soft) ${deg}deg)">
        <span class="donut-pct">${p}%</span>
      </div>
      <div class="donut-label">${esc(label)}</div>
    </div>`;
}

function renderBotStats(data) {
  const wrap = document.getElementById('stats-bot');
  if (!wrap) return;
  const servers = data.servers ?? 0;
  const totalUsers = data.totalUsers ?? 0;
  // The member count is only ever a real Discord total: 'bot' = live heartbeat
  // member_count, 'rest' = REST-summed guild.memberCount. Members are NOT
  // tracked via leveling, so when neither is available we show a dash.
  const hasMemberCount = data.totalUsers != null
    && (data.totalUsersSource === 'bot' || data.totalUsersSource === 'rest');
  const usersLabel = hasMemberCount ? 'Total members (live)' : 'Members unavailable';
  const botName = data.bot?.username || data.botName || 'PrimeBot';
  const features = data.features || {};
  const serversLabel = data.serversSource === 'db' ? 'Servers configured' : 'Servers';
  const usersIcon = window.svgIcon ? window.svgIcon('users') : '👥';
  const usersValue = hasMemberCount ? Number(totalUsers).toLocaleString() : '—';
  const cards = [
    statCardHTML('🤖', botName, 'Bot', false),
    statCardHTML('📣', Number(servers).toLocaleString(), serversLabel, true),
    statCardHTML(usersIcon, usersValue, usersLabel, false),
    statCardHTML('🏷️', esc(data.version || ''), 'Version', false),
  ].join('');

  const donuts = [
    donutHTML(features.leveling?.percent ?? 0, 'Leveling'),
    donutHTML(features.welcome?.percent ?? 0, 'Welcome'),
    donutHTML(features.autoReactions?.percent ?? 0, 'Auto-Reactions'),
    donutHTML(features.broadcasts?.percent ?? 0, 'Broadcasts'),
  ].join('');

  const counts = [
    `${features.leveling?.count ?? 0} leveling`,
    `${features.welcome?.count ?? 0} welcome`,
    `${features.autoReactions?.count ?? 0} auto-reactions`,
    `${features.broadcasts?.count ?? 0} broadcasts`,
  ].join(' · ');

  wrap.innerHTML = `
    <div class="stats-band-head">
      <span class="stats-band-title">Bot statistics</span>
      <span class="stats-band-sub">${liveUsers ? 'Member count is reported live by the running bot across all servers.' : 'Server count is fetched live from Discord · feature adoption across configured servers.'}</span>
    </div>
    <div class="stats-cards">${cards}</div>
    <div class="stats-chart-wrap">
      <div class="stats-chart-head">Feature adoption (${esc(counts)})</div>
      <div class="donut-grid">${donuts}</div>
    </div>`;
}

const NODE_STATUS = {
  online: { icon: '🟢', label: 'Online', cls: 'node-online' },
  offline: { icon: '🔴', label: 'Offline', cls: 'node-offline' },
  never: { icon: '⚪', label: 'Never reported', cls: 'node-never' },
};

function nodeRowHTML(n) {
  const st = NODE_STATUS[n.status] || NODE_STATUS.never;
  const name = n.nodeName ? esc(n.nodeName) : '<span class="text-faint">—</span>';
  const role = esc(n.role);
  const active = n.active ? '<span class="node-badge node-active">ACTIVE</span>' : '<span class="node-badge node-standby">standby</span>';
  const hb = n.lastHeartbeat
    ? esc(new Date(n.lastHeartbeat).toLocaleString())
    : '—';
  const age = n.ageMs != null ? `${Math.round(n.ageMs / 1000)}s ago` : '—';
  // Live counts the active bot node reports on its heartbeat.
  const counts = n.memberCount != null
    ? ` · ${Number(n.memberCount).toLocaleString()} members in ${Number(n.guildCount ?? 0).toLocaleString()} servers`
    : '';
  return `
    <div class="node-row ${st.cls}">
      <span class="node-icon">${st.icon}</span>
      <div class="node-main">
        <div class="node-name">${name} ${active}</div>
        <div class="node-meta">role <code>${role}</code> · last heartbeat ${esc(hb)} (${esc(age)})${counts}</div>
      </div>
      <span class="node-status-label">${st.label}</span>
    </div>`;
}

function renderNodeStats(data) {
  const wrap = document.getElementById('stats-nodes');
  if (!wrap) return;
  const nodes = data.nodes || [];
  const lease = data.lease;
  const activeNode = nodes.find(n => n.active);
  const onlineCount = nodes.filter(n => n.status === 'online').length;

  const leaseHTML = lease
    ? `<div class="node-lease ${lease.stale ? 'stale' : ''}">
         <span class="node-lease-label">Failover lease</span>
         <span class="node-lease-owner">${esc(lease.ownerNodeName || '—')} <code>(${esc(lease.ownerRole || '')})</code></span>
         <span class="node-lease-meta ${lease.stale ? 'node-lease-stale' : ''}">${lease.stale ? '⚠️ lease stale' : '✅ active'} · last seen ${Math.round(lease.ageMs / 1000)}s ago</span>
       </div>`
    : '<div class="node-lease"><span class="node-lease-label">Failover lease</span><span class="node-lease-meta">No active lease (bot not running failover).</span></div>';

  wrap.innerHTML = `
    <div class="node-summary">
      <span><strong>${onlineCount}/${nodes.length}</strong> nodes online</span>
      <span>Active node: <strong>${activeNode ? esc(activeNode.nodeName || activeNode.role) : '—'}</strong></span>
    </div>
    <div class="node-list">${nodes.map(nodeRowHTML).join('')}</div>
    ${leaseHTML}
    <p class="node-note">Heartbeats are written by the bot's nodeFailover module every ~15s. A node is shown offline once its heartbeat is older than ${Math.round((data.thresholdMs || 45000) / 1000)}s.</p>`;
}

async function loadStatsBot() {
  try {
    const data = await api('/api/stats/bot');
    renderBotStats(data);
  } catch (err) {
    const wrap = document.getElementById('stats-bot');
    if (wrap) wrap.innerHTML = `<div class="alert alert-error">${esc(err.message || 'Failed to load bot stats.')}</div>`;
  }
}

async function loadStatsNodes() {
  try {
    const data = await api('/api/stats/nodes');
    renderNodeStats(data);
  } catch (err) {
    const wrap = document.getElementById('stats-nodes');
    if (wrap) wrap.innerHTML = `<div class="alert alert-error">${esc(err.message || 'Failed to load node stats.')}</div>`;
  }
}

// ── Website latency graph (githubstatus-style) ──────────────────────────────
//
// The API returns an hourly series { ts, count, avg, p50, p95, max }. We draw a
// stroked line for the hourly average over soft threshold bands (green/yellow/
// red) so slow periods read at a glance. No chart library — a pure SVG polyline.

const LATENCY_BANDS = [
  { max: 500, cls: 'lat-band-ok', label: 'Good (<500ms)' },
  { max: 1500, cls: 'lat-band-warn', label: 'Slow (<1.5s)' },
  { max: Infinity, cls: 'lat-band-bad', label: 'Degraded (≥1.5s)' },
];

let latencyData = null;
let latencyDays = 30;

function bandFor(ms) {
  if (ms == null) return null;
  for (const b of LATENCY_BANDS) if (ms < b.max) return b.cls;
  return 'lat-band-bad';
}

function fmtAxisValue(v) {
  if (!v) return '';
  const d = new Date(v);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function renderLatencyGraph(data) {
  const wrap = document.getElementById('stats-latency');
  if (!wrap) return;
  const series = data.series || [];
  const summary = data.summary || {};
  const withData = series.filter(b => b.count > 0);
  const hasData = withData.length > 0;
  const win = data.days || latencyDays;
  const step = data.granularityMs || 3600000;

  if (!hasData) {
    wrap.innerHTML = `
      <div class="lat-empty">
        ${window.svgIcon ? window.svgIcon('activity') : ''}
        <p>No latency samples recorded yet in this window. Samples are captured automatically as the dashboard serves pages and API requests.</p>
      </div>`;
    return;
  }

  const W = 760, H = 200, PAD = { top: 12, right: 8, bottom: 26, left: 40 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;

  // Y scale: from 0 to a comfortable ceiling (a bit above the max, aligned to a
  // "nice" step). Guarantees a minimum span so a flat low-latency line still
  // has visible breathing room.
  const maxMs = Math.max(...withData.map(b => b.max || 0));
  const rawMax = Math.max(500, Math.ceil(maxMs * 1.15 / 100) * 100);
  const yStep = niceStep(rawMax / 4);
  const yMax = Math.ceil(rawMax / yStep) * yStep;
  const y = v => PAD.top + innerH - (Math.min(v, yMax) / yMax) * innerH;

  // X scale: map timestamp -> pixel over the full window span.
  const t0 = new Date(series[0].ts).getTime();
  const t1 = new Date(series[series.length - 1].ts).getTime() + step;
  const span = Math.max(t1 - t0, step);
  const x = ts => PAD.left + ((new Date(ts).getTime() - t0) / span) * innerW;

  const grid = [];
  for (let v = 0; v <= yMax; v += yStep) {
    grid.push(`<line x1="${PAD.left}" x2="${W - PAD.right}" y1="${y(v)}" y2="${y(v)}" class="lat-grid"/>`);
  }

  const bars = series.map(b => {
    const cx = x(b.ts) + ((x(b.ts + step) - x(b.ts)) / 2);
    const ms = b.avg;
    if (ms == null) return '';
    const cls = bandFor(ms);
    return `<rect class="lat-bar ${cls}" x="${(cx - 2).toFixed(1)}" y="${y(ms).toFixed(1)}" width="4" height="${(H - PAD.bottom - y(ms)).toFixed(1)}"/>`;
  }).join('');

  const line = withData.map(b => `${x(b.ts).toFixed(1)},${y(b.avg).toFixed(1)}`).join(' ');

  const xLabels = [];
  const labelEvery = Math.ceil(series.length / 6);
  series.forEach((b, i) => {
    if (i % labelEvery === 0) {
      xLabels.push(`<text x="${x(b.ts).toFixed(1)}" y="${H - 8}" class="lat-axis">${fmtAxisValue(b.ts)}</text>`);
    }
  });

  const lastPoint = withData[withData.length - 1];
  const nowLabel = lastPoint ? `${Math.round(lastPoint.avg)}ms avg` : '';

  const bands = LATENCY_BANDS.map(b => `<span class="lat-legend ${b.cls}">${b.label}</span>`).join('');

  wrap.innerHTML = `
    <div class="lat-head">
      <span class="lat-now">${nowLabel}</span>
      <span class="lat-summary">
        ${summary.avg != null ? `<b>${esc(String(summary.avg))}ms</b> avg · ` : ''}
        ${summary.p95 != null ? `<b>${esc(String(summary.p95))}ms</b> p95 · ` : ''}
        ${summary.max != null ? `<b>${esc(String(summary.max))}ms</b> max · ` : ''}
        <b>${Number(summary.sampleCount).toLocaleString()}</b> samples over <b>${win}</b> days
      </span>
      <span class="lat-legend-wrap">${bands}</span>
    </div>
    <svg class="lat-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Dashboard latency over the last ${win} days" preserveAspectRatio="none">
      ${grid}
      <line x1="${PAD.left}" x2="${W - PAD.right}" y1="${H - PAD.bottom}" y2="${H - PAD.bottom}" class="lat-axis-line"/>
      ${bars}
      ${line ? `<polyline points="${line}" class="lat-line" fill="none"/>` : ''}
      ${xLabels}
    </svg>`;
}

function niceStep(rough) {
  const pow = Math.pow(10, Math.floor(Math.log10(rough)));
  const n = rough / pow;
  const nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return nice * pow;
}

/** Render the "Slowest routes" breakdown table beneath the latency graph. */
function renderLatencyRoutes(routes) {
  const wrap = document.getElementById('stats-latency-routes');
  if (!wrap) return;
  const title = '<h3 class="lat-routes-title">Slowest routes</h3>';
  const list = routes || [];
  if (!list.length) {
    wrap.innerHTML = `${title}<p class="lat-routes-empty">No route breakdown yet in this window.</p>`;
    return;
  }
  const maxAvg = Math.max(...list.map(r => r.avg || 0));
  const rows = list.map(r => {
    const pct = maxAvg > 0 ? Math.round(((r.avg || 0) / maxAvg) * 100) : 0;
    const band = bandFor(r.avg);
    // Route strings are "METHOD /path"; split so the method gets its own chip.
    const sp = String(r.route || '').split(' ');
    const method = r.method || sp[0] || '';
    const path = sp.length > 1 ? sp.slice(1).join(' ') : String(r.route || '');
    return `<tr>
      <td class="lat-route-name"><span class="lat-route-method">${esc(method)}</span> <code>${esc(path)}</code></td>
      <td class="lat-num">${esc(String(r.avg ?? '—'))}ms</td>
      <td class="lat-num">${esc(String(r.p95 ?? '—'))}ms</td>
      <td class="lat-num">${esc(String(r.max ?? '—'))}ms</td>
      <td class="lat-num">${esc(String(r.count ?? 0))}</td>
      <td class="lat-bar-cell"><div class="lat-route-bar ${band || ''}" style="width:${pct}%"></div></td>
    </tr>`;
  }).join('');

  wrap.innerHTML = `
    ${title}
    <table class="lat-routes">
      <thead><tr>
        <th>Route</th><th>Avg</th><th>P95</th><th>Max</th><th>Count</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function loadStatsLatency() {
  const wrap = document.getElementById('stats-latency');
  const windows = document.getElementById('latency-windows');
  if (!wrap) return;
  if (windows) windows.hidden = false;
  try {
    const data = await api(`/api/stats/latency?days=${latencyDays}`);
    latencyData = data;
    renderLatencyGraph(data);
    renderLatencyRoutes(data.routes);
  } catch (err) {
    wrap.innerHTML = `<div class="alert alert-error">${esc(err.message || 'Failed to load latency stats.')}</div>`;
  }
}

// Window switcher: re-fetch with the selected range without reloading the page.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.lat-window');
  if (!btn) return;
  const days = Number(btn.dataset.days);
  latencyDays = days;
  document.querySelectorAll('.lat-window').forEach(b => b.classList.toggle('active', Number(b.dataset.days) === days));
  loadStatsLatency();
});

// Auto-refresh so the graph stays live while the Stats page is open. Pauses
// while the tab is hidden (Neon-friendly: no background polling).
let latencyRefreshTimer = null;
function scheduleLatencyRefresh() {
  if (latencyRefreshTimer) clearInterval(latencyRefreshTimer);
  latencyRefreshTimer = setInterval(() => {
    if (document.hidden) return;
    loadStatsLatency();
  }, 60000);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadStatsLatency();
});

loadStatsBot();
loadStatsNodes();
loadStatsLatency();
scheduleLatencyRefresh();
