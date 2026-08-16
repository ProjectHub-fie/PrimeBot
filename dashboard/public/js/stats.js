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
  const botName = data.bot?.username || data.botName || 'PrimeBot';
  const features = data.features || {};
  const cards = [
    statCardHTML('🤖', botName, 'Bot', false),
    statCardHTML('📣', Number(servers).toLocaleString(), 'Servers', true),
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
      <span class="stats-band-sub">Server count is fetched live from Discord · feature adoption across configured servers.</span>
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
  return `
    <div class="node-row ${st.cls}">
      <span class="node-icon">${st.icon}</span>
      <div class="node-main">
        <div class="node-name">${name} ${active}</div>
        <div class="node-meta">role <code>${role}</code> · last heartbeat ${esc(hb)} (${esc(age)})</div>
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

loadStatsBot();
loadStatsNodes();
