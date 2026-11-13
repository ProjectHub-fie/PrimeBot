/* Infrastructure Status board — rendered into the Stats page.
 * Loads /api/status/detailed (auth) and paints the overall banner, the per
 * component cards with exactly-30-day uptime bars, the shard infrastructure
 * summary, and the incidents list. Clicking a component loads its detail view
 * (full bars + incidents + node heartbeat timeline).
 *
 * The render deliberately happens client-side so the page skeleton paints
 * immediately and monitoring data loads asynchronously (no heavy queries on
 * page load).
 */
(() => {
    const $ = (sel, root) => (root || document).querySelector(sel);
    const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    // Local JSON fetch — the Stats page is public, so it must NOT use the
    // global api() helper (whose 401 handler bounces visitors to /login). The
    // status endpoints are read-only and public; a failure just renders the
    // error state.
    async function fetchStatus(path) {
        const res = await fetch(path, { headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        return res.json();
    }

    const STATUS_META = {
        operational: { label: 'Operational', cls: 'ok' },
        degraded: { label: 'Degraded', cls: 'degraded' },
        stale: { label: 'Checking…', cls: 'stale' },
        unavailable: { label: 'Outage', cls: 'down' },
        unknown: { label: 'No data', cls: 'no-data' },
        maintenance: { label: 'Maintenance', cls: 'maint' },
    };

    // Node role / gateway / health badges (kept orthogonal to the status pill).
    const ROLE_META = {
        active: { label: 'ACTIVE', cls: 'active' },
        standby: { label: 'STANDBY', cls: 'standby' },
    };
    const GATEWAY_META = {
        connected: { label: 'Gateway connected', cls: 'ok' },
        disconnected: { label: 'Gateway disconnected', cls: 'down' },
        not_assigned: { label: 'Gateway not assigned', cls: 'muted' },
    };
    // A node's card uses a BLUE (standby) accent when it is a healthy standby,
    // never the red "down" accent — a standby with no shards is not a fault.
    function nodeAccent(c) {
        if (c.health === 'offline' || c.status === 'unavailable') return 'down';
        if (c.health === 'unknown' || c.status === 'unknown') return 'no-data';
        if (c.health === 'stale' || c.status === 'stale') return 'stale';
        if (c.status === 'degraded') return 'degraded';
        return c.role === 'standby' ? 'standby' : 'ok';
    }

    function fmtDuration(ms) {
        if (ms == null) return '—';
        const s = Math.round(ms / 1000);
        if (s < 60) return `${s}s`;
        const m = Math.floor(s / 60);
        if (m < 60) return `${m}m ${s % 60}s`;
        const h = Math.floor(m / 60);
        if (h < 24) return `${h}h ${m % 60}m`;
        return `${Math.floor(h / 24)}d ${h % 24}h`;
    }

    function fmtPct(pct) {
        if (pct == null || !Number.isFinite(pct)) return '—';
        return pct >= 99.995 ? '100%' : `${pct.toFixed(2)}%`;
    }

    const lastCheckLabel = (d) => {
        if (!d) return '—';
        const t = new Date(d);
        if (Number.isNaN(t.getTime())) return '—';
        return t.toLocaleString();
    };

    // Map a day bucket to a visual state.
    function barState(day) {
        if (!day.hasData) return 'no-data';
        if (day.maintenanceMs > 0) return 'maint';
        if (day.uptime == null) return 'no-data';
        if (day.uptime >= 99.99) return 'ok';
        if (day.uptime >= 95) return 'degraded';
        if (day.uptime >= 80) return 'partial';
        return 'down';
    }

    function barTitle(day, componentLabel, incidentCount) {
        const date = new Date(day.day + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
        const lines = [
            `${componentLabel}`,
            date,
            `Uptime: ${fmtPct(day.uptime)}`,
            `Downtime: ${fmtDuration(day.downtimeMs)}`,
            `Degraded: ${fmtDuration(day.degradedMs)}`,
            `Incidents: ${incidentCount || 0}`,
        ];
        if (day.maintenanceMs > 0) lines.push('Scheduled maintenance');
        return lines.join('\n');
    }

    // 30-day bar strip (compact sparkline + tooltip).
    function barStrip(series, componentLabel, incidentsByDay) {
        return series.map(day => {
            const st = barState(day);
            const inc = incidentsByDay && (incidentsByDay[day.day] || []).length || 0;
            return `<div class="uptime-bar bar-${st}" role="img"
              aria-label="${barTitle(day, componentLabel, inc).replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"
              data-tip="${barTitle(day, componentLabel, inc).replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"></div>`;
        }).join('');
    }

    function incidentsByDayMap(incidents) {
        const map = {};
        for (const inc of incidents || []) {
            const day = String(inc.startedAt || '').slice(0, 10);
            if (!day) continue;
            (map[day] = map[day] || []).push(inc);
        }
        return map;
    }

    function componentCard(c, incByDay) {
        const isNode = c.key === 'sn1' || c.key === 'sn2' || c.key === 'sn3';
        const accent = isNode ? nodeAccent(c) : (STATUS_META[c.status] || STATUS_META.unknown).cls;
        const meta = isNode
            ? { label: nodeStatusLabel(c), cls: accent }
            : (STATUS_META[c.status] || STATUS_META.unknown);
        const label = c.label || c.key;
        const stri = c.series ? barStrip(c.series, label, incByDay) : '';

        // Node-specific badges: role + gateway.
        let nodeBadges = '';
        if (isNode) {
            const role = ROLE_META[c.role] || null;
            const gw = GATEWAY_META[c.gateway] || null;
            nodeBadges = `
              <div class="status-card-badges">
                ${role ? `<span class="badge badge-role badge-${role.cls}">${role.label}</span>` : ''}
                ${gw ? `<span class="badge badge-gw badge-${gw.cls}">${gw.label}</span>` : ''}
              </div>`;
        }

        // Node footer details: shards + last heartbeat.
        let foot = '';
        if (isNode) {
            const shards = c.shardsTotal > 0
                ? `${c.shardsReady}/${c.shardsTotal} shards`
                : 'No shards assigned';
            foot = `
              <div class="status-card-foot">
                <span class="status-foot-chip">${shards}</span>
                <span class="status-foot-last">Heartbeat ${lastCheckLabel(c.lastObservedAt)}</span>
              </div>`;
        } else {
            const chip = (label === 'Main Website' || label === 'Dashboard / API') ? 'HTTP' : '';
            foot = `
              <div class="status-card-foot">
                ${chip ? `<span class="status-foot-chip">${chip}</span>` : ''}
                <span class="status-foot-last">Last check ${lastCheckLabel(c.lastObservedAt)}</span>
              </div>`;
        }

        return `
        <button type="button" class="status-card status-card-${accent}" data-component="${c.key}" aria-label="View ${label} history">
          <div class="status-card-top">
            <span class="status-dot dot-${meta.cls}"></span>
            <span class="status-card-name">${label}</span>
            <span class="status-pill pill-${meta.cls}">${meta.label}</span>
          </div>
          ${nodeBadges}
          <div class="status-card-uptime">
            <span class="status-uptime-big">${uptimeText(c)}</span>
            <span class="status-uptime-cap">${uptimeCap(c)}</span>
          </div>
          <div class="uptime-strip" title="">
            ${stri}
          </div>
          ${foot}
        </button>`;
    }

    // A node that is online and healthy reads "Online"/"Standby online" rather
    // than a bare "Operational" — and never "Outage" just for having no shards.
    function nodeStatusLabel(c) {
        if (c.health === 'offline' || c.status === 'unavailable') return 'Offline';
        if (c.health === 'unknown' || c.status === 'unknown') return 'No data';
        if (c.health === 'stale' || c.status === 'stale') return 'Checking…';
        if (c.status === 'degraded') return 'Degraded';
        return c.role === 'standby' ? 'Online (standby)' : 'Online (active)';
    }

    // NO DATA must never read "100%". Show a dash + honest caption instead.
    function uptimeText(c) {
        if (!c.uptime30 || c.uptime30.pct == null) return '—';
        return fmtPct(c.uptime30.pct);
    }

    function uptimeCap(c) {
        if (!c.uptime30 || c.uptime30.pct == null) return 'No monitoring data';
        const days = c.uptime30.daysWithData;
        if (c.uptime30.partial) return `${days}/${c.uptime30.windowDays} days monitored`;
        return '30-day uptime';
    }

    function shardInfra(components, summary) {
        const nodes = ['sn1', 'sn2', 'sn3'].map(k => components[k]).filter(Boolean);
        const infra = summary.infra || {};
        const total = infra.total || nodes.length || 3;
        const online = infra.online != null ? infra.online : nodes.filter(n => n.health === 'online').length;
        const active = infra.active != null ? infra.active : nodes.filter(n => n.role === 'active').length;
        const standby = infra.standby != null ? infra.standby : nodes.filter(n => n.role === 'standby').length;
        const offline = infra.offline != null ? infra.offline : nodes.filter(n => n.health === 'offline').length;
        const unhealthy = infra.unhealthy != null ? infra.unhealthy : 0;

        const combinedPct = infra.combinedPct != null ? infra.combinedPct : null;
        const mostReliable = infra.mostReliable ? (components[infra.mostReliable] || {}).label : '—';
        const mostDown = infra.mostDown ? (components[infra.mostDown] || {}).label : '—';
        const botComp = components.bot;

        const pctText = combinedPct == null ? '—' : fmtPct(combinedPct);
        return `
        <div class="card status-infra">
          <div class="card-title"><span><span class="icon">${window.svgIcon ? window.svgIcon('activity') : ''}</span> Shard infrastructure</span></div>
          <div class="infra-grid">
            <div class="infra-stat"><span class="infra-num infra-ok">${online}/${total}</span><span class="infra-cap">Online nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${active}/${total}</span><span class="infra-cap">Active nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${standby}/${total}</span><span class="infra-cap">Standby nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${offline}/${total}</span><span class="infra-cap">Offline nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${unhealthy}/${total}</span><span class="infra-cap">Unhealthy nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${pctText}</span><span class="infra-cap">Combined shard availability</span></div>
            <div class="infra-stat"><span class="infra-num">${mostReliable}</span><span class="infra-cap">Most reliable node</span></div>
            <div class="infra-stat"><span class="infra-num">${mostDown}</span><span class="infra-cap">Highest downtime node</span></div>
          </div>
          <div class="infra-service">
            <span>PrimeBot service availability (30d):</span>
            <strong>${uptimeText(botComp || {})}</strong>
          </div>
        </div>`;
    }

    function incidentsHTML(active, resolved) {
        const rows = (inc, cls) => `
        <div class="incident-row ${cls}">
          <span class="incident-sev sev-${inc.severity}">${inc.severity}</span>
          <span class="incident-title">${esc(inc.title)}</span>
          <span class="incident-comp">${esc(inc.component)}</span>
          <span class="incident-status st-${inc.status}">${inc.status}</span>
          <time class="incident-time">${lastCheckLabel(inc.startedAt)}</time>
        </div>`;
        const activeHtml = (active && active.length)
            ? active.map(i => rows(i, 'incident-active')).join('')
            : '<div class="incident-empty">No active incidents 🎉</div>';
        const resolvedHtml = (resolved && resolved.length)
            ? resolved.slice(0, 8).map(i => rows(i, 'incident-resolved')).join('')
            : '<div class="incident-empty">No resolved incidents in the window.</div>';
        return `
        <div class="card status-incidents">
          <div class="card-title"><span><span class="icon"></span> Incidents</span></div>
          <h3 class="incident-subhead">Active incidents</h3>
          <div class="incident-list">${activeHtml}</div>
          <h3 class="incident-subhead">Resolved incidents</h3>
          <div class="incident-list">${resolvedHtml}</div>
        </div>`;
    }

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }

    function overallBanner(summary) {
        const key = summary.overall ? summary.overall.key : 'no_data';
        const label = summary.overall ? summary.overall.label : 'Monitoring Data Unavailable';
        const clsMap = {
            operational: 'ok',
            degraded: 'degraded',
            major: 'down',
            critical: 'critical',
            no_data: 'no-data',
            maintenance: 'maint',
        };
        const cls = clsMap[key] || 'no-data';
        return `
        <div class="status-overall overall-${cls}">
          <div class="overall-left">
            <span class="overall-orb"></span>
            <div>
              <div class="overall-title">${esc(label)}</div>
              <div class="overall-sub">${summary.openIncidents ? `${summary.openIncidents} active incident(s)` : 'No open incidents'}</div>
            </div>
          </div>
          <div class="overall-right">
            <span class="overall-check">Last monitoring update</span>
            <strong>${lastCheckLabel(summary.lastCheckedAt)}</strong>
          </div>
        </div>`;
    }

    // ── Detail view ────────────────────────────────────────────────────────────

    const COLUMNS = ['bot', 'website', 'api', 'db', 'gateway', 'sn1', 'sn2', 'sn3'];

    async function openDetail(component, label) {
        const modal = $('#status-detail-modal');
        if (!modal) return;
        modal.classList.remove('hidden');
        $('#status-detail-body').innerHTML = '<div class="splash"><div class="spinner"></div><p>Loading history…</p></div>';
        try {
            const data = await fetchStatus(`/api/status/history?component=${encodeURIComponent(component)}&days=30`);
            renderDetailBody(component, label, data);
        } catch (err) {
            $('#status-detail-body').innerHTML = `<div class="status-error">Could not load history for ${esc(label)}.</div>`;
        }
    }

    function renderDetailBody(component, label, data) {
        const hero = `
        <div class="detail-hero">
          <h2>${esc(data.component.label || label)}</h2>
          <p>${esc(data.component.description || '')}</p>
        </div>`;
        const bars = data.series.map(day => {
            const st = barState(day);
            return `<div class="uptime-bar-bar bar-${st}" data-day="${day.day}" data-uptime="${fmtPct(day.uptime)}" data-down="${fmtDuration(day.downtimeMs)}" data-deg="${fmtDuration(day.degradedMs)}"></div>`;
        }).join('');

        let timelines = '';
        if (data.pulseTimeline && data.pulseTimeline.length) {
            timelines = `
            <div class="detail-section">
              <h3>Heartbeat timeline</h3>
              <div class="pulse-list">
                ${data.pulseTimeline.slice(0, 100).map(p => `
                  <div class="pulse-row">
                    <span class="pulse-node">${esc(p.nodeName)}</span>
                    <span class="pulse-state ${p.gatewayReady ? 'ok' : (p.gatewayConnected ? 'degraded' : 'no-data')}">${p.gatewayReady ? 'gateway ready' : (p.gatewayConnected ? 'connecting' : 'not connected')}</span>
                    <span class="pulse-shards">${p.shardsReady}/${p.shardsTotal} shards${(p.shardIds && p.shardIds.length) ? ' [' + p.shardIds.join(', ') + ']' : ''}</span>
                    <span class="pulse-time">${lastCheckLabel(p.ts)}</span>
                  </div>`).join('')}
              </div>
            </div>`;
        }

        let restartsHTML = '';
        if (data.restarts && data.restarts.length) {
            restartsHTML = `
            <div class="detail-section">
              <h3>Restart history</h3>
              <div class="pulse-list">
                ${data.restarts.slice(0, 20).map(r => `
                  <div class="pulse-row">
                    <span class="pulse-node">${esc(r.nodeName)}</span>
                    <span class="pulse-state">restart</span>
                    <span class="pulse-shards">pid ${r.pid || '—'}</span>
                    <span class="pulse-time">${lastCheckLabel(r.restartedAt)}</span>
                  </div>`).join('')}
              </div>
            </div>`;
        }

        const incList = (data.incidents && data.incidents.length)
            ? data.incidents.slice(0, 20).map(i => `
              <div class="incident-row">
                <span class="incident-sev sev-${esc(i.severity)}">${esc(i.severity)}</span>
                <span class="incident-title">${esc(i.title)}</span>
                <span class="incident-status st-${esc(i.status)}">${esc(i.status)}</span>
                <span class="incident-time">${lastCheckLabel(i.startedAt)} → ${lastCheckLabel(i.resolvedAt)}</span>
              </div>`).join('')
            : '<div class="incident-empty">No incidents for this component.</div>';

        $('#status-detail-body').innerHTML = `
        ${hero}
        <div class="detail-section">
          <div class="detail-series-head">
            <span>Last 30 days</span>
            <span class="detail-legend">
              <i class="lg lg-ok"></i> ok <i class="lg lg-degraded"></i> degraded
              <i class="lg lg-partial"></i> outage <i class="lg lg-maint"></i> maintenance
            </span>
          </div>
          <div class="detail-bars" id="detail-bars">${bars}</div>
        </div>
        ${timelines}
        ${restartsHTML}
        <div class="detail-section">
          <h3>Related incidents</h3>
          <div class="incident-list">${incList}</div>
        </div>`;

        // Tooltip plumbing.
        const barsWrap = $('#detail-bars');
        const tooltip = $('#status-tooltip');
        if (barsWrap) {
            $$('.uptime-bar-bar', barsWrap).forEach(b => {
                b.addEventListener('mouseenter', (e) => {
                    if (!tooltip) return;
                    tooltip.innerHTML = `<strong>${esc(label)} — ${b.dataset.day}</strong><br>Uptime: ${b.dataset.uptime}<br>Downtime: ${b.dataset.down}<br>Degraded: ${b.dataset.deg}`;
                    tooltip.classList.remove('hidden');
                });
                b.addEventListener('mousemove', (e) => {
                    if (!tooltip) return;
                    const r = b.getBoundingClientRect();
                    tooltip.style.left = `${e.clientX + 12}px`;
                    tooltip.style.top = `${e.clientY + 8}px`;
                });
                b.addEventListener('mouseleave', () => tooltip && tooltip.classList.add('hidden'));
            });
        }
    }

    function closeDetail() {
        const modal = $('#status-detail-modal');
        if (modal) modal.classList.add('hidden');
    }

    function bindMouseStrips() {
        const tooltip = $('#status-tooltip');
        if (!tooltip) return;
        document.addEventListener('mousemove', (e) => {
            const bar = e.target.closest ? e.target.closest('.uptime-bar[data-tip]') : null;
            if (bar) {
                tooltip.innerHTML = bar.dataset.tip.replace(/\n/g, '<br>');
                tooltip.classList.remove('hidden');
                tooltip.style.left = `${e.clientX + 12}px`;
                tooltip.style.top = `${e.clientY + 8}px`;
            } else if (!e.target.closest || !e.target.closest('#status-detail-modal') || !e.target.closest('.uptime-bar-bar')) {
                tooltip.classList.add('hidden');
            }
        });
    }

    // ── Bootstrap ──────────────────────────────────────────────────────────────

    // Skeleton markup mirroring the real board, kept in sync with the
    // server-rendered shell in render/pages.js (used for the detail modal's
    // own loading state).
    const SKELETON = `
      <div class="sk-banner sk-shimmer"></div>
      <div class="sk-infra">${'<div class="sk-stat sk-shimmer"></div>'.repeat(6)}</div>
      <div class="sk-grid">${'<div class="sk-card sk-shimmer"></div>'.repeat(8)}</div>
      <div class="sk-lines">${'<div class="sk-line sk-shimmer"></div>'.repeat(3)}</div>`;

    async function init() {
        const root = $('#stats-status');
        if (!root) return;

        // Build the static shell + shared tooltip/modal once. The skeleton the
        // server rendered stays in place until the data arrives, so the board
        // never flashes empty.
        root.innerHTML = `
        <div id="status-result">
          <div class="status-skeleton" role="status" aria-label="Loading infrastructure status">${SKELETON}</div>
        </div>
        <div id="status-detail-modal" class="modal-overlay hidden">
          <div class="modal-floating-window status-detail">
            <div class="status-detail-close" id="status-detail-close" title="Close (Esc)">×</div>
            <div id="status-detail-body"></div>
          </div>
        </div>
        <div id="status-tooltip" class="status-tooltip hidden"></div>`;

        $('#status-detail-close').addEventListener('click', closeDetail);
        $('#status-detail-modal').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) closeDetail();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeDetail();
        });
        bindMouseStrips();

        try {
            const summary = await fetchStatus('/api/status/detailed');
            render(summary);
            window.__statusSummary = summary;
        } catch (err) {
            root.innerHTML = `<div class="status-error">Monitoring data is unavailable right now. It will appear after the monitor starts collecting observations.</div>`;
        } finally {
            root.setAttribute('aria-busy', 'false');
        }
    }

    function render(summary) {
        const comps = {};
        for (const c of summary.components || []) comps[c.key] = c;

        // Per-component per-day incident maps for the strip tooltips.
        const incByComponent = {};
        for (const inc of summary.activeIncidents || []) {
            (incByComponent[inc.component] = incByComponent[inc.component] || []).push(inc);
        }
        for (const inc of summary.resolvedIncidents || []) {
            (incByComponent[inc.component] = incByComponent[inc.component] || []).push(inc);
        }
        const byComponentDay = {};
        for (const [comp, list] of Object.entries(incByComponent)) {
            byComponentDay[comp] = incidentsByDayMap(list);
        }

        const grid = COLUMNS.map(k => comps[k]).filter(Boolean).map(c => componentCard(c, byComponentDay[c.key])).join('');

        const adminControls = summary.isAdmin
            ? `<div class="status-admin">
                 <span class="status-admin-hint">You have admin access. Incidents resolve automatically on recovery; use the API to manage maintenance windows.</span>
               </div>`
            : '';

        $('#status-result').innerHTML = `
        ${overallBanner(summary)}
        ${shardInfra(comps, summary)}
        ${adminControls}
        <div class="card status-components">
          <div class="card-title"><span><span class="icon"></span> Components</span>
            <span class="status-update-hint">Updates every ${Math.round((summary.measurement && summary.measurement.intervalMs || 60000) / 1000)}s</span>
          </div>
          <div class="status-grid">${grid || '<div class="status-error">No components.</div>'}</div>
        </div>
        ${incidentsHTML(summary.activeIncidents, summary.resolvedIncidents)}
        `;

        // Detail links.
        $$('.status-card', $('#status-result')).forEach(card => {
            card.addEventListener('click', () => openDetail(card.dataset.component, card.querySelector('.status-card-name').textContent));
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();