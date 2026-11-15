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
        unavailable: { label: 'Outage', cls: 'down' },
        unknown: { label: 'No data', cls: 'no-data' },
        maintenance: { label: 'Maintenance', cls: 'maint' },
    };

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

    // Map a day bucket to a visual state. The 30-day strip ALWAYS renders one
    // bar per position, including NO DATA days (grey) — it must never collapse
    // to a single bar because only one day has data.
    function barState(day) {
        if (!day || !day.hasData) return 'no-data';
        if (day.maintenanceMs > 0) return 'maint';
        if (day.uptime == null) return 'no-data';
        // An incomplete day (partial monitoring coverage) is visually distinct
        // from a fully monitored healthy day, even when it was 100% up.
        if (day.uptime >= 99.99) return day.dataStatus === 'partial' ? 'partial' : 'ok';
        if (day.uptime >= 95) return 'degraded';
        if (day.uptime >= 80) return 'partial';
        return 'down';
    }

    function barTitle(day, componentLabel, incidentCount) {
        const date = new Date(day.day + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
        const lines = [componentLabel, date];
        if (!day.hasData) {
            lines.push('No monitoring data');
            return lines.join('\n');
        }
        lines.push(`Uptime: ${fmtPct(day.uptime)}`);
        lines.push(`Downtime: ${fmtDuration(day.downtimeMs)}`);
        lines.push(`Degraded: ${fmtDuration(day.degradedMs)}`);
        if (day.coverage != null) lines.push(`Coverage: ${Math.round(day.coverage * 100)}%`);
        lines.push(`Incidents: ${incidentCount || 0}`);
        if (day.maintenanceMs > 0) lines.push('Scheduled maintenance');
        return lines.join('\n');
    }

    // 30-day bar strip (compact sparkline + tooltip). Renders EVERY position.
    function barStrip(series, componentLabel, incidentsByDay) {
        const days = Array.isArray(series) ? series : [];
        return days.map(day => {
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
        const meta = STATUS_META[c.status] || STATUS_META.unknown;
        const label = c.label || c.key;
        const isNode = c.key === 'sn1' || c.key === 'sn2' || c.key === 'sn3';
        const stri = c.series ? barStrip(c.series, label, incByDay) : '';
        // Independent node chips: role (active/standby), gateway, shards.
        let nodeChips = '';
        if (isNode && c.node) {
            const n = c.node;
            const roleChip = n.isActive ? 'Active' : 'Standby';
            const gwChip = n.gateway && n.gateway.ready ? 'Gateway ready'
                : (n.gateway && n.gateway.connected ? 'Gateway connecting' : 'No gateway');
            const shardChip = n.shards && n.shards.assigned > 0
                ? `${n.shards.ready}/${n.shards.assigned} shards`
                : 'No shards assigned';
            nodeChips = `<span class="status-foot-chip node-role ${n.isActive ? 'role-active' : 'role-standby'}">${roleChip}</span>`
                + `<span class="status-foot-chip">${gwChip}</span>`
                + `<span class="status-foot-chip">${shardChip}</span>`;
        }
        const uptimeCap = c.uptime30
            ? '30-day uptime'
            : 'no monitored history';
        return `
        <button type="button" class="status-card" data-component="${c.key}" aria-label="View ${label} history">
          <div class="status-card-top">
            <span class="status-dot dot-${meta.cls}"></span>
            <span class="status-card-name">${label}</span>
            <span class="status-pill pill-${meta.cls}">${meta.label}</span>
          </div>
          <div class="status-card-uptime">
            <span class="status-uptime-big">${fmtPct(c.uptime30 && c.uptime30.pct)}</span>
            <span class="status-uptime-cap">${uptimeCap}</span>
          </div>
          <div class="uptime-strip" title="">
            ${stri}
          </div>
          <div class="status-card-foot">
            ${nodeChips || (isNode ? `<span class="status-foot-chip">Node</span>` : (label === 'Main Website' || label === 'Dashboard / API') ? `<span class="status-foot-chip">HTTP</span>` : '')}
            <span class="status-foot-last">Last check ${lastCheckLabel(c.lastObservedAt)}</span>
          </div>
        </button>`;
    }

    function shardInfra(components, summary) {
        const nodes = ['sn1', 'sn2', 'sn3'].map(k => components[k]).filter(Boolean);
        // Prefer the fleet summary computed by the backend (independent signals).
        const fleet = summary.fleet || null;
        const online = fleet ? fleet.online : nodes.filter(n => n.status === 'operational' || n.status === 'degraded').length;
        const healthy = fleet ? fleet.healthy : nodes.filter(n => n.status === 'operational').length;
        const active = fleet ? fleet.active : nodes.filter(n => n.node && n.node.isActive).length;
        const standby = fleet ? fleet.standby : nodes.filter(n => n.node && !n.node.isActive && n.online).length;
        const offline = fleet ? fleet.offline : nodes.filter(n => n.status === 'unavailable').length;

        let combinedMonitored = 0, combinedDown = 0, combinedDeg = 0;
        for (const n of nodes) {
            if (n.uptime30) {
                combinedMonitored += n.uptime30.monitoredMs;
                combinedDown += n.uptime30.downtimeMs;
                combinedDeg += n.uptime30.degradedMs;
            }
        }
        const combinedPct = combinedMonitored > 0 ? ((combinedMonitored - combinedDown) / combinedMonitored) * 100 : null;

        let mostReliable = null, mostDown = null;
        for (const n of nodes) {
            if (!n.uptime30) continue;
            if (!mostReliable || (n.uptime30.pct || 0) > (mostReliable.uptime30.pct || 0)) mostReliable = n;
            if (!mostDown || (n.uptime30.downtimeMs || 0) > (mostDown.uptime30.downtimeMs || 0)) mostDown = n;
        }

        const botComp = components.bot;
        return `
        <div class="card status-infra">
          <div class="card-title"><span><span class="icon">${window.svgIcon ? window.svgIcon('activity') : ''}</span> Shard infrastructure</span></div>
          <div class="infra-grid">
            <div class="infra-stat"><span class="infra-num">${online}/3</span><span class="infra-cap">Nodes online</span></div>
            <div class="infra-stat"><span class="infra-num">${healthy}/3</span><span class="infra-cap">Healthy nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${active}/3</span><span class="infra-cap">Active node(s)</span></div>
            <div class="infra-stat"><span class="infra-num">${standby}/3</span><span class="infra-cap">Standby node(s)</span></div>
            <div class="infra-stat"><span class="infra-num">${offline}/3</span><span class="infra-cap">Offline nodes</span></div>
            <div class="infra-stat"><span class="infra-num">${fmtPct(combinedPct)}</span><span class="infra-cap">Combined shard availability</span></div>
            <div class="infra-stat"><span class="infra-num">${summary.openIncidents || 0}</span><span class="infra-cap">Open incidents</span></div>
            <div class="infra-stat"><span class="infra-num">${fmtDuration(combinedDown)}</span><span class="infra-cap">Total shard downtime (30d)</span></div>
            <div class="infra-stat"><span class="infra-num">${mostReliable ? mostReliable.label : '—'}</span><span class="infra-cap">Most reliable node</span></div>
          </div>
          <div class="infra-service">
            <span>PrimeBot service availability (30d):</span>
            <strong>${fmtPct(botComp && botComp.uptime30 && botComp.uptime30.pct)}</strong>
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
        // Detail bars: ALWAYS render every position in the series (30), each
        // with a date + its own state, so a day with no data is still a visible
        // grey bar rather than a missing element.
        const series = Array.isArray(data.series) ? data.series : [];
        const bars = series.map(day => {
            const st = barState(day);
            return `<div class="uptime-bar-bar bar-${st}" data-day="${day.day}"
              data-tip="${barTitle(day, data.component.label || label, 0).replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"
              aria-label="${esc(day.day)} ${fmtPct(day.uptime)}"></div>`;
        }).join('');

        let timelines = '';
        if (data.pulseTimeline && data.pulseTimeline.length) {
            timelines = `
            <div class="detail-section">
              <h3>Heartbeat timeline</h3>
              <div class="pulse-list">
                ${data.pulseTimeline.slice(0, 100).map(p => `
                  <div class="pulse-row">
                    <span class="pulse-node">${esc(p.nodeId || p.nodeName)}</span>
                    <span class="pulse-state ${p.gatewayReady ? 'ok' : (p.gatewayConnected ? 'degraded' : 'no-data')}">${p.gatewayReady ? 'gateway ready' : (p.gatewayConnected ? 'connecting' : 'not connected')}</span>
                    <span class="pulse-shards">${p.shardsReady}/${p.shardsTotal} shards</span>
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
              <i class="lg lg-ok"></i> healthy <i class="lg lg-degraded"></i> degraded
              <i class="lg lg-partial"></i> partial/outage <i class="lg lg-down"></i> down
              <i class="lg lg-maint"></i> maintenance <i class="lg lg-no-data"></i> no data
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
                b.addEventListener('mouseenter', () => {
                    if (!tooltip) return;
                    tooltip.innerHTML = (b.dataset.tip || '').replace(/\n/g, '<br>');
                    tooltip.classList.remove('hidden');
                });
                b.addEventListener('mousemove', (e) => {
                    if (!tooltip) return;
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