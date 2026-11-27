/**
 * Fleet totals band on /stats.
 *
 * The Stats page is public, so this reads the public `/api/stats` payload (the
 * same one the login screen uses) and shows the FLEET server/member totals plus
 * the per-node breakdown behind them. Under active-active sharding each node
 * only serves its own shards, so a per-node number is a fraction of the bot —
 * the sum is what users must see.
 *
 * Uses a local fetch (not common.js `api()`) so an anonymous visitor is never
 * bounced to /login by the shared 401 handler.
 */
(function () {
    'use strict';

    const REFRESH_MS = 60_000;

    function el(id) { return document.getElementById(id); }

    function fmt(n) {
        return typeof n === 'number' && Number.isFinite(n) ? n.toLocaleString() : '—';
    }

    function ageLabel(ms) {
        if (typeof ms !== 'number' || !Number.isFinite(ms)) return '—';
        const s = Math.max(0, Math.round(ms / 1000));
        if (s < 60) return `${s}s ago`;
        const m = Math.round(s / 60);
        if (m < 60) return `${m}m ago`;
        return `${Math.round(m / 60)}h ago`;
    }

    const SOURCE_LABEL = {
        rest: 'Direct from Discord',
        bot: 'Reported by the bot nodes',
        db: 'Configured servers only',
    };

    function renderNodes(nodes) {
        const wrap = el('fleet-nodes-wrap');
        const body = el('fleet-nodes-body');
        if (!wrap || !body) return;
        if (!Array.isArray(nodes) || nodes.length === 0) {
            wrap.hidden = true;
            body.textContent = '';
            return;
        }
        body.textContent = '';
        for (const node of nodes) {
            const tr = document.createElement('tr');
            const cells = [
                node.role || '—',
                fmt(node.guildCount),
                fmt(node.memberCount),
                node.active === false ? 'not serving' : ageLabel(node.ageMs),
            ];
            for (const value of cells) {
                const td = document.createElement('td');
                td.textContent = String(value);
                tr.appendChild(td);
            }
            if (node.active === false) tr.classList.add('fleet-row-idle');
            body.appendChild(tr);
        }
        wrap.hidden = false;
    }

    function render(stats) {
        const servers = el('fleet-servers');
        const members = el('fleet-members');
        const nodes = el('fleet-nodes');
        const sub = el('fleet-sub');
        const serversLabel = el('fleet-servers-label');
        const membersLabel = el('fleet-members-label');
        if (!servers) return;

        const liveNodes = Array.isArray(stats.liveNodes) ? stats.liveNodes : [];
        const serving = liveNodes.filter((n) => n.active !== false);

        servers.textContent = fmt(stats.servers);
        members.textContent = fmt(stats.totalUsers);
        nodes.textContent = String(serving.length || (stats.serversSource === 'rest' ? '—' : 0));

        if (serversLabel) {
            serversLabel.textContent = stats.serversSource === 'db' ? 'Servers configured' : 'Servers';
        }
        if (membersLabel) {
            membersLabel.textContent = stats.totalUsers == null ? 'Members unavailable' : 'Members';
        }
        if (sub) {
            sub.textContent = SOURCE_LABEL[stats.serversSource] || 'Live totals';
        }
        renderNodes(liveNodes);
    }

    function renderError() {
        const sub = el('fleet-sub');
        if (sub) sub.textContent = 'Fleet totals unavailable right now';
    }

    async function load() {
        try {
            const res = await fetch('/api/stats', { headers: { Accept: 'application/json' }, cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            render(await res.json());
        } catch (_) {
            renderError();
        }
    }

    function start() {
        load();
        // Refresh only while the tab is visible: the fleet numbers move slowly
        // and a hidden tab should not keep a serverless function warm.
        setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
        document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
