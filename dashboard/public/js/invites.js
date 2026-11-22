/* Invite Tracking dashboard page.
 *
 * The page is server-rendered; this script refreshes the overview, paginates
 * the leaderboard, saves configuration through the floating Save bar, resets
 * statistics behind an explicit confirmation, and opens a per-inviter detail
 * modal. IIFE-wrapped so it can never collide with another page script's
 * top-level bindings (classic scripts share one global scope).
 */
(function () {
    'use strict';

    const page = document.getElementById('iv-page');
    if (!page) return;
    const GUILD_ID = page.dataset.guildId;
    if (!GUILD_ID) return;

    let state = { page: 1, totalPages: 1, data: null };

    const $ = (sel) => document.querySelector(sel);
    const fmtWhen = (iso) => {
        if (!iso) return '—';
        const ms = new Date(iso).getTime();
        if (!Number.isFinite(ms)) return '—';
        return `<t:${Math.floor(ms / 1000)}:R>`;
    };
    const escHtml = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const icon = (name) => (window.svgIcon ? window.svgIcon(name) : '');

    function attributionBadge(j) {
        if (j.attribution === 'exact') return '<span class="iv-badge iv-badge-good">Attributed</span>';
        if (j.attribution === 'ambiguous') return '<span class="iv-badge iv-badge-warn">Ambiguous</span>';
        if (j.source === 'vanity') return '<span class="iv-badge iv-badge-info">Vanity (probable)</span>';
        if (j.source === 'bot') return '<span class="iv-badge">Bot</span>';
        return '<span class="iv-badge iv-badge-muted">Unknown</span>';
    }

    function inviterCell(j) {
        if (j.inviterId) return `<a href="#" class="iv-member" data-invite-member="${escHtml(j.inviterId)}">&lt;@${escHtml(j.inviterId)}&gt;</a>`;
        return '<span class="iv-muted">Unknown</span>';
    }

    function renderStats(totals) {
        const set = (key, value) => {
            const el = document.querySelector(`[data-iv="${key}"]`);
            if (el) el.textContent = String(value == null ? 0 : value);
        };
        set('totalJoins', totals.totalJoins);
        set('totalLeaves', totals.totalLeaves);
        set('net', totals.net);
        set('joins24h', totals.joins24h);
        set('uniqueInviters', totals.uniqueInviters);
        set('unknownJoins', totals.unknownJoins);
    }

    function renderLeaderboard(rows) {
        const body = document.querySelector('#iv-leaderboard tbody');
        if (!body) return;
        if (!rows || !rows.length) {
            body.innerHTML = `<tr><td colspan="6" class="iv-empty">${icon('users')} No invites tracked yet. Invite someone and their join appears here.</td></tr>`;
            return;
        }
        const max = Math.max(...rows.map(r => Math.max(r.net, 0)), 1);
        body.innerHTML = rows.map((r, i) => {
            const place = (state.page - 1) * 10 + i + 1;
            const pct = Math.max(2, Math.round((Math.max(r.net, 0) / max) * 100));
            return `<tr>
              <td class="iv-rank">${place}</td>
              <td><a href="#" class="iv-member" data-invite-member="${escHtml(r.userId)}">&lt;@${escHtml(r.userId)}&gt;</a></td>
              <td class="iv-num">${r.joins}</td>
              <td class="iv-num">${r.leaves}</td>
              <td class="iv-num iv-net">${r.net}<div class="iv-bar"><div class="iv-bar-fill" style="width:${pct}%"></div></div></td>
              <td class="iv-num">${r.activeInvites || 0}</td>
            </tr>`;
        }).join('');
        bindMemberLinks();
    }

    function renderJoins(joins) {
        const body = document.querySelector('#iv-joins tbody');
        if (!body) return;
        if (!joins || !joins.length) {
            body.innerHTML = `<tr><td colspan="4" class="iv-empty">${icon('userPlus')} No joins recorded yet.</td></tr>`;
            return;
        }
        body.innerHTML = joins.map(j => `<tr>
          <td><span class="iv-member-static">&lt;@${escHtml(j.userId)}&gt;</span></td>
          <td>${inviterCell(j)}</td>
          <td>${attributionBadge(j)}${j.inviteCode ? ` <code class="iv-code">${escHtml(j.inviteCode)}</code>` : ''}</td>
          <td class="iv-when">${fmtWhen(j.joinedAt)}</td>
        </tr>`).join('');
        bindMemberLinks();
    }

    function renderActivity(activity) {
        const list = document.getElementById('iv-activity');
        if (!list) return;
        if (!activity || !activity.length) {
            list.innerHTML = `<li class="iv-activity-empty">${icon('activity')} No activity yet.</li>`;
            return;
        }
        const iconFor = (type) => type === 'join' ? 'userPlus' : type === 'leave' ? 'userX'
            : type === 'reset' ? 'trash' : type === 'config' ? 'settings' : 'link';
        list.innerHTML = activity.slice(0, 20).map(a => `
          <li class="iv-activity-row">
            <span class="iv-activity-ico iv-activity-${escHtml(a.type)}">${icon(iconFor(a.type))}</span>
            <span class="iv-activity-body">
              <span class="iv-activity-title">${escHtml(String(a.type || '').replace(/_/g, ' '))}</span>
              <span class="iv-activity-detail">${a.userId ? `&lt;@${escHtml(a.userId)}&gt;` : ''}${a.detail ? ` · ${escHtml(a.detail)}` : ''}</span>
            </span>
            <span class="iv-activity-when">${fmtWhen(a.createdAt)}</span>
          </li>`).join('');
    }

    function renderStatus(settings, diagnostics) {
        const wrap = document.getElementById('iv-status');
        if (wrap) {
            wrap.innerHTML = `
              <span class="iv-pill ${settings.enabled !== false ? 'iv-pill-on' : 'iv-pill-off'}">${icon(settings.enabled !== false ? 'check' : 'ban')} ${settings.enabled !== false ? 'Tracking enabled' : 'Tracking disabled'}</span>
              <ul class="iv-status-list">
                <li><span>Log channel</span><strong>${settings.logChannelId ? `&lt;#${escHtml(settings.logChannelId)}&gt;` : 'Not set'}</strong></li>
                <li><span>Join notifications</span><strong>${settings.joinNotifications ? 'On' : 'Off'}</strong></li>
                <li><span>Leave notifications</span><strong>${settings.leaveNotifications ? 'On' : 'Off'}</strong></li>
                <li><span>Vanity detection</span><strong>${settings.vanityTracking !== false ? 'On' : 'Off'}</strong></li>
                <li><span>Exclude bots</span><strong>${settings.excludeBots !== false ? 'Yes' : 'No'}</strong></li>
                <li><span>Excluded members</span><strong>${(settings.excludedUserIds || []).length}</strong></li>
              </ul>`;
        }
        const diagWrap = document.getElementById('iv-diagnostics');
        if (diagWrap && diagnostics) {
            diagWrap.innerHTML = diagnostics.ok
                ? `<p class="iv-diag iv-diag-ok">${icon('check')} The bot can read invites (Manage Server) — attribution is active.</p>`
                : `<p class="iv-diag iv-diag-warn">${icon('ban')} The bot is missing <strong>Manage Server</strong>, so it cannot read invite usage. Joins are recorded with an <strong>Unknown</strong> inviter until this is granted.</p>`;
        }
    }

    function renderPager(data) {
        state.page = data.page || 1;
        state.totalPages = data.totalPages || 1;
        const label = document.getElementById('iv-page-label');
        if (label) label.textContent = `Page ${state.page} / ${state.totalPages}`;
        const prev = document.getElementById('iv-prev');
        const next = document.getElementById('iv-next');
        if (prev) prev.disabled = state.page <= 1;
        if (next) next.disabled = state.page >= state.totalPages;
        const total = document.getElementById('iv-total');
        if (total) total.textContent = `${data.total || 0} tracked`;
    }

    async function refresh(pageNumber) {
        const btn = document.getElementById('iv-refresh');
        if (btn) btn.disabled = true;
        try {
            const data = await api(`/api/guilds/${GUILD_ID}/invites?page=${pageNumber || state.page}`);
            state.data = data;
            renderStats(data.totals || {});
            renderLeaderboard(data.leaderboard);
            renderJoins(data.recentJoins);
            renderActivity(data.activity);
            renderStatus(data.settings || {}, data.diagnostics);
            renderPager(data);
        } catch (err) {
            toast(err.message || 'Failed to refresh invite tracking.', 'error');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    // ── Configuration (floating Save bar) ────────────────────────────────────
    function collectSettings() {
        const excluded = ($('#iv-excluded')?.value || '')
            .split(/[\s,]+/).map(s => s.trim()).filter(s => /^\d{15,22}$/.test(s));
        return {
            enabled: $('#iv-enabled')?.checked === true,
            joinNotifications: $('#iv-join-notify')?.checked === true,
            leaveNotifications: $('#iv-leave-notify')?.checked === true,
            vanityTracking: $('#iv-vanity')?.checked === true,
            excludeBots: $('#iv-exclude-bots')?.checked === true,
            logChannelId: $('#iv-log-channel')?.value || null,
            excludedUserIds: excluded,
        };
    }

    async function saveConfig() {
        const { settings } = await api(`/api/guilds/${GUILD_ID}/invites`, {
            method: 'PATCH',
            body: JSON.stringify(collectSettings()),
        });
        toast('Invite tracking saved', 'success');
        renderStatus(settings, state.data ? state.data.diagnostics : null);
    }

    // ── Reset ────────────────────────────────────────────────────────────────
    function wireReset() {
        const input = document.getElementById('iv-reset-confirm');
        const btn = document.getElementById('iv-reset');
        if (!input || !btn) return;
        input.addEventListener('input', () => {
            btn.disabled = input.value.trim().toUpperCase() !== 'RESET';
        });
        btn.addEventListener('click', async () => {
            if (input.value.trim().toUpperCase() !== 'RESET') return;
            btn.disabled = true;
            btn.textContent = 'Resetting…';
            try {
                const result = await api(`/api/guilds/${GUILD_ID}/invites/reset`, {
                    method: 'POST',
                    body: JSON.stringify({ confirm: true }),
                });
                toast(`Reset complete — cleared ${result.joins} joins.`, 'success');
                input.value = '';
                await refresh(1);
            } catch (err) {
                toast(err.message || 'Reset failed.', 'error');
            } finally {
                btn.textContent = 'Reset statistics';
                btn.disabled = input.value.trim().toUpperCase() !== 'RESET';
            }
        });
    }

    // ── Member detail modal ──────────────────────────────────────────────────
    function modalEl() {
        let modal = document.getElementById('iv-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'iv-modal';
            modal.className = 'hidden';
            document.body.appendChild(modal);
        }
        return modal;
    }

    async function openMember(userId) {
        const modal = modalEl();
        modal.innerHTML = `<div class="modal floating-window"><div class="modal-body"><p class="iv-muted">Loading…</p></div></div>`;
        modal.classList.remove('hidden');
        const close = () => { modal.classList.add('hidden'); modal.innerHTML = ''; };
        modal.onclick = (e) => { if (e.target === modal) close(); };
        try {
            const data = await api(`/api/guilds/${GUILD_ID}/invites/member/${userId}`);
            const s = data.stat || {};
            const invited = (data.invited || []).map(j =>
                `<li>&lt;@${escHtml(j.userId)}&gt;${j.leftAt ? ' <span class="iv-badge iv-badge-muted">left</span>' : ''} <span class="iv-muted">${fmtWhen(j.joinedAt)}</span></li>`
            ).join('') || '<li class="iv-muted">No members invited yet.</li>';
            modal.innerHTML = `
              <div class="modal floating-window">
                <div class="modal-head">
                  <span>&lt;@${escHtml(userId)}&gt; — invite details</span>
                  <button class="modal-close" id="iv-modal-close" aria-label="Close">✕</button>
                </div>
                <div class="modal-body">
                  <div class="iv-modal-stats">
                    <div><strong>${s.joins || 0}</strong><span>Joins</span></div>
                    <div><strong>${s.leaves || 0}</strong><span>Left</span></div>
                    <div><strong>${s.net || 0}</strong><span>Net</span></div>
                    <div><strong>${s.activeInvites || 0}</strong><span>Active codes</span></div>
                    ${data.rank ? `<div><strong>#${data.rank.rank}</strong><span>Rank of ${data.rank.total}</span></div>` : ''}
                  </div>
                  <h4 class="iv-modal-title">Invited members</h4>
                  <ul class="iv-modal-list">${invited}</ul>
                </div>
                <div class="modal-actions"><button class="btn btn-secondary" id="iv-modal-done">Close</button></div>
              </div>`;
            document.getElementById('iv-modal-close')?.addEventListener('click', close);
            document.getElementById('iv-modal-done')?.addEventListener('click', close);
        } catch (err) {
            modal.innerHTML = `<div class="modal floating-window"><div class="modal-body"><p class="iv-muted">${escHtml(err.message || 'Failed to load member details.')}</p></div><div class="modal-actions"><button class="btn btn-secondary" id="iv-modal-done">Close</button></div></div>`;
            document.getElementById('iv-modal-done')?.addEventListener('click', close);
        }
    }

    function bindMemberLinks() {
        document.querySelectorAll('[data-invite-member]').forEach(el => {
            el.onclick = (e) => {
                e.preventDefault();
                openMember(el.dataset.inviteMember);
            };
        });
    }

    // ── Wiring ───────────────────────────────────────────────────────────────
    document.getElementById('iv-prev')?.addEventListener('click', () => refresh(state.page - 1));
    document.getElementById('iv-next')?.addEventListener('click', () => refresh(state.page + 1));
    document.getElementById('iv-refresh')?.addEventListener('click', () => refresh(state.page));

    if (window.saveBar) {
        window.saveBar.register(saveConfig);
        window.saveBar.track(document.body);
    }

    wireReset();
    bindMemberLinks();
})();
