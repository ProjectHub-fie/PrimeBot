/* AI Assistant dashboard page.
 *
 * Section rail, configuration saving through the floating Save bar, knowledge
 * CRUD, session clearing and provider tests. IIFE-wrapped so it never collides
 * with another page script's top-level bindings.
 */
(function () {
    'use strict';

    const page = document.getElementById('ai-page');
    if (!page) return;
    const GUILD_ID = page.dataset.guildId;
    if (!GUILD_ID) return;

    const $ = (sel) => document.querySelector(sel);
    const escHtml = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const icon = (name) => (window.svgIcon ? window.svgIcon(name) : '');

    // ── Section rail ────────────────────────────────────────────────────────
    function showSection(key, push) {
        const target = document.querySelector(`.ai-section[data-section="${key}"]`);
        if (!target) return;
        document.querySelectorAll('.ai-section').forEach(s => { s.hidden = s !== target; });
        document.querySelectorAll('.ai-section-btn').forEach(b => {
            const active = b.dataset.aiSection === key;
            b.classList.toggle('active', active);
            b.setAttribute('aria-current', active ? 'page' : 'false');
        });
        if (push) {
            const url = new URL(window.location.href);
            url.searchParams.set('section', key);
            history.replaceState({}, '', url);
        }
        target.scrollIntoView({ block: 'nearest' });
    }

    document.querySelectorAll('.ai-section-btn').forEach(btn => {
        btn.addEventListener('click', () => showSection(btn.dataset.aiSection, true));
    });
    showSection(new URL(window.location.href).searchParams.get('section') || 'overview', false);

    // ── Configuration (floating Save bar) ───────────────────────────────────
    const selectedValues = (sel) => Array.from(document.getElementById(sel)?.selectedOptions || []).map(o => o.value);

    function collectSettings() {
        const num = (id) => {
            const v = parseInt(document.getElementById(id)?.value, 10);
            return Number.isFinite(v) ? v : undefined;
        };
        const payload = {
            enabled: $('#ai-enabled')?.checked === true,
            knowledgeEnabled: $('#ai-knowledge-enabled')?.checked === true,
            visionEnabled: $('#ai-vision')?.checked === true,
            mode: $('#ai-mode')?.value,
            language: $('#ai-language')?.value,
            personality: $('#ai-personality')?.value,
            customInstructions: $('#ai-instructions')?.value || '',
            channelIds: selectedValues('ai-channels'),
            roleIds: selectedValues('ai-roles'),
            maxResponseChars: num('ai-max-length'),
            sessionTtlMinutes: num('ai-session-ttl'),
            cooldownSeconds: num('ai-cooldown'),
            dailyUserRequests: num('ai-daily-user'),
            dailyGuildRequests: num('ai-daily-guild'),
        };
        Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);
        return payload;
    }

    async function saveConfig() {
        const { settings } = await api(`/api/guilds/${GUILD_ID}/ai`, {
            method: 'PATCH',
            body: JSON.stringify(collectSettings()),
        });
        toast('AI settings saved', 'success');
        const pill = document.getElementById('ai-enabled-pill');
        if (pill) {
            pill.className = `ai-pill ${settings.enabled ? 'ai-pill-on' : 'ai-pill-off'}`;
            pill.innerHTML = `${icon(settings.enabled ? 'check' : 'ban')} ${settings.enabled ? 'Enabled' : 'Disabled'}`;
        }
    }

    if (window.saveBar) {
        window.saveBar.register(saveConfig);
        window.saveBar.track(document.body);
    }

    // ── Knowledge base ──────────────────────────────────────────────────────
    async function addKnowledge() {
        const title = document.getElementById('ai-kb-title')?.value.trim();
        const content = document.getElementById('ai-kb-content')?.value.trim();
        const tags = document.getElementById('ai-kb-tags')?.value.trim();
        if (!title || !content) {
            toast('A title and content are required.', 'error');
            return;
        }
        const btn = document.getElementById('ai-kb-add');
        if (btn) btn.disabled = true;
        try {
            await api(`/api/guilds/${GUILD_ID}/ai/knowledge`, {
                method: 'POST',
                body: JSON.stringify({ title, content, tags }),
            });
            toast('Knowledge entry added', 'success');
            await refresh();
        } catch (err) {
            toast(err.message || 'Failed to add the entry.', 'error');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function deleteKnowledge(id) {
        if (!window.confirm('Delete this knowledge entry?')) return;
        try {
            await api(`/api/guilds/${GUILD_ID}/ai/knowledge/${id}`, { method: 'DELETE' });
            toast('Entry deleted', 'success');
            await refresh();
        } catch (err) {
            toast(err.message || 'Failed to delete the entry.', 'error');
        }
    }

    // ── Sessions ────────────────────────────────────────────────────────────
    async function clearSession(userId) {
        if (!window.confirm('Clear this member\'s AI conversation?')) return;
        try {
            await api(`/api/guilds/${GUILD_ID}/ai/sessions/${userId}`, { method: 'DELETE' });
            toast('Session cleared', 'success');
            await refresh();
        } catch (err) {
            toast(err.message || 'Failed to clear the session.', 'error');
        }
    }

    async function clearAllSessions() {
        if (!window.confirm('Clear every AI conversation in this server?')) return;
        try {
            await api(`/api/guilds/${GUILD_ID}/ai/sessions/clear`, { method: 'POST' });
            toast('All sessions cleared', 'success');
            await refresh();
        } catch (err) {
            toast(err.message || 'Failed to clear sessions.', 'error');
        }
    }

    // ── Provider tests ──────────────────────────────────────────────────────
    async function testProvider(provider, btn) {
        const original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `${icon('loading')} Testing…`;
        try {
            const result = await api(`/api/guilds/${GUILD_ID}/ai/providers/${provider}/test`, { method: 'POST' });
            toast(result.ok
                ? `${provider} responded in ${result.latencyMs}ms`
                : `${provider}: ${result.message || 'failed'}`, result.ok ? 'success' : 'error');
        } catch (err) {
            toast(err.message || 'Provider test failed.', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = original;
        }
    }

    // ── Rendering / refresh ─────────────────────────────────────────────────
    function renderKnowledge(entries) {
        const body = document.querySelector('#ai-knowledge-list tbody');
        if (!body) return;
        if (!entries.length) {
            body.innerHTML = `<tr><td colspan="4" class="ai-empty">${icon('book')} No knowledge yet. Add your server rules, FAQ or key facts below.</td></tr>`;
            return;
        }
        body.innerHTML = entries.map(e => `<tr>
            <td><code>#${e.id}</code></td>
            <td><strong>${escHtml(e.title)}</strong>${e.tags ? `<div class="ai-hint">${escHtml(e.tags)}</div>` : ''}</td>
            <td class="ai-kb-content">${escHtml(e.content.slice(0, 220))}${e.content.length > 220 ? '…' : ''}</td>
            <td><button type="button" class="btn btn-secondary btn-sm ai-kb-delete" data-id="${e.id}">${icon('trash')} Delete</button></td>
        </tr>`).join('');
        bindKnowledge();
    }

    function renderSessions(sessions) {
        const body = document.querySelector('#ai-sessions tbody');
        if (!body) return;
        if (!sessions.length) {
            body.innerHTML = `<tr><td colspan="4" class="ai-empty">${icon('layers')} No active conversations.</td></tr>`;
            return;
        }
        body.innerHTML = sessions.map(s => `<tr>
            <td><code>${escHtml(s.userId)}</code></td>
            <td>${Number(s.messageCount) || 0}</td>
            <td>${escHtml(new Date(s.expiresAt).toLocaleString())}</td>
            <td><button type="button" class="btn btn-secondary btn-sm ai-session-clear" data-user="${escHtml(s.userId)}">${icon('trash')} Clear</button></td>
        </tr>`).join('');
        bindSessions();
    }

    function renderUsage(usage) {
        const series = document.getElementById('ai-usage-series');
        if (series) {
            if (!usage.series || !usage.series.length) {
                series.innerHTML = `<p class="ai-empty">${icon('chart')} No usage recorded yet.</p>`;
            } else {
                const max = Math.max(...usage.series.map(s => s.requests), 1);
                series.innerHTML = `<div class="ai-bars">${usage.series.map(s => {
                    const h = Math.max(3, Math.round((s.requests / max) * 100));
                    return `<div class="ai-bar-col" title="${escHtml(s.day)}: ${s.requests} request(s)">
                        <div class="ai-bar" style="height:${h}%"></div>
                        <span>${escHtml(s.day.slice(5))}</span>
                    </div>`;
                }).join('')}</div>`;
            }
        }
        const top = document.querySelector('#ai-top-users tbody');
        if (top) {
            top.innerHTML = (usage.topUsers && usage.topUsers.length)
                ? usage.topUsers.map((r, i) => `<tr><td class="ai-rank">${i + 1}</td><td><code>${escHtml(r.userId)}</code></td><td class="ai-num">${r.requests} requests · ${r.tokens} tokens</td></tr>`).join('')
                : '<tr><td colspan="3" class="ai-empty">No usage yet.</td></tr>';
        }
        const today = document.getElementById('ai-usage-today');
        if (today) today.textContent = `${usage.guildToday?.requests ?? 0} / ${usage.limits?.dailyGuildRequests ?? '—'}`;
        const tokens = document.getElementById('ai-usage-tokens');
        if (tokens) tokens.textContent = String(usage.guildToday?.tokens ?? 0);
    }

    function setStat(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = String(value);
    }

    async function refresh() {
        const btn = document.getElementById('ai-refresh');
        if (btn) btn.disabled = true;
        try {
            const data = await api(`/api/guilds/${GUILD_ID}/ai`);
            renderKnowledge(data.knowledge || []);
            renderSessions(data.sessions || []);
            renderUsage({ ...(data.usage || {}), limits: data.settings || {} });
            setStat('ai-stat-requests', data.usage?.today?.requests ?? 0);
            setStat('ai-stat-sessions', data.sessionTotal ?? (data.sessions || []).length);
            setStat('ai-stat-knowledge', (data.knowledge || []).length);
            setStat('ai-stat-providers', (data.providers || []).filter(p => p.active).length);
            const count = document.getElementById('ai-kb-count');
            if (count) count.textContent = `${(data.knowledge || []).length} / ${data.knowledgeLimit || 50}`;
        } catch (err) {
            toast(err.message || 'Failed to refresh AI data.', 'error');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function bindKnowledge() {
        document.querySelectorAll('.ai-kb-delete').forEach(btn => {
            btn.onclick = () => deleteKnowledge(btn.dataset.id);
        });
    }

    function bindSessions() {
        document.querySelectorAll('.ai-session-clear').forEach(btn => {
            btn.onclick = () => clearSession(btn.dataset.user);
        });
    }

    function bindProviders() {
        document.querySelectorAll('.ai-test-provider').forEach(btn => {
            btn.onclick = () => testProvider(btn.dataset.provider, btn);
        });
    }

    document.getElementById('ai-kb-add')?.addEventListener('click', addKnowledge);
    document.getElementById('ai-clear-all')?.addEventListener('click', clearAllSessions);
    document.getElementById('ai-refresh')?.addEventListener('click', refresh);
    document.getElementById('ai-refresh-providers')?.addEventListener('click', refresh);

    bindKnowledge();
    bindSessions();
    bindProviders();
})();
