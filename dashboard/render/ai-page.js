/**
 * AI Assistant dashboard page (/guild/:guildId/ai).
 *
 * Server-rendered with eight horizontal sections, matching the AutoMod console
 * (hero + stat cards + section rail + cards). Every control here persists to
 * AI_DATABASE_URL through the dashboard API; provider API keys are never
 * rendered — only whether a provider is configured and a masked hint.
 */

const { esc, svgIcon } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');
const {
    AI_MODES, AI_PERSONALITIES, AI_LANGUAGES, AI_LIMITS, DEFAULT_AI_SETTINGS,
} = require('../../shared/aiConstants');

const SUPPORT_URL = 'https://discord.gg/gd7UNSfX86';

const SECTION_ORDER = [
    'overview', 'configuration', 'personality', 'knowledge', 'memory', 'usage', 'providers', 'permissions',
];

const SECTION_LABELS = {
    overview: 'Overview',
    configuration: 'AI Configuration',
    personality: 'Personality',
    knowledge: 'Knowledge Base',
    memory: 'Memory',
    usage: 'Usage Analytics',
    providers: 'Provider Status',
    permissions: 'Permissions',
};

const SECTION_ICONS = {
    overview: 'sparkles',
    configuration: 'settings',
    personality: 'smile',
    knowledge: 'book',
    memory: 'layers',
    usage: 'chart',
    providers: 'server',
    permissions: 'lock',
};

function fmtWhen(iso) {
    if (!iso) return '—';
    const ms = new Date(iso).getTime();
    if (!Number.isFinite(ms)) return '—';
    return `<t:${Math.floor(ms / 1000)}:R>`;
}

function sectionRail(active = 'overview') {
    return `<nav class="ai-sections" id="ai-sections" aria-label="AI sections">${SECTION_ORDER.map(key => `
        <button type="button" class="ai-section-btn${key === active ? ' active' : ''}" data-ai-section="${key}"
                aria-current="${key === active ? 'page' : 'false'}">
            ${svgIcon(SECTION_ICONS[key])}<span>${SECTION_LABELS[key]}</span>
        </button>`).join('')}</nav>`;
}

function statCard(label, value, icon, id) {
    return `<div class="ai-stat">
        <div class="ai-stat-ico">${svgIcon(icon)}</div>
        <div>
            <div class="ai-stat-num" ${id ? `id="${id}"` : ''}>${esc(String(value))}</div>
            <div class="ai-stat-label">${esc(label)}</div>
        </div>
    </div>`;
}

function providerCard(p, meta = {}) {
    const configured = p.configured === true;
    const state = !configured ? 'Not configured' : (meta.active === false ? 'Cooling down' : 'Ready');
    const tone = !configured ? 'off' : (meta.active === false ? 'warn' : 'on');
    return `<article class="ai-provider" data-provider="${esc(p.provider)}">
        <header>
            <span class="ai-provider-name">${svgIcon('server')} ${esc(p.label)}</span>
            <span class="ai-pill ai-pill-${tone}">${esc(state)}</span>
        </header>
        <dl class="ai-provider-meta">
            <div><dt>Model</dt><dd><code>${esc(p.model || '—')}</code></dd></div>
            <div><dt>Free tier</dt><dd>${p.model ? 'Yes (allowlisted)' : '—'}</dd></div>
            <div><dt>Vision</dt><dd>${p.vision ? 'Supported' : 'Not supported'}</dd></div>
            <div><dt>Key</dt><dd>${configured ? `<code>${esc(p.keyHint || '••••')}</code>` : `<code>${esc(p.envKey)}</code> not set`}</dd></div>
            <div><dt>Requests</dt><dd>${Number(meta.requests) || 0}</dd></div>
            <div><dt>Failures</dt><dd>${Number(meta.failures) || 0}</dd></div>
            ${meta.lastError ? `<div class="ai-provider-error"><dt>Last error</dt><dd>${esc(String(meta.lastError).slice(0, 160))}</dd></div>` : ''}
        </dl>
        <div class="ai-provider-actions">
            <button type="button" class="btn btn-secondary btn-sm ai-test-provider" data-provider="${esc(p.provider)}"
                    ${configured ? '' : 'disabled'}>${svgIcon('activity')} Test</button>
        </div>
    </article>`;
}

function toggleRow(id, label, checked, hint = '') {
    return `<label class="ai-toggle-row">
        <span><strong>${esc(label)}</strong>${hint ? `<span class="ai-hint">${esc(hint)}</span>` : ''}</span>
        <input type="checkbox" id="${id}" ${checked ? 'checked' : ''} />
    </label>`;
}

function selectRow(id, label, value, options, hint = '') {
    return `<div class="field">
        <label class="field-label" for="${id}">${esc(label)}</label>
        <select id="${id}">
            ${options.map(o => `<option value="${esc(o.value)}" ${String(o.value) === String(value) ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}
        </select>
        ${hint ? `<div class="field-hint">${esc(hint)}</div>` : ''}
    </div>`;
}

function numberRow(id, label, value, { min, max }, hint = '') {
    return `<div class="field">
        <label class="field-label" for="${id}">${esc(label)}</label>
        <input type="number" id="${id}" value="${esc(String(value))}" min="${min}" max="${max}" />
        ${hint ? `<div class="field-hint">${esc(hint)}</div>` : ''}
    </div>`;
}

function knowledgeRows(entries) {
    if (!entries.length) {
        return `<tr><td colspan="4" class="ai-empty">${svgIcon('book')} No knowledge yet. Add your server rules, FAQ or key facts below.</td></tr>`;
    }
    return entries.map(e => `<tr>
        <td><code>#${e.id}</code></td>
        <td><strong>${esc(e.title)}</strong>${e.tags ? `<div class="ai-hint">${esc(e.tags)}</div>` : ''}</td>
        <td class="ai-kb-content">${esc(e.content.slice(0, 220))}${e.content.length > 220 ? '…' : ''}</td>
        <td><button type="button" class="btn btn-secondary btn-sm ai-kb-delete" data-id="${e.id}">${svgIcon('trash')} Delete</button></td>
    </tr>`).join('');
}

function sessionRows(sessions) {
    if (!sessions.length) {
        return `<tr><td colspan="4" class="ai-empty">${svgIcon('layers')} No active conversations.</td></tr>`;
    }
    return sessions.map(s => `<tr>
        <td><code>${esc(s.userId)}</code></td>
        <td>${Number(s.messageCount) || 0}</td>
        <td>${fmtWhen(s.expiresAt)}</td>
        <td><button type="button" class="btn btn-secondary btn-sm ai-session-clear" data-user="${esc(s.userId)}">${svgIcon('trash')} Clear</button></td>
    </tr>`).join('');
}

function usageBars(series) {
    if (!series || !series.length) return `<p class="ai-empty">${svgIcon('chart')} No usage recorded yet.</p>`;
    const max = Math.max(...series.map(s => s.requests), 1);
    return `<div class="ai-bars">${series.map(s => {
        const h = Math.max(3, Math.round((s.requests / max) * 100));
        return `<div class="ai-bar-col" title="${esc(s.day)}: ${s.requests} request(s)">
            <div class="ai-bar" style="height:${h}%"></div>
            <span>${esc(s.day.slice(5))}</span>
        </div>`;
    }).join('')}</div>`;
}

function topUserRows(rows) {
    if (!rows || !rows.length) return `<tr><td colspan="3" class="ai-empty">No usage yet.</td></tr>`;
    return rows.map((r, i) => `<tr>
        <td class="ai-rank">${i + 1}</td>
        <td><code>${esc(r.userId)}</code></td>
        <td class="ai-num">${r.requests} requests · ${r.tokens} tokens</td>
    </tr>`).join('');
}

function aiPage({ guild, user }) {
    const data = (guild._config && guild._config.ai) || {};
    const settings = { ...DEFAULT_AI_SETTINGS, ...(data.settings || {}) };
    const providers = data.providers || [];
    const providerMeta = new Map((data.providerMeta || []).map(m => [m.provider, m]));
    const usage = data.usage || {};
    const sessions = data.sessions || [];
    const knowledge = data.knowledge || [];
    const configured = providers.filter(p => p.configured);
    const ready = providers.filter(p => p.configured && providerMeta.get(p.provider)?.active !== false);

    const channelOpts = (guild._channels || [])
        .map(c => `<option value="${esc(c.id)}"${settings.channelIds.includes(String(c.id)) ? ' selected' : ''}>#${esc(c.name)}</option>`)
        .join('');
    const roleOptions = (guild._roles || [])
        .filter(r => !r.managed && r.name !== '@everyone')
        .map(r => `<option value="${esc(r.id)}"${settings.roleIds.includes(String(r.id)) ? ' selected' : ''}>${esc(r.name)}</option>`)
        .join('');

    const body = `
${guildHeaderHTML(guild)}
${tabNavHTML(guild.id, 'ai')}
<div class="ai-page" id="ai-page" data-guild-id="${esc(guild.id)}">

    <section class="ai-hero">
        <div class="ai-hero-main">
            <span class="ai-hero-icon">${svgIcon('sparkles')}</span>
            <div>
                <h1 class="ai-hero-title">AI Assistant</h1>
                <p class="ai-hero-sub">A free AI assistant for every member — slash commands, prefix commands and mentions, all sharing one memory and one provider pool.</p>
                <div class="ai-hero-pills">
                    <span class="ai-pill ai-pill-premium">${svgIcon('premium')} Free for every server</span>
                    <span class="ai-pill ${settings.enabled ? 'ai-pill-on' : 'ai-pill-off'}" id="ai-enabled-pill">${svgIcon(settings.enabled ? 'check' : 'ban')} ${settings.enabled ? 'Enabled' : 'Disabled'}</span>
                    <span class="ai-pill">${svgIcon('server')} ${configured.length} provider${configured.length === 1 ? '' : 's'} configured</span>
                    <span class="ai-pill">${svgIcon('activity')} ${ready.length} ready now</span>
                </div>
            </div>
        </div>
        <div class="ai-hero-actions">
            <button type="button" class="btn btn-secondary" id="ai-refresh">${svgIcon('refresh')} Refresh</button>
        </div>
    </section>

    <section class="ai-stats">
        ${statCard('Requests today', usage.today?.requests ?? 0, 'activity', 'ai-stat-requests')}
        ${statCard('Active conversations', data.sessionTotal ?? sessions.length, 'layers', 'ai-stat-sessions')}
        ${statCard('Knowledge entries', knowledge.length, 'book', 'ai-stat-knowledge')}
        ${statCard('Providers ready', ready.length, 'server', 'ai-stat-providers')}
    </section>

    ${sectionRail('overview')}

    <section class="ai-section" data-section="overview">
        <div class="ai-grid">
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('sparkles')} How it works</h3></div>
                <ul class="ai-list">
                    <li><strong>Slash</strong> — <code>/ai ask</code>, <code>/ai chat</code>, <code>/ai translate</code>…</li>
                    <li><strong>Prefix</strong> — <code>$ai ask …</code> using the server prefix.</li>
                    <li><strong>Mentions</strong> — mention the bot, or reply to one of its answers.</li>
                    <li>Conversations are per member and per server, persisted across restarts.</li>
                    <li>All providers are free tiers; a shared daily budget keeps them usable for everyone.</li>
                </ul>
                <div class="ai-quick">
                    <a class="btn btn-secondary btn-sm" href="/guild/${esc(guild.id)}/ai?section=configuration">${svgIcon('settings')} Configuration</a>
                    <a class="btn btn-secondary btn-sm" href="/guild/${esc(guild.id)}/ai?section=personality">${svgIcon('smile')} Personality</a>
                    <a class="btn btn-secondary btn-sm" href="/guild/${esc(guild.id)}/ai?section=knowledge">${svgIcon('book')} Knowledge</a>
                </div>
            </div>
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('chart')} Usage today</h3></div>
                <dl class="ai-kv">
                    <div><dt>This server</dt><dd id="ai-usage-today">${usage.guildToday?.requests ?? 0} / ${settings.dailyGuildRequests}</dd></div>
                    <div><dt>Tokens</dt><dd id="ai-usage-tokens">${usage.guildToday?.tokens ?? 0}</dd></div>
                    <div><dt>Session TTL</dt><dd>${settings.sessionTtlMinutes} min</dd></div>
                    <div><dt>Cooldown</dt><dd>${settings.cooldownSeconds}s</dd></div>
                </dl>
                <div class="ai-diag-wrap" id="ai-diagnostics">${configured.length
                    ? `<p class="ai-diag ai-diag-ok">${svgIcon('check')} ${configured.length} free provider(s) configured — the assistant is available.</p>`
                    : `<p class="ai-diag ai-diag-warn">${svgIcon('ban')} No provider key is set. The bot owner must configure <code>GROQ_API_KEY</code> (recommended), <code>GEMINI_API_KEY</code> or <code>OPENROUTER_API_KEY</code>.</p>`}</div>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="configuration" hidden>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('settings')} AI configuration</h3><span class="ai-hint">Saves apply to the bot within ~30s</span></div>
            <div class="ai-form-grid">
                ${toggleRow('ai-enabled', 'AI assistant enabled', settings.enabled, 'Turning this off disables every AI entry point in this server.')}
                ${toggleRow('ai-knowledge-enabled', 'Use the server knowledge base', settings.knowledgeEnabled)}
                ${toggleRow('ai-vision', 'Allow image analysis', settings.visionEnabled, 'Routes images to a free vision model (Gemini).')}
                ${selectRow('ai-mode', 'Response mode', settings.mode, AI_MODES.map(m => ({ value: m.key, label: m.label })), 'Mention mode never answers unmentioned chatter.')}
                ${selectRow('ai-language', 'Response language', settings.language, AI_LANGUAGES.map(l => ({ value: l.key, label: l.label })))}
                ${numberRow('ai-max-length', 'Max response length (characters)', settings.maxResponseChars, AI_LIMITS.maxResponseCharsSetting)}
                ${numberRow('ai-session-ttl', 'Session expiry (minutes)', settings.sessionTtlMinutes, AI_LIMITS.sessionTtlMinutes)}
                ${numberRow('ai-cooldown', 'Per-user cooldown (seconds)', settings.cooldownSeconds, AI_LIMITS.cooldownSeconds)}
                ${numberRow('ai-daily-user', 'Daily requests per member', settings.dailyUserRequests, AI_LIMITS.dailyUserRequests)}
                ${numberRow('ai-daily-guild', 'Daily requests per server', settings.dailyGuildRequests, AI_LIMITS.dailyGuildRequests)}
            </div>
            <div class="ai-form-grid">
                <div class="field">
                    <label class="field-label" for="ai-channels">Allowed channels</label>
                    <select id="ai-channels" multiple size="6">${channelOpts}</select>
                    <div class="field-hint">Nothing selected = every channel. Hold Ctrl/Cmd to select several.</div>
                </div>
                <div class="field">
                    <label class="field-label" for="ai-roles">Allowed roles</label>
                    <select id="ai-roles" multiple size="6">${roleOptions}</select>
                    <div class="field-hint">Nothing selected = every member. Admins always pass.</div>
                </div>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="personality" hidden>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('smile')} Personality</h3></div>
            <div class="ai-form-grid">
                ${selectRow('ai-personality', 'Assistant tone', settings.personality, AI_PERSONALITIES.map(p => ({ value: p.key, label: p.label })))}
                <div class="field ai-field-wide">
                    <label class="field-label" for="ai-instructions">Custom instructions</label>
                    <textarea id="ai-instructions" rows="5" maxlength="${AI_LIMITS.maxInstructions}" placeholder="e.g. Always answer in a friendly tone, mention our event channel for event questions, never give legal advice.">${esc(settings.customInstructions || '')}</textarea>
                    <div class="field-hint">Used with the <code>custom</code> personality, and as extra guidance for every preset.</div>
                </div>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="knowledge" hidden>
        <div class="ai-grid">
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('book')} Knowledge base</h3><span class="ai-hint" id="ai-kb-count">${knowledge.length} / ${AI_LIMITS.maxKnowledgeEntries}</span></div>
                <div class="ai-table-wrap">
                    <table class="ai-table" id="ai-knowledge-list">
                        <thead><tr><th>#</th><th>Title</th><th>Content</th><th></th></tr></thead>
                        <tbody>${knowledgeRows(knowledge)}</tbody>
                    </table>
                </div>
            </div>
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('plus')} Add knowledge</h3></div>
                <div class="field"><label class="field-label" for="ai-kb-title">Title</label><input id="ai-kb-title" maxlength="${AI_LIMITS.maxKnowledgeTitle}" placeholder="Rules, FAQ, opening hours…" /></div>
                <div class="field"><label class="field-label" for="ai-kb-content">Content</label><textarea id="ai-kb-content" rows="5" maxlength="${AI_LIMITS.maxKnowledgeContent}" placeholder="The facts the assistant may use."></textarea></div>
                <div class="field"><label class="field-label" for="ai-kb-tags">Tags (optional)</label><input id="ai-kb-tags" maxlength="120" placeholder="rules, support" /></div>
                <button type="button" class="btn btn-primary" id="ai-kb-add">${svgIcon('plus')} Add entry</button>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="memory" hidden>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('layers')} Conversation memory</h3>
                <button type="button" class="btn btn-secondary btn-sm" id="ai-clear-all">${svgIcon('trash')} Clear all sessions</button>
            </div>
            <p class="ai-hint">One conversation per member. Sessions expire after ${settings.sessionTtlMinutes} minutes of inactivity; clearing a session removes its stored messages.</p>
            <div class="ai-table-wrap">
                <table class="ai-table" id="ai-sessions">
                    <thead><tr><th>Member</th><th>Messages</th><th>Expires</th><th></th></tr></thead>
                    <tbody>${sessionRows(sessions)}</tbody>
                </table>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="usage" hidden>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('chart')} Requests (last 14 days)</h3></div>
            <div id="ai-usage-series">${usageBars(usage.series || [])}</div>
        </div>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('trophy')} Top members</h3></div>
            <div class="ai-table-wrap">
                <table class="ai-table" id="ai-top-users">
                    <thead><tr><th>#</th><th>Member</th><th>Usage</th></tr></thead>
                    <tbody>${topUserRows(usage.topUsers || [])}</tbody>
                </table>
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="providers" hidden>
        <div class="ai-card">
            <div class="ai-card-head"><h3>${svgIcon('server')} Provider status</h3>
                <button type="button" class="btn btn-secondary btn-sm" id="ai-refresh-providers">${svgIcon('refresh')} Refresh</button>
            </div>
            <p class="ai-hint">Priority: Groq → Gemini → OpenRouter (free models only). Keys are configured by the bot owner as environment variables and are never shown here.</p>
            <div class="ai-providers" id="ai-providers">
                ${providers.map(p => providerCard(p, providerMeta.get(p.provider) || {})).join('') || `<p class="ai-empty">${svgIcon('server')} Provider status unavailable.</p>`}
            </div>
        </div>
    </section>

    <section class="ai-section" data-section="permissions" hidden>
        <div class="ai-grid">
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('lock')} Access rules</h3></div>
                <dl class="ai-kv">
                    <div><dt>Allowed channels</dt><dd>${settings.channelIds.length ? settings.channelIds.map(id => `<code>${esc(id)}</code>`).join(', ') : 'Any channel'}</dd></div>
                    <div><dt>Allowed roles</dt><dd>${settings.roleIds.length ? settings.roleIds.map(id => `<code>${esc(id)}</code>`).join(', ') : 'Everyone'}</dd></div>
                    <div><dt>Admin actions</dt><dd>Require <strong>Manage Server</strong></dd></div>
                    <div><dt>Member actions</dt><dd>ask · chat · explain · translate · summarize · analyze · memory · reset · usage</dd></div>
                </dl>
            </div>
            <div class="ai-card">
                <div class="ai-card-head"><h3>${svgIcon('shield')} Safety</h3></div>
                <ul class="ai-list">
                    <li>Sessions are isolated per member and per server — nobody can read another member's conversation.</li>
                    <li>Prompt-injection attempts are treated as untrusted data; system instructions and keys are never revealed.</li>
                    <li>Daily limits and cooldowns keep the shared free quota fair for every server.</li>
                    <li>Attachments are only accepted when image analysis is enabled.</li>
                </ul>
                <p class="ai-foot">Questions? Join the <a href="${SUPPORT_URL}" target="_blank" rel="noopener">support server</a>.</p>
            </div>
        </div>
    </section>
</div>
${guildDataScript({ guildId: guild.id, channels: guild._channels || [], roles: guild._roles || [] })}
`;

    return {
        body,
        scripts: ['/js/ai.js'],
        title: `PrimeBot · ${guild.name} · AI Assistant`,
    };
}

module.exports = { aiPage, SECTION_ORDER, SECTION_LABELS };
