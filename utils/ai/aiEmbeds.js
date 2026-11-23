/**
 * AI Assistant reply text — shared by slash, prefix, mention and the dashboard.
 *
 * AI replies are plain messages: no embeds anywhere in this subsystem. Text is
 * clipped to Discord's 2000-character content limit; long answers are already
 * chunked by the manager and sent as follow-up messages.
 */

const { AI_PERSONALITIES, AI_MODES, AI_LANGUAGES } = require('../../shared/aiConstants');

const FOOTER = 'PrimeBot AI • free providers';
const MAX_CONTENT = 2000;

function clip(text, max = MAX_CONTENT) {
    const value = String(text ?? '');
    return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function footerLine(provider) {
    return provider ? `${FOOTER} • ${provider}` : FOOTER;
}

function answerText({ text, provider } = {}) {
    const body = String(text ?? '');
    const tail = `\n\n-# ${footerLine(provider)}`;
    if (!body.trim()) return `-# ${footerLine(provider)}`;
    return `${clip(body, MAX_CONTENT - tail.length)}${tail}`;
}

function renderFields(fields = []) {
    return fields
        .filter(f => f && f.name && f.value != null && String(f.value).length)
        .map(f => `**${f.name}** · ${f.value}`);
}

function infoText(title, description = '', fields = []) {
    const lines = [`**${title}**`];
    if (description) lines.push(description);
    const rendered = renderFields(fields);
    if (rendered.length) lines.push(rendered.join('\n'));
    return clip(lines.join('\n'));
}

function errorText(message) {
    return clip(`❌ ${message}`);
}

function warnText(message) {
    return clip(`⚠️ ${message}`);
}

function helpText(prefix = '$') {
    const lines = [
        `**Slash:** \`/ai <action>\`  •  **Prefix:** \`${prefix}ai <action>\`  •  **Mention:** \`@PrimeBot <question>\``,
        '',
        '**Ask & chat**',
        `\`${prefix}ai ask <question>\` — one-off answer`,
        `\`${prefix}ai chat [message]\` — continue the conversation (keeps memory)`,
        `\`${prefix}ai explain <text>\` — explain a concept, code or error`,
        `\`${prefix}ai translate <language> <text>\` — translate text`,
        `\`${prefix}ai summarize [count]\` — summarize recent channel messages`,
        `\`${prefix}ai analyze [image]\` — analyse an image (attach it or reply to it)`,
        '',
        '**Memory & usage**',
        `\`${prefix}ai memory\` — show your session  •  \`${prefix}ai reset\` — clear it`,
        `\`${prefix}ai usage\` — your daily usage`,
        '',
        '**Admin — one-word shortcuts**',
        `\`${prefix}ai enable\` · \`${prefix}ai disable\` — turn the assistant on/off`,
        `\`${prefix}ai channel #general\` · \`${prefix}ai channels clear\``,
        `\`${prefix}ai role @Member\` · \`${prefix}ai roles clear\``,
        `\`${prefix}ai mode mention|auto\` · \`${prefix}ai language es\``,
        `\`${prefix}ai cooldown 5\` · \`${prefix}ai limit 60\` · \`${prefix}ai serverlimit 600\``,
        `\`${prefix}ai ttl 60\` · \`${prefix}ai length 1800\``,
        `\`${prefix}ai knowledge on|off\` · \`${prefix}ai vision on|off\``,
        `\`${prefix}ai settings\` — show the current configuration`,
        `\`${prefix}ai config <setting> <value>\` — full form (same settings)`,
        '',
        '**Admin — other**',
        `\`${prefix}ai personality <preset|instructions>\` — set the assistant tone`,
        `\`${prefix}ai knowledge add|remove|list …\` — manage server knowledge`,
        `\`${prefix}ai memory clear @member\` — clear a member's session`,
        `\`${prefix}ai usage server\` — server-wide usage`,
        '',
        '**Settings:** ' + ['enabled', 'mode', 'language', 'personality', 'channel', 'role',
            'clear_channels', 'clear_roles', 'max_length', 'session_ttl', 'cooldown',
            'daily_user', 'daily_guild', 'knowledge', 'vision'].map(s => `\`${s}\``).join(', '),
        '**Modes:** ' + AI_MODES.map(m => `\`${m.key}\``).join(', ') +
            '  •  **Personalities:** ' + AI_PERSONALITIES.map(p => `\`${p.key}\``).join(', '),
        '**Languages:** ' + AI_LANGUAGES.map(l => `\`${l.key}\``).join(', '),
    ];
    return clip(`**AI Assistant**\n${lines.join('\n')}`);
}

const PROVIDER_STATE_LABEL = {
    ok: 'ready',
    unconfigured: 'not configured',
    invalid_key: 'invalid API key',
    invalid_model: 'model unavailable',
    rate_limited: 'rate limited',
};

function statusText(settings, providerStatus = []) {
    const active = providerStatus.filter(p => p.configured && p.active).map(p => p.label);
    const providers = providerStatus.map((p) => {
        const state = PROVIDER_STATE_LABEL[p.status] || (p.active ? 'ready' : 'unavailable');
        return p.configured
            ? `• ${p.label} — \`${p.model || 'no model'}\` · ${state}`
            : `• ${p.label} — not configured`;
    });
    return infoText('AI configuration', 'Current AI settings for this server.', [
        { name: 'Enabled', value: settings.enabled ? 'Yes' : 'No' },
        { name: 'Mode', value: settings.mode },
        { name: 'Language', value: settings.language },
        { name: 'Personality', value: settings.personality },
        { name: 'Channels', value: settings.channelIds.length ? settings.channelIds.map(id => `<#${id}>`).join(', ') : 'Any channel' },
        { name: 'Roles', value: settings.roleIds.length ? settings.roleIds.map(id => `<@&${id}>`).join(', ') : 'Everyone' },
        { name: 'Limits', value: `Max ${settings.maxResponseChars} chars • ${settings.sessionTtlMinutes} min sessions • ${settings.cooldownSeconds}s cooldown • ${settings.dailyUserRequests}/user/day • ${settings.dailyGuildRequests}/server/day` },
        { name: 'Providers', value: providers.length ? providers.join('\n') : 'No provider configured' },
        { name: 'Available now', value: active.length ? active.join(', ') : 'None (busy or not configured)' },
    ]);
}

function usageText(userUsage, guildUsage, settings, { isServer = false } = {}) {
    const fields = isServer
        ? [
            { name: 'Server today', value: `${guildUsage.requests} / ${settings.dailyGuildRequests} requests` },
            { name: 'Tokens today', value: String(guildUsage.tokens || 0) },
        ]
        : [
            { name: 'Your usage today', value: `${userUsage.requests} / ${settings.dailyUserRequests} requests` },
            { name: 'Your tokens today', value: String(userUsage.tokens || 0) },
            { name: 'Server today', value: `${guildUsage.requests} / ${settings.dailyGuildRequests} requests` },
        ];
    return infoText('AI usage', 'Free-tier usage is shared by every server, so daily limits keep it fair.', fields);
}

module.exports = {
    FOOTER,
    MAX_CONTENT,
    answerText,
    infoText,
    errorText,
    warnText,
    helpText,
    statusText,
    usageText,
};
