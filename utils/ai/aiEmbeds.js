/**
 * AI Assistant embeds — shared by slash, prefix and the dashboard previews.
 * Brand palette only (config.colors) and no secrets in any field.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../../config');
const { AI_PERSONALITIES, AI_MODES, AI_LANGUAGES } = require('../../shared/aiConstants');

const FOOTER = 'PrimeBot AI • free providers';

function answerEmbed(result) {
    const provider = result.provider ? ` • ${result.provider}` : '';
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setDescription(result.text)
        .setFooter({ text: `${FOOTER}${provider}` });
}

function infoEmbed(title, description, fields = []) {
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle(title)
        .setDescription(description)
        .setFooter({ text: FOOTER });
    if (fields.length) embed.addFields(fields);
    return embed;
}

function errorEmbed(description) {
    return new EmbedBuilder()
        .setColor(config.colors.error)
        .setTitle('AI Assistant')
        .setDescription(description)
        .setFooter({ text: FOOTER });
}

function warnEmbed(description) {
    return new EmbedBuilder()
        .setColor(config.colors.warning)
        .setTitle('AI Assistant')
        .setDescription(description)
        .setFooter({ text: FOOTER });
}

function helpEmbed(prefix = '$') {
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
        '**Admin**',
        `\`${prefix}ai config <setting> <value>\` — enable, mode, language, personality, channel, role, limits`,
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
    return infoEmbed('AI Assistant', lines.join('\n'));
}

const PROVIDER_STATE_LABEL = {
    ok: 'ready',
    unconfigured: 'not configured',
    invalid_key: 'invalid API key',
    invalid_model: 'model unavailable',
    rate_limited: 'rate limited',
};

function statusEmbed(settings, providerStatus = []) {
    const active = providerStatus.filter(p => p.configured && p.active).map(p => p.label);
    const configured = providerStatus.map((p) => {
        const state = PROVIDER_STATE_LABEL[p.status] || (p.active ? 'ready' : 'unavailable');
        return p.configured
            ? `${p.label} — \`${p.model || 'no model'}\` • ${state}`
            : `${p.label} — not configured`;
    });
    return infoEmbed('AI configuration', 'Current AI settings for this server.', [
        { name: 'Enabled', value: settings.enabled ? 'Yes' : 'No', inline: true },
        { name: 'Mode', value: settings.mode, inline: true },
        { name: 'Language', value: settings.language, inline: true },
        { name: 'Personality', value: settings.personality, inline: true },
        { name: 'Channels', value: settings.channelIds.length ? settings.channelIds.map(id => `<#${id}>`).join(', ') : 'Any channel', inline: false },
        { name: 'Roles', value: settings.roleIds.length ? settings.roleIds.map(id => `<@&${id}>`).join(', ') : 'Everyone', inline: false },
        { name: 'Limits', value: `Max ${settings.maxResponseChars} chars • ${settings.sessionTtlMinutes} min sessions • ${settings.cooldownSeconds}s cooldown\n${settings.dailyUserRequests}/user/day • ${settings.dailyGuildRequests}/server/day`, inline: false },
        { name: 'Providers', value: configured.length ? configured.join('\n') : 'No provider configured', inline: false },
        { name: 'Available now', value: active.length ? active.join(', ') : 'None (busy or not configured)', inline: false },
    ]);
}

function usageEmbed(userUsage, guildUsage, settings, { isServer = false } = {}) {
    const fields = isServer
        ? [
            { name: 'Server today', value: `${guildUsage.requests} / ${settings.dailyGuildRequests} requests`, inline: true },
            { name: 'Tokens today', value: String(guildUsage.tokens || 0), inline: true },
        ]
        : [
            { name: 'Your usage today', value: `${userUsage.requests} / ${settings.dailyUserRequests} requests`, inline: true },
            { name: 'Your tokens today', value: String(userUsage.tokens || 0), inline: true },
            { name: 'Server today', value: `${guildUsage.requests} / ${settings.dailyGuildRequests} requests`, inline: true },
        ];
    return infoEmbed('AI usage', 'Free-tier usage is shared by every server, so daily limits keep it fair.', fields);
}

module.exports = {
    FOOTER,
    answerEmbed,
    infoEmbed,
    errorEmbed,
    warnEmbed,
    helpEmbed,
    statusEmbed,
    usageEmbed,
};
