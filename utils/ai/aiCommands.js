/**
 * Shared AI command logic.
 *
 * Slash commands, prefix commands and mention replies all call `runAiAction`
 * with the same canonical `options` object, so the behaviour, permissions,
 * cooldowns, quotas and memory are identical across every entry point. The
 * command layers only translate their transport (interaction vs message) into
 * this shape and send the returned plain-text content.
 */

const config = require('../../config');
const repo = require('../../server/aiRepo');
const {
    AI_LIMITS, AI_MODES, AI_PERSONALITIES, AI_LANGUAGES,
    personalityPrompt,
} = require('../../shared/aiConstants');
const { sanitizeUserText, chunkText } = require('./promptSafety');
const { resolveModel } = require('./freeModels');
const E = require('./aiEmbeds');

const ACTIONS = [
    'ask', 'chat', 'summarize', 'translate', 'explain', 'analyze',
    'personality', 'knowledge', 'memory', 'config', 'usage', 'reset', 'help',
];

function isAdminCtx(ctx) {
    return Boolean(ctx.isAdmin || ctx.member?.permissions?.has?.('ManageGuild'));
}

function adminRequired() {
    return { embeds: [E.warnEmbed('You need the **Manage Server** permission to use this AI action.')], ephemeral: true };
}

function aiError(result) {
    const messages = {
        disabled: 'The AI assistant is disabled in this server. An admin can enable it with `/ai config enabled true`.',
        channel: 'The AI assistant is not enabled in this channel.',
        role: 'You do not have an AI-allowed role in this server.',
        cooldown: `Please wait ${Math.ceil((result.retryAfterMs || 0) / 1000)}s before asking again.`,
        user_quota: 'You have reached your daily AI request limit. It resets at midnight UTC.',
        guild_quota: 'This server has reached its daily AI request limit. It resets at midnight UTC.',
        global_quota: 'The assistant has reached its shared daily limit. Please try again tomorrow.',
        vision_disabled: 'Image analysis is disabled in this server.',
        attachments_disabled: 'Attachments are disabled for the AI assistant in this server.',
        empty: 'Please include a question or some text.',
        not_configured: 'No AI provider is configured yet. The bot owner must set `GROQ_API_KEY` (or Gemini/OpenRouter).',
        unavailable: 'The AI assistant is temporarily unavailable — all free providers are busy. Please try again shortly.',
        vision_unavailable: 'Image analysis is temporarily unavailable — no free vision model is available right now.',
    };
    return { embeds: [E.errorEmbed(messages[result.reason] || result.message || 'The AI request failed.')], ephemeral: true };
}

function answer(result) {
    const first = E.answerText({ text: result.chunks?.[0] || result.text, provider: result.provider });
    const followUps = (result.chunks || []).slice(1);
    return { content: first, followUps };
}

function parseBool(value) {
    if (typeof value === 'boolean') return value;
    const v = String(value || '').toLowerCase();
    if (['true', 'on', 'yes', '1', 'enable', 'enabled'].includes(v)) return true;
    if (['false', 'off', 'no', '0', 'disable', 'disabled'].includes(v)) return false;
    return null;
}

function parseId(value) {
    const m = String(value || '').match(/(\d{15,22})/);
    return m ? m[1] : null;
}

function parseLanguage(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const byKey = AI_LANGUAGES.find(l => l.key.toLowerCase() === raw.toLowerCase());
    if (byKey) return byKey.key;
    const byLabel = AI_LANGUAGES.find(l => l.label.toLowerCase() === raw.toLowerCase());
    if (byLabel) return byLabel.key;
    return raw.slice(0, 40);
}

async function recentTranscript(ctx, count = 20) {
    if (typeof ctx.fetchRecentMessages !== 'function') return '';
    const messages = await ctx.fetchRecentMessages(count);
    return (messages || [])
        .slice()
        .reverse()
        .map(m => `${m.author?.username || 'user'}: ${sanitizeUserText(m.content, 500)}`)
        .filter(line => line.split(': ')[1])
        .join('\n')
        .slice(0, AI_LIMITS.contextChars);
}

function imageUrls(ctx, options = {}) {
    const urls = [];
    const push = (url) => {
        if (url && /^https:\/\//i.test(url) && !urls.includes(url)) urls.push(url);
    };
    if (options.imageUrl) push(options.imageUrl);
    for (const att of ctx.message?.attachments?.values?.() || []) {
        if (/^image\//i.test(att.contentType || '')) push(att.url);
    }
    const replied = ctx.repliedMessage;
    for (const att of replied?.attachments?.values?.() || []) {
        if (/^image\//i.test(att.contentType || '')) push(att.url);
    }
    return urls.slice(0, 2);
}

async function handleAsk(ctx, options, { useSession }) {
    const prompt = sanitizeUserText(options.question || options.text || options.message || '');
    if (!prompt) {
        return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai ${useSession ? 'chat' : 'ask'} <question>\``)], ephemeral: true };
    }
    const images = imageUrls(ctx, options);
    const result = await ctx.manager.chat({
        guildId: ctx.guildId,
        userId: ctx.userId,
        channelId: ctx.channelId,
        guildName: ctx.guildName,
        prompt,
        images,
        capability: images.length ? 'vision' : 'chat',
        useSession,
        maxTokens: 900,
    });
    return result.ok ? answer(result) : aiError(result);
}

async function handleSummarize(ctx, options) {
    let text = sanitizeUserText(options.text || '');
    if (!text) {
        const count = Math.min(50, Math.max(5, parseInt(options.count, 10) || 25));
        text = await recentTranscript(ctx, count);
    }
    if (!text) return { embeds: [E.warnEmbed('There is nothing to summarize here yet.')], ephemeral: true };
    const result = await ctx.manager.complete({
        guildId: ctx.guildId,
        guildName: ctx.guildName,
        system: 'You summarize Discord conversations. Produce 3-6 short bullet points, then one line of key takeaway. No preamble.',
        user: `<conversation>\n${text}\n</conversation>`,
        maxTokens: 600,
    });
    return result.ok ? answer(result) : aiError(result);
}

async function handleTranslate(ctx, options) {
    const language = parseLanguage(options.language);
    const text = sanitizeUserText(options.text || '');
    if (!language || !text) {
        return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai translate <language> <text>\``)], ephemeral: true };
    }
    const result = await ctx.manager.complete({
        guildId: ctx.guildId,
        guildName: ctx.guildName,
        system: `You are a professional translator. Translate the user's text into ${language}. Return only the translation, no commentary.`,
        user: `<text_to_translate>\n${text}\n</text_to_translate>`,
        maxTokens: 800,
    });
    return result.ok ? answer(result) : aiError(result);
}

async function handleExplain(ctx, options) {
    const text = sanitizeUserText(options.text || options.question || '');
    if (!text) {
        return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai explain <topic, code or error>\``)], ephemeral: true };
    }
    const result = await ctx.manager.complete({
        guildId: ctx.guildId,
        guildName: ctx.guildName,
        system: 'You explain things clearly for a Discord chat. Start with a one-sentence summary, then the details, then a short example when useful. Keep it concise.',
        user: `<explain_request>\n${text}\n</explain_request>`,
        maxTokens: 900,
    });
    return result.ok ? answer(result) : aiError(result);
}

async function handleAnalyze(ctx, options) {
    const images = imageUrls(ctx, options);
    const text = sanitizeUserText(options.text || options.question || '');
    if (!images.length && !text) {
        return {
            embeds: [E.warnEmbed(`Attach an image, reply to an image, or add text.\nUsage: \`${ctx.prefix || '/'}ai analyze [text] [image]\``)],
            ephemeral: true,
        };
    }
    if (images.length) {
        const result = await ctx.manager.chat({
            guildId: ctx.guildId,
            userId: ctx.userId,
            channelId: ctx.channelId,
            guildName: ctx.guildName,
            prompt: text || 'Describe this image in detail and point out anything important.',
            images,
            capability: 'vision',
            useSession: false,
            maxTokens: 900,
        });
        return result.ok ? answer(result) : aiError(result);
    }
    return handleExplain(ctx, { text });
}

async function handlePersonality(ctx, options) {
    if (!isAdminCtx(ctx)) return adminRequired();
    const preset = String(options.preset || '').toLowerCase();
    if (preset === 'custom') {
        const instructions = sanitizeUserText(options.instructions || '', AI_LIMITS.maxInstructions);
        if (!instructions) {
            return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai personality custom <instructions>\``)], ephemeral: true };
        }
        const settings = await ctx.manager.updateSettings(ctx.guildId, { personality: 'custom', customInstructions: instructions });
        return { embeds: [E.statusEmbed(settings, await ctx.manager.getProviderStatus())], ephemeral: true };
    }
    if (!AI_PERSONALITIES.some(p => p.key === preset)) {
        return {
            embeds: [E.warnEmbed('Choose one of: ' + AI_PERSONALITIES.map(p => `\`${p.key}\``).join(', '))],
            ephemeral: true,
        };
    }
    await ctx.manager.updateSettings(ctx.guildId, { personality: preset });
    return {
        embeds: [E.infoEmbed('AI personality updated', `The assistant now uses the **${preset}** personality.\n\n_${personalityPrompt(preset)}_`)],
        ephemeral: true,
    };
}

async function handleKnowledge(ctx, options) {
    if (!isAdminCtx(ctx)) return adminRequired();
    const sub = String(options.sub || 'list').toLowerCase();
    const guildId = ctx.guildId;

    if (sub === 'add') {
        const title = sanitizeUserText(options.title || '', AI_LIMITS.maxKnowledgeTitle);
        const content = sanitizeUserText(options.content || '', AI_LIMITS.maxKnowledgeContent);
        if (!title || !content) {
            return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai knowledge add <title> | <content>\``)], ephemeral: true };
        }
        const count = await repo.countKnowledge(guildId);
        if (count >= AI_LIMITS.maxKnowledgeEntries) {
            return { embeds: [E.warnEmbed(`The knowledge base is full (${AI_LIMITS.maxKnowledgeEntries} entries). Remove one first.`)], ephemeral: true };
        }
        const row = await repo.addKnowledge(guildId, {
            title, content,
            tags: sanitizeUserText(options.tags || '', 120),
            createdBy: ctx.userId,
        });
        return { embeds: [E.infoEmbed('Knowledge saved', `**${row.title}** was added to the server knowledge base.`)], ephemeral: true };
    }

    if (sub === 'remove' || sub === 'delete') {
        const id = parseInt(options.id, 10);
        if (!Number.isFinite(id)) return { embeds: [E.warnEmbed(`Usage: \`${ctx.prefix || '/'}ai knowledge remove <id>\``)], ephemeral: true };
        const removed = await repo.deleteKnowledge(guildId, id);
        return {
            embeds: [removed ? E.infoEmbed('Knowledge removed', `Entry #${id} was deleted.`) : E.warnEmbed(`No knowledge entry #${id}.`)],
            ephemeral: true,
        };
    }

    const entries = await repo.listKnowledge(guildId, { limit: AI_LIMITS.maxKnowledgeEntries });
    if (!entries.length) {
        return {
            embeds: [E.infoEmbed('Knowledge base', `No entries yet.\nAdd one with \`${ctx.prefix || '/'}ai knowledge add <title> | <content>\`.`)],
            ephemeral: true,
        };
    }
    const lines = entries.map(e => `**#${e.id}** ${e.title}${e.tags ? ` _(${e.tags})_` : ''}\n${e.content.slice(0, 140)}${e.content.length > 140 ? '…' : ''}`);
    return { embeds: [E.infoEmbed('Server knowledge', lines.join('\n\n').slice(0, 3800))], ephemeral: true };
}

async function handleMemory(ctx, options) {
    const sub = String(options.sub || 'show').toLowerCase();

    if (sub === 'clear' || sub === 'clear-all') {
        const targetId = parseId(options.target);
        if (sub === 'clear-all') {
            if (!isAdminCtx(ctx)) return adminRequired();
            const removed = await ctx.manager.clearGuildSessions(ctx.guildId);
            return { embeds: [E.infoEmbed('Memory cleared', `Removed **${removed}** conversation session(s) for this server.`)], ephemeral: true };
        }
        if (targetId && targetId !== ctx.userId) {
            if (!isAdminCtx(ctx)) return adminRequired();
            await ctx.manager.resetSession(ctx.guildId, targetId);
            return { embeds: [E.infoEmbed('Memory cleared', `Cleared <@${targetId}>'s AI conversation.`)], ephemeral: true };
        }
        await ctx.manager.resetSession(ctx.guildId, ctx.userId);
        return { embeds: [E.infoEmbed('Memory cleared', 'Your AI conversation was reset.')], ephemeral: true };
    }

    const session = await repo.getSession(ctx.guildId, ctx.userId);
    if (!session) {
        return {
            embeds: [E.infoEmbed('AI memory', 'You have no active conversation. Start one with `/ai chat` or by mentioning the bot.')],
            ephemeral: true,
        };
    }
    const messages = await repo.getMessages(session.id, 6);
    const preview = messages.map(m => `**${m.role === 'assistant' ? 'PrimeBot' : 'You'}:** ${String(m.content).slice(0, 120)}`).join('\n');
    return {
        embeds: [E.infoEmbed('Your AI conversation', preview || 'No messages stored yet.', [
            { name: 'Messages', value: String(session.messageCount), inline: true },
            { name: 'Expires', value: `<t:${Math.floor(new Date(session.expiresAt).getTime() / 1000)}:R>`, inline: true },
        ])],
        ephemeral: true,
    };
}

async function handleConfig(ctx, options) {
    if (!isAdminCtx(ctx)) return adminRequired();
    const setting = String(options.setting || '').toLowerCase();
    const raw = options.value;
    const settings = ctx.manager.getSettings(ctx.guildId);

    // `$ai config` / `$ai settings` with no value shows the current configuration.
    if (!setting || setting === 'show' || setting === 'status') {
        return { embeds: [E.statusEmbed(settings, await ctx.manager.getProviderStatus())], ephemeral: true };
    }

    const patch = {};

    switch (setting) {
        case 'enabled': {
            const v = parseBool(raw);
            if (v == null) return { embeds: [E.warnEmbed('Usage: `/ai config enabled true|false`')], ephemeral: true };
            patch.enabled = v;
            break;
        }
        case 'mode': {
            const v = String(raw || '').toLowerCase();
            if (!AI_MODES.some(m => m.key === v)) return { embeds: [E.warnEmbed('Mode must be `mention` or `auto`.')], ephemeral: true };
            patch.mode = v;
            break;
        }
        case 'language': {
            const v = parseLanguage(raw);
            if (!v) return { embeds: [E.warnEmbed('Provide a language (e.g. `en`, `es`, `auto`).')], ephemeral: true };
            patch.language = v;
            break;
        }
        case 'personality': {
            const v = String(raw || '').toLowerCase();
            if (!AI_PERSONALITIES.some(p => p.key === v)) return { embeds: [E.warnEmbed('Unknown personality.')], ephemeral: true };
            patch.personality = v;
            break;
        }
        case 'channel': {
            const id = parseId(raw);
            if (!id) return { embeds: [E.warnEmbed('Mention a channel or provide its id.')], ephemeral: true };
            const list = new Set(settings.channelIds);
            if (String(raw).startsWith('-')) list.delete(id); else list.add(id);
            patch.channelIds = Array.from(list);
            break;
        }
        case 'role': {
            const id = parseId(raw);
            if (!id) return { embeds: [E.warnEmbed('Mention a role or provide its id.')], ephemeral: true };
            const list = new Set(settings.roleIds);
            if (String(raw).startsWith('-')) list.delete(id); else list.add(id);
            patch.roleIds = Array.from(list);
            break;
        }
        case 'clear_channels': patch.channelIds = []; break;
        case 'clear_roles': patch.roleIds = []; break;
        case 'max_length': patch.maxResponseChars = raw; break;
        case 'session_ttl': patch.sessionTtlMinutes = raw; break;
        case 'cooldown': patch.cooldownSeconds = raw; break;
        case 'daily_user': patch.dailyUserRequests = raw; break;
        case 'daily_guild': patch.dailyGuildRequests = raw; break;
        case 'knowledge': {
            const v = parseBool(raw);
            if (v == null) return { embeds: [E.warnEmbed('Usage: `/ai config knowledge true|false`')], ephemeral: true };
            patch.knowledgeEnabled = v;
            break;
        }
        case 'vision': {
            const v = parseBool(raw);
            if (v == null) return { embeds: [E.warnEmbed('Usage: `/ai config vision true|false`')], ephemeral: true };
            patch.visionEnabled = v;
            break;
        }
        default:
            return {
                embeds: [E.warnEmbed('Unknown setting. Use one of: `enabled`, `mode`, `language`, `personality`, `channel`, `role`, `clear_channels`, `clear_roles`, `max_length`, `session_ttl`, `cooldown`, `daily_user`, `daily_guild`, `knowledge`, `vision`.')],
                ephemeral: true,
            };
    }

    const next = await ctx.manager.updateSettings(ctx.guildId, patch);
    return { embeds: [E.statusEmbed(next, await ctx.manager.getProviderStatus())], ephemeral: true };
}

async function handleUsage(ctx, options) {
    const settings = ctx.manager.getSettings(ctx.guildId);
    const guildUsage = await repo.getGuildUsageToday(ctx.guildId);
    const sub = String(options.sub || '').toLowerCase();
    const targetId = parseId(options.target);
    const wantsServer = sub === 'server' || Boolean(targetId);

    if (wantsServer) {
        if (!isAdminCtx(ctx)) return adminRequired();
        if (targetId) {
            const userUsage = await repo.getUsageToday(ctx.guildId, targetId);
            return {
                embeds: [E.infoEmbed('AI usage', `<@${targetId}> used **${userUsage.requests}** request(s) today.`, [
                    { name: 'Server today', value: `${guildUsage.requests} / ${settings.dailyGuildRequests}`, inline: true },
                    { name: 'Tokens', value: String(userUsage.tokens || 0), inline: true },
                ])],
                ephemeral: true,
            };
        }
        return { embeds: [E.usageEmbed(null, guildUsage, settings, { isServer: true })], ephemeral: true };
    }

    const userUsage = await repo.getUsageToday(ctx.guildId, ctx.userId);
    return { embeds: [E.usageEmbed(userUsage, guildUsage, settings)], ephemeral: true };
}

async function handleReset(ctx) {
    await ctx.manager.resetSession(ctx.guildId, ctx.userId);
    return { embeds: [E.infoEmbed('Conversation reset', 'Your AI conversation memory was cleared. The next message starts fresh.')], ephemeral: true };
}

/**
 * Dispatch one AI action.
 * @param {string} action one of ACTIONS
 * @param {object} options canonical options
 * @param {object} ctx { manager, guildId, guildName, channelId, userId, member, isAdmin, message, prefix, ... }
 */
async function runAiAction(action, options, ctx) {
    const act = String(action || 'help').toLowerCase();
    if (!ACTIONS.includes(act)) {
        return { embeds: [E.warnEmbed(`Unknown action \`${act}\`. Try \`${ctx.prefix || '/'}ai help\`.`)], ephemeral: true };
    }
    try {
        switch (act) {
            case 'ask': return await handleAsk(ctx, options, { useSession: false });
            case 'chat': return await handleAsk(ctx, options, { useSession: true });
            case 'summarize': return await handleSummarize(ctx, options);
            case 'translate': return await handleTranslate(ctx, options);
            case 'explain': return await handleExplain(ctx, options);
            case 'analyze': return await handleAnalyze(ctx, options);
            case 'personality': return await handlePersonality(ctx, options);
            case 'knowledge': return await handleKnowledge(ctx, options);
            case 'memory': return await handleMemory(ctx, options);
            case 'config': return await handleConfig(ctx, options);
            case 'usage': return await handleUsage(ctx, options);
            case 'reset': return await handleReset(ctx);
            case 'help':
            default:
                return { embeds: [E.helpEmbed(ctx.prefix || '/')] };
        }
    } catch (err) {
        console.error('[AI] action failed:', err.message);
        return { embeds: [E.errorEmbed('Something went wrong while handling that AI request.')], ephemeral: true };
    }
}

// ── Prefix shortcuts ────────────────────────────────────────────────────────
//
// `$ai config <setting> <value>` is precise but long. These short forms map to
// the same settings so everyday configuration is one word:
//   $ai enable · $ai disable · $ai channel #general · $ai channels clear
//   $ai role @Member · $ai roles clear · $ai mode auto · $ai language es
//   $ai cooldown 5 · $ai limit 60 · $ai serverlimit 600 · $ai ttl 60
//   $ai length 1800 · $ai knowledge on · $ai vision off · $ai settings
const CONFIG_SHORTCUTS = Object.freeze({
    enable: 'enabled', on: 'enabled', disable: 'enabled', off: 'enabled',
    mode: 'mode',
    language: 'language', lang: 'language',
    channel: 'channel', channels: 'channel',
    role: 'role', roles: 'role',
    cooldown: 'cooldown',
    limit: 'daily_user', userlimit: 'daily_user',
    serverlimit: 'daily_guild', guildlimit: 'daily_guild',
    ttl: 'session_ttl', sessionttl: 'session_ttl',
    length: 'max_length', maxlength: 'max_length',
    knowledge: 'knowledge', vision: 'vision',
});

const CLEAR_WORDS = new Set(['clear', 'none', 'off', 'reset', 'remove']);

/**
 * Translate a short prefix form into `{ setting, value }`.
 * Returns null when the input is not a shortcut (so normal subcommands run).
 */
function parseAiShortcut(args = []) {
    const key = String(args[0] || '').toLowerCase();
    if (!key) return null;
    if (key === 'settings' || key === 'status') return { setting: 'show', value: null };

    const setting = CONFIG_SHORTCUTS[key];
    if (!setting) return null;

    const rest = args.slice(1);
    const value = rest.join(' ').trim();

    if (setting === 'enabled') {
        return { setting, value: (key === 'enable' || key === 'on') ? 'true' : 'false' };
    }

    if (setting === 'channel' || setting === 'role') {
        if (!value) return null;
        if (CLEAR_WORDS.has(value.toLowerCase())) {
            return { setting: setting === 'channel' ? 'clear_channels' : 'clear_roles', value: null };
        }
        return { setting, value };
    }

    // `knowledge`/`vision` are also subcommands (`$ai knowledge add …`), so only
    // treat them as the toggle when the value is clearly a boolean.
    if (setting === 'knowledge' || setting === 'vision') {
        return parseBool(value) == null ? null : { setting, value };
    }

    if (!value) return null;
    return { setting, value };
}

module.exports = {
    ACTIONS,
    runAiAction,
    parseAiShortcut,
    CONFIG_SHORTCUTS,
    parseBool,
    parseId,
    parseLanguage,
    imageUrls,
    recentTranscript,
    aiError,
    answer,
    aiDefaultModel: (provider) => resolveModel(provider),
    colors: config.colors,
    chunkText,
};
