const {
    SlashCommandBuilder, PermissionFlagsBits, MessageFlags,
} = require('discord.js');
const { runAiAction, aiError } = require('../utils/ai/aiCommands');
const { AI_PERSONALITIES } = require('../shared/aiConstants');

function managerFor(interaction) {
    return interaction.client?.aiManager || null;
}

function buildCtx(interaction, manager) {
    const member = interaction.member;
    const isAdmin = Boolean(interaction.memberPermissions?.has?.(PermissionFlagsBits.ManageGuild));
    return {
        manager,
        guildId: interaction.guildId,
        guildName: interaction.guild?.name || '',
        channelId: interaction.channelId,
        userId: interaction.user.id,
        username: interaction.user.username,
        member,
        isAdmin,
        prefix: '/',
        message: null,
        repliedMessage: null,
        fetchRecentMessages: async (count) => {
            if (!interaction.channel?.messages?.fetch) return [];
            const map = await interaction.channel.messages.fetch({ limit: Math.min(count, 100) });
            return Array.from(map.values());
        },
    };
}

function optionsFrom(interaction) {
    const get = (name) => {
        try { return interaction.options.getString(name); } catch (_) { return null; }
    };
    const getInt = (name) => {
        try { return interaction.options.getInteger(name); } catch (_) { return null; }
    };
    const getAttachment = (name) => {
        try { return interaction.options.getAttachment(name); } catch (_) { return null; }
    };
    const getUser = (name) => {
        try { return interaction.options.getUser(name); } catch (_) { return null; }
    };

    const subcommand = interaction.options.getSubcommand(false);
    const innerAction = get('action');
    const scope = get('scope');
    const sub = subcommand === 'memory' ? (innerAction === 'clear-member' ? 'clear' : (innerAction || 'show'))
        : subcommand === 'knowledge' ? (innerAction || 'list')
        : subcommand === 'usage' ? (scope || 'me')
        : subcommand;
    const image = getAttachment('image');
    return {
        sub,
        subcommand,
        question: get('question'),
        message: get('message'),
        text: get('text'),
        language: get('language'),
        count: getInt('count'),
        preset: get('preset'),
        instructions: get('instructions'),
        setting: get('setting'),
        value: get('value'),
        title: get('title'),
        content: get('content'),
        id: getInt('id'),
        tags: get('tags'),
        target: getUser('user')?.id || null,
        imageUrl: image?.url || null,
    };
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('ai')
        .setDescription('AI assistant — ask questions, chat, translate, summarize and analyse')
        .setDMPermission(false)
        .addSubcommand(s => s.setName('ask').setDescription('Ask a one-off question')
            .addStringOption(o => o.setName('question').setDescription('Your question').setRequired(true).setMaxLength(6000)))
        .addSubcommand(s => s.setName('chat').setDescription('Start or continue a conversation (keeps memory)')
            .addStringOption(o => o.setName('message').setDescription('Your message').setMaxLength(6000))
            .addAttachmentOption(o => o.setName('image').setDescription('Optional image to discuss')))
        .addSubcommand(s => s.setName('summarize').setDescription('Summarize recent messages or text')
            .addIntegerOption(o => o.setName('count').setDescription('How many recent messages (5-50)').setMinValue(5).setMaxValue(50))
            .addStringOption(o => o.setName('text').setDescription('Text to summarize instead')))
        .addSubcommand(s => s.setName('translate').setDescription('Translate text into another language')
            .addStringOption(o => o.setName('language').setDescription('Target language (e.g. English, es, Japanese)').setRequired(true))
            .addStringOption(o => o.setName('text').setDescription('Text to translate').setRequired(true).setMaxLength(6000)))
        .addSubcommand(s => s.setName('explain').setDescription('Explain a concept, code snippet or error')
            .addStringOption(o => o.setName('text').setDescription('What to explain').setRequired(true).setMaxLength(6000)))
        .addSubcommand(s => s.setName('analyze').setDescription('Analyze an image or text')
            .addAttachmentOption(o => o.setName('image').setDescription('Image to analyse'))
            .addStringOption(o => o.setName('text').setDescription('Question about the image, or text to analyse')))
        .addSubcommand(s => s.setName('personality').setDescription('Configure the assistant personality (Manage Server)')
            .addStringOption(o => o.setName('preset').setDescription('Personality preset').setRequired(true)
                .addChoices(...AI_PERSONALITIES.map(p => ({ name: p.label, value: p.key }))))
            .addStringOption(o => o.setName('instructions').setDescription('Custom instructions (with preset "custom")').setMaxLength(1500)))
        .addSubcommand(s => s.setName('knowledge').setDescription('Manage server knowledge (Manage Server)')
            .addStringOption(o => o.setName('action').setDescription('What to do').setRequired(true)
                .addChoices({ name: 'Add', value: 'add' }, { name: 'Remove', value: 'remove' }, { name: 'List', value: 'list' }))
            .addStringOption(o => o.setName('title').setDescription('Entry title (add)').setMaxLength(120))
            .addStringOption(o => o.setName('content').setDescription('Entry content (add)').setMaxLength(2000))
            .addStringOption(o => o.setName('tags').setDescription('Optional tags').setMaxLength(120))
            .addIntegerOption(o => o.setName('id').setDescription('Entry id (remove)').setMinValue(1)))
        .addSubcommand(s => s.setName('memory').setDescription('Show or clear AI conversation memory')
            .addStringOption(o => o.setName('action').setDescription('What to do')
                .addChoices({ name: 'Show mine', value: 'show' }, { name: 'Clear mine', value: 'clear' },
                    { name: 'Clear a member (Manage Server)', value: 'clear-member' }, { name: 'Clear all (Manage Server)', value: 'clear-all' }))
            .addUserOption(o => o.setName('user').setDescription('Member to clear (Manage Server)')))
        .addSubcommand(s => s.setName('config').setDescription('Configure AI settings (Manage Server)')
            .addStringOption(o => o.setName('setting').setDescription('Setting').setRequired(true)
                .addChoices(
                    { name: 'Enabled', value: 'enabled' }, { name: 'Mode', value: 'mode' },
                    { name: 'Language', value: 'language' }, { name: 'Personality', value: 'personality' },
                    { name: 'Allowed channel', value: 'channel' }, { name: 'Allowed role', value: 'role' },
                    { name: 'Clear channels', value: 'clear_channels' }, { name: 'Clear roles', value: 'clear_roles' },
                    { name: 'Max response length', value: 'max_length' }, { name: 'Session TTL (minutes)', value: 'session_ttl' },
                    { name: 'Cooldown (seconds)', value: 'cooldown' }, { name: 'Daily per-user limit', value: 'daily_user' },
                    { name: 'Daily per-server limit', value: 'daily_guild' }, { name: 'Knowledge enabled', value: 'knowledge' },
                    { name: 'Vision enabled', value: 'vision' }))
            .addStringOption(o => o.setName('value').setDescription('New value (prefix a channel/role id with "-" to remove)')))
        .addSubcommand(s => s.setName('usage').setDescription('Show AI usage statistics')
            .addStringOption(o => o.setName('scope').setDescription('Mine or server').addChoices(
                { name: 'Mine', value: 'me' }, { name: 'Server (Manage Server)', value: 'server' }))
            .addUserOption(o => o.setName('user').setDescription('Member usage (Manage Server)')))
        .addSubcommand(s => s.setName('reset').setDescription('Reset your AI conversation'))
        .addSubcommand(s => s.setName('help').setDescription('Show AI help')),

    async execute(interaction) {
        const manager = managerFor(interaction);
        if (!manager) {
            return interaction.reply({ content: 'The AI assistant is not available right now.', ephemeral: true });
        }
        const action = interaction.options.getSubcommand();
        const options = optionsFrom(interaction);
        const ctx = buildCtx(interaction, manager);

        const ephemeral = ['personality', 'knowledge', 'memory', 'config', 'usage', 'reset', 'help'].includes(action);
        await interaction.deferReply(ephemeral ? { flags: MessageFlags.Ephemeral } : {});

        // Channel/role gate for answer-producing actions only.
        if (['ask', 'chat', 'summarize', 'translate', 'explain', 'analyze'].includes(action)) {
            const access = manager.checkAccess({ guildId: ctx.guildId, channelId: ctx.channelId, member: ctx.member });
            if (!access.ok) {
                const payload = aiError({ reason: access.reason });
                return interaction.editReply({ embeds: payload.embeds });
            }
        }

        const result = await runAiAction(action, options, ctx);
        await interaction.editReply({
            embeds: result.embeds,
            allowedMentions: { parse: [] },
        });
        for (const chunk of result.followUps || []) {
            await interaction.followUp({ content: chunk, allowedMentions: { parse: [] } }).catch(() => {});
        }
    },
};
