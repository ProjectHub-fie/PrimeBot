const { SlashCommandBuilder } = require('discord.js');
const { executeEventAction, REGISTRATION_MODES } = require('../utils/eventCommands');
const { EVENT_TYPES, EVENT_STATUSES } = require('../shared/eventConstants');

const typeChoices = EVENT_TYPES.map(t => ({ name: t.label, value: t.key }));

module.exports = {
    data: new SlashCommandBuilder()
        .setName('event')
        .setDescription('Create, join and manage community events')
        .setDefaultMemberPermissions('0')
        .addSubcommand(sub => sub
            .setName('create')
            .setDescription('Create a new event (organizers)')
            .addStringOption(o => o.setName('name').setDescription('Event name').setRequired(true).setMaxLength(100))
            .addStringOption(o => o.setName('start').setDescription('Start time — YYYY-MM-DD HH:MM (UTC) or ISO').setRequired(true))
            .addIntegerOption(o => o.setName('duration').setDescription('Duration in minutes (default 120)').setMinValue(5).setMaxValue(10080))
            .addStringOption(o => o.setName('description').setDescription('What the event is about').setMaxLength(2000))
            .addStringOption(o => o.setName('type').setDescription('Event type').addChoices(...typeChoices))
            .addChannelOption(o => o.setName('location').setDescription('Voice/stage channel for the event'))
            .addChannelOption(o => o.setName('announce').setDescription('Channel to post the announcement in'))
            .addIntegerOption(o => o.setName('max').setDescription('Maximum participants (blank = unlimited)').setMinValue(1).setMaxValue(10000))
            .addStringOption(o => o.setName('recurrence').setDescription('Repeat schedule')
                .addChoices({ name: 'Does not repeat', value: 'none' }, { name: 'Daily', value: 'daily' }, { name: 'Weekly', value: 'weekly' }, { name: 'Monthly', value: 'monthly' }))
            .addBooleanOption(o => o.setName('publish').setDescription('Publish immediately (default yes)')))
        .addSubcommand(sub => sub
            .setName('edit')
            .setDescription('Edit an event you manage')
            .addIntegerOption(o => o.setName('event').setDescription('Event id').setRequired(true).setMinValue(1))
            .addStringOption(o => o.setName('name').setDescription('New name').setMaxLength(100))
            .addStringOption(o => o.setName('description').setDescription('New description').setMaxLength(2000))
            .addStringOption(o => o.setName('start').setDescription('New start time — YYYY-MM-DD HH:MM (UTC) or ISO'))
            .addIntegerOption(o => o.setName('duration').setDescription('New duration in minutes').setMinValue(5).setMaxValue(10080))
            .addChannelOption(o => o.setName('location').setDescription('New voice/stage channel'))
            .addChannelOption(o => o.setName('announce').setDescription('New announcement channel'))
            .addIntegerOption(o => o.setName('max').setDescription('New maximum participants').setMinValue(1).setMaxValue(10000))
            .addStringOption(o => o.setName('recurrence').setDescription('Repeat schedule')
                .addChoices({ name: 'Does not repeat', value: 'none' }, { name: 'Daily', value: 'daily' }, { name: 'Weekly', value: 'weekly' }, { name: 'Monthly', value: 'monthly' }))
            .addStringOption(o => o.setName('registration').setDescription('Registration mode')
                .addChoices(...REGISTRATION_MODES.map(r => ({ name: r.label, value: r.key })))))
        .addSubcommand(sub => sub
            .setName('cancel')
            .setDescription('Cancel an event (organizers)')
            .addIntegerOption(o => o.setName('event').setDescription('Event id').setRequired(true).setMinValue(1))
            .addStringOption(o => o.setName('reason').setDescription('Reason shown to participants').setMaxLength(500)))
        .addSubcommand(sub => sub
            .setName('delete')
            .setDescription('Delete an event permanently (organizers)')
            .addIntegerOption(o => o.setName('event').setDescription('Event id').setRequired(true).setMinValue(1)))
        .addSubcommand(sub => sub
            .setName('list')
            .setDescription('List this server\'s events')
            .addStringOption(o => o.setName('status').setDescription('Filter by status')
                .addChoices({ name: 'All', value: 'all' }, ...EVENT_STATUSES.map(s => ({ name: s.label, value: s.key })))))
        .addSubcommand(sub => sub
            .setName('info')
            .setDescription('Show event details')
            .addIntegerOption(o => o.setName('event').setDescription('Event id (default: newest)')))
        .addSubcommand(sub => sub
            .setName('join')
            .setDescription('RSVP Going to an event')
            .addIntegerOption(o => o.setName('event').setDescription('Event id (default: newest)')))
        .addSubcommand(sub => sub
            .setName('leave')
            .setDescription('RSVP Not going / leave an event')
            .addIntegerOption(o => o.setName('event').setDescription('Event id (default: newest)')))
        .addSubcommand(sub => sub
            .setName('config')
            .setDescription('View or change event configuration (organizers)')
            .addIntegerOption(o => o.setName('event').setDescription('Event id (default: newest)'))
            .addChannelOption(o => o.setName('announce').setDescription('Announcement channel'))
            .addRoleOption(o => o.setName('manager_role').setDescription('Role allowed to manage events'))
            .addIntegerOption(o => o.setName('max').setDescription('Maximum participants').setMinValue(1).setMaxValue(10000))
            .addStringOption(o => o.setName('registration').setDescription('Registration mode')
                .addChoices(...REGISTRATION_MODES.map(r => ({ name: r.label, value: r.key })))))
        .addSubcommand(sub => sub
            .setName('reminders')
            .setDescription('Set which reminders are sent (organizers)')
            .addIntegerOption(o => o.setName('event').setDescription('Event id').setRequired(true).setMinValue(1))
            .addStringOption(o => o.setName('reminders').setDescription('Comma separated: 24h,1h,15m,5m (blank = none)'))),

    async execute(interaction, client) {
        const sub = interaction.options.getSubcommand();
        const guild = interaction.guild;
        if (!guild) {
            return interaction.reply({ content: 'Events can only be used inside a server.', ephemeral: true }).catch(() => {});
        }

        const params = {};
        if (sub === 'create') {
            params.name = interaction.options.getString('name');
            params.start = interaction.options.getString('start');
            params.duration = interaction.options.getInteger('duration');
            params.description = interaction.options.getString('description');
            params.type = interaction.options.getString('type');
            params.channel = interaction.options.getChannel('location')?.id || null;
            params.announceChannel = interaction.options.getChannel('announce')?.id || null;
            params.max = interaction.options.getInteger('max');
            params.recurrence = interaction.options.getString('recurrence');
            const publish = interaction.options.getBoolean('publish');
            params.publish = publish === null ? true : publish;
        } else if (sub === 'edit') {
            params.eventId = interaction.options.getInteger('event');
            params.name = interaction.options.getString('name');
            params.description = interaction.options.getString('description');
            params.start = interaction.options.getString('start');
            params.duration = interaction.options.getInteger('duration');
            params.channel = interaction.options.getChannel('location')?.id || null;
            params.announceChannel = interaction.options.getChannel('announce')?.id || null;
            params.max = interaction.options.getInteger('max');
            params.recurrence = interaction.options.getString('recurrence');
            params.registrationMode = interaction.options.getString('registration');
        } else if (sub === 'cancel') {
            params.eventId = interaction.options.getInteger('event');
            params.reason = interaction.options.getString('reason');
        } else if (sub === 'delete') {
            params.eventId = interaction.options.getInteger('event');
        } else if (sub === 'list') {
            params.status = interaction.options.getString('status');
        } else if (sub === 'info' || sub === 'join' || sub === 'leave') {
            params.eventId = interaction.options.getInteger('event');
        } else if (sub === 'config') {
            params.eventId = interaction.options.getInteger('event');
            params.announceChannel = interaction.options.getChannel('announce')?.id || null;
            params.managerRole = interaction.options.getRole('manager_role')?.id || null;
            params.max = interaction.options.getInteger('max');
            params.registrationMode = interaction.options.getString('registration');
        } else if (sub === 'reminders') {
            params.eventId = interaction.options.getInteger('event');
            params.reminders = interaction.options.getString('reminders');
        }

        await interaction.deferReply({ ephemeral: true }).catch(() => {});
        try {
            const result = await executeEventAction(client, {
                action: sub, guild, member: interaction.member, params,
            });
            const payload = { content: result.message || undefined, embeds: result.embed ? [result.embed] : undefined };
            await interaction.editReply(payload).catch(() => {});
        } catch (err) {
            console.error('[EVENT CMD] error:', err.message);
            await interaction.editReply({ content: `❌ ${err.message || 'Something went wrong.'}` }).catch(() => {});
        }
    },
};
