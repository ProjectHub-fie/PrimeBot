const { pgTable, text, integer, timestamp, boolean, varchar, serial, jsonb } = require('drizzle-orm/pg-core');
const { relations } = require('drizzle-orm');

// Live polls table
const livePolls = pgTable('live_polls', {
  id: serial('id').primaryKey(),
  pollId: varchar('poll_id', { length: 100 }).notNull().unique(),
  passCode: varchar('pass_code', { length: 20 }).notNull(),
  question: text('question').notNull(),
  creatorId: varchar('creator_id', { length: 50 }).notNull(),
  isActive: boolean('is_active').default(true),
  allowMultipleVotes: boolean('allow_multiple_votes').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at'),
  messageId: varchar('message_id', { length: 50 }),
  channelId: varchar('channel_id', { length: 50 }),
});

// Live poll options table
const livePollOptions = pgTable('live_poll_options', {
  id: serial('id').primaryKey(),
  pollId: varchar('poll_id', { length: 100 }).notNull(),
  optionText: text('option_text').notNull(),
  optionIndex: integer('option_index').notNull(),
  voteCount: integer('vote_count').default(0),
});

// Live poll votes table
const livePollVotes = pgTable('live_poll_votes', {
  id: serial('id').primaryKey(),
  pollId: varchar('poll_id', { length: 100 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  optionIndex: integer('option_index').notNull(),
  votedAt: timestamp('voted_at').defaultNow(),
});

// Relations
const livePollsRelations = relations(livePolls, ({ many }) => ({
  options: many(livePollOptions),
  votes: many(livePollVotes),
}));

const livePollOptionsRelations = relations(livePollOptions, ({ one }) => ({
  poll: one(livePolls, {
    fields: [livePollOptions.pollId],
    references: [livePolls.pollId],
  }),
}));

const livePollVotesRelations = relations(livePollVotes, ({ one }) => ({
  poll: one(livePolls, {
    fields: [livePollVotes.pollId],
    references: [livePolls.pollId],
  }),
}));

// Regular polls table (unified with live polls system)
const polls = pgTable('polls', {
  id: serial('id').primaryKey(),
  messageId: varchar('message_id', { length: 50 }).notNull().unique(),
  channelId: varchar('channel_id', { length: 50 }).notNull(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  question: text('question').notNull(),
  creatorId: varchar('creator_id', { length: 50 }).notNull(),
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at'),
  ended: boolean('ended').default(false)
});

// Regular poll options table
const pollOptions = pgTable('poll_options', {
  id: serial('id').primaryKey(),
  pollId: varchar('message_id', { length: 50 }).notNull(),
  optionText: text('option_text').notNull(),
  optionIndex: integer('option_index').notNull(),
  emoji: varchar('emoji', { length: 10 }).notNull(),
  voteCount: integer('vote_count').default(0),
});

// Regular poll votes table
const pollVotes = pgTable('poll_votes', {
  id: serial('id').primaryKey(),
  pollId: varchar('message_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  optionIndex: integer('option_index').notNull(),
  votedAt: timestamp('voted_at').defaultNow(),
});

// Relations for regular polls
const pollsRelations = relations(polls, ({ many }) => ({
  options: many(pollOptions),
  votes: many(pollVotes),
}));

const pollOptionsRelations = relations(pollOptions, ({ one }) => ({
  poll: one(polls, {
    fields: [pollOptions.pollId],
    references: [polls.messageId],
  }),
}));

const pollVotesRelations = relations(pollVotes, ({ one }) => ({
  poll: one(polls, {
    fields: [pollVotes.pollId],
    references: [polls.messageId],
  }),
}));

// Giveaways table
const giveaways = pgTable('giveaways', {
  id: serial('id').primaryKey(),
  messageId: varchar('message_id', { length: 50 }).notNull().unique(),
  channelId: varchar('channel_id', { length: 50 }).notNull(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  prize: text('prize').notNull(),
  description: text('description'),
  winnerCount: integer('winner_count').default(1),
  hostId: varchar('host_id', { length: 50 }).notNull(),
  isActive: boolean('is_active').default(true),
  ended: boolean('ended').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  endsAt: timestamp('ends_at').notNull(),
});

// Giveaway participants table
const giveawayParticipants = pgTable('giveaway_participants', {
  id: serial('id').primaryKey(),
  giveawayId: varchar('giveaway_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  joinedAt: timestamp('joined_at').defaultNow(),
});

// Giveaway winners table
const giveawayWinners = pgTable('giveaway_winners', {
  id: serial('id').primaryKey(),
  giveawayId: varchar('giveaway_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  selectedAt: timestamp('selected_at').defaultNow(),
});

// Relations for giveaways
const giveawaysRelations = relations(giveaways, ({ many }) => ({
  participants: many(giveawayParticipants),
  winners: many(giveawayWinners),
}));

const giveawayParticipantsRelations = relations(giveawayParticipants, ({ one }) => ({
  giveaway: one(giveaways, {
    fields: [giveawayParticipants.giveawayId],
    references: [giveaways.messageId],
  }),
}));

const giveawayWinnersRelations = relations(giveawayWinners, ({ one }) => ({
  giveaway: one(giveaways, {
    fields: [giveawayWinners.giveawayId],
    references: [giveaways.messageId],
  }),
}));

// User levels table
const userLevels = pgTable('user_levels', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  xp: integer('xp').default(0),
  level: integer('level').default(0),
  messages: integer('messages').default(0),
  lastMessage: timestamp('last_message'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// User badges table
const userBadges = pgTable('user_badges', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  badgeId: varchar('badge_id', { length: 100 }).notNull(),
  badgeName: varchar('badge_name', { length: 255 }).notNull(),
  badgeEmoji: varchar('badge_emoji', { length: 10 }).notNull(),
  badgeColor: varchar('badge_color', { length: 50 }).notNull(),
  badgeDescription: text('badge_description').notNull(),
  badgeType: varchar('badge_type', { length: 50 }).notNull(),
  earnedAt: timestamp('earned_at').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

// Relations for leveling
const userLevelsRelations = relations(userLevels, ({ many }) => ({
  badges: many(userBadges),
}));

const userBadgesRelations = relations(userBadges, ({ one }) => ({
  user: one(userLevels, {
    fields: [userBadges.guildId, userBadges.userId],
    references: [userLevels.guildId, userLevels.userId],
  }),
}));

// Session storage table (for Replit Auth)
const sessions = pgTable('sessions', {
  sid: varchar('sid', { length: 255 }).primaryKey(),
  sess: text('sess').notNull(),
  expire: timestamp('expire').notNull(),
});

// User storage table (for Replit Auth)
const users = pgTable('users', {
  id: varchar('id', { length: 255 }).primaryKey(),
  email: varchar('email', { length: 255 }).unique(),
  firstName: varchar('first_name', { length: 255 }),
  lastName: varchar('last_name', { length: 255 }),
  profileImageUrl: varchar('profile_image_url', { length: 500 }),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Birthdays tables
const birthdaysGuilds = pgTable('birthdays_guilds', {
  guildId: varchar('guild_id', { length: 50 }).primaryKey(),
  announcementChannel: varchar('announcement_channel', { length: 50 }),
  roleId: varchar('role_id', { length: 50 }),
});

const birthdays = pgTable('birthdays', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  month: integer('month').notNull(),
  day: integer('day').notNull(),
  year: integer('year'),
  lastCelebrated: varchar('last_celebrated', { length: 50 }),
});

// Counting games table
const countingGames = pgTable('counting_games', {
  channelId: varchar('channel_id', { length: 50 }).primaryKey(),
  startNumber: integer('start_number').notNull().default(1),
  currentNumber: integer('current_number').notNull().default(0),
  goalNumber: integer('goal_number').notNull().default(100),
  lastUserId: varchar('last_user_id', { length: 50 }),
  highestNumber: integer('highest_number').notNull().default(0),
  failCount: integer('fail_count').notNull().default(0),
  participants: text('participants'), // JSON string of participant counts
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Beta settings table
const betaSettings = pgTable('beta_settings', {
  guildId: varchar('guild_id', { length: 50 }).primaryKey(),
  enabled: boolean('enabled').default(false).notNull(),
  allowed: boolean('allowed').default(false).notNull(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Server settings table (replaces serverSettings.json)
const serverSettings = pgTable('server_settings', {
  guildId: varchar('guild_id', { length: 50 }).primaryKey(),
  receiveBroadcasts: boolean('receive_broadcasts').default(true).notNull(),
  broadcastChannelId: varchar('broadcast_channel_id', { length: 50 }),
  welcomeEnabled: boolean('welcome_enabled').default(false).notNull(),
  welcomeChannelId: varchar('welcome_channel_id', { length: 50 }),
  welcomeMessage: text('welcome_message'),
  welcomeBannerUrl: text('welcome_banner_url'),
  welcomeColor: varchar('welcome_color', { length: 20 }),
  welcomeDmEnabled: boolean('welcome_dm_enabled').default(false).notNull(),
  welcomeDmMessage: text('welcome_dm_message'),
  welcomeShowMemberCount: boolean('welcome_show_member_count').default(true).notNull(),
  welcomeShowJoinDate: boolean('welcome_show_join_date').default(true).notNull(),
  welcomeShowAccountAge: boolean('welcome_show_account_age').default(true).notNull(),
  welcomeCustomTitle: varchar('welcome_custom_title', { length: 255 }),
  welcomeCustomFooter: varchar('welcome_custom_footer', { length: 255 }),
  levelingEnabled: boolean('leveling_enabled').default(true).notNull(),
  levelingChannelId: varchar('leveling_channel_id', { length: 50 }),
  xpMultiplier: integer('xp_multiplier').default(1),
  xpCooldown: integer('xp_cooldown').default(60000).notNull(),
  autoReactionsEnabled: boolean('auto_reactions_enabled').default(false).notNull(),
  autoReactions: text('auto_reactions').default('[]').notNull(),
  noPrefixUsers: text('no_prefix_users').default('{}').notNull(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Tickets table (replaces tickets.json)
const tickets = pgTable('tickets', {
  channelId: varchar('channel_id', { length: 50 }).primaryKey(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  category: varchar('category', { length: 50 }).default('general').notNull(),
  createdAt: integer('created_at').notNull(),
  closed: boolean('closed').default(false).notNull(),
  isThread: boolean('is_thread').default(false).notNull(),
  parentChannelId: varchar('parent_channel_id', { length: 50 }),
  controlMessageId: varchar('control_message_id', { length: 50 }),
  closedAt: integer('closed_at'),
  closedBy: varchar('closed_by', { length: 50 }),
  reopenedAt: integer('reopened_at'),
  reopenedBy: varchar('reopened_by', { length: 50 }),
});

// Reaction-role menus — a "menu" is a message the bot watches for reactions
// that grant roles. A menu has many reaction-role mappings (one emoji → role).
const reactionRoles = pgTable('reaction_roles', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  // The message the bot watches. For bot-created menus this is the message the
  // bot sent; for "attach to any message" menus it is an existing user message
  // referenced by channelId + messageId.
  channelId: varchar('channel_id', { length: 50 }).notNull(),
  messageId: varchar('message_id', { length: 50 }).notNull(),
  // A short label shown in the dashboard list (not the embed title).
  title: varchar('title', { length: 255 }),
  // The embed body the bot posts (for bot-created menus). Null when attaching
  // to an existing message.
  description: text('description'),
  color: varchar('color', { length: 20 }).default('#5865F2'),
  // Premium behavior modes:
  //  'normal'   — toggle: react adds role, unreact removes role (default)
  //  'sticky'   — react adds role and the bot removes the user's reaction but
  //               keeps the role (one-click assign, no toggle)
  //  'verify'   — react grants role once; unreacting does NOT remove it
  //               (good for "I have read the rules" gates)
  //  'unique'   — within the menu a member may hold only ONE role at a time;
  //               reacting to a new option swaps the role
  mode: varchar('mode', { length: 20 }).default('normal'),
  // When true the bot re-applies roles on startup by fetching the message's
  // current reactions (premium "persist" feature).
  persistent: boolean('persistent').default(true),
  // When true, bots are allowed to trigger the menu (off by default).
  includeBots: boolean('include_bots').default(false),
  // Optional role required before a member can use this menu (premium gating).
  requiredRoleId: varchar('required_role_id', { length: 50 }),
  // Optional role that is REMOVED when a member takes a role from this menu
  // (premium "mutually exclusive" support across menus).
  exclusiveRoleId: varchar('exclusive_role_id', { length: 50 }),
  // Who created the menu and when.
  createdBy: varchar('created_by', { length: 50 }),
  enabled: boolean('enabled').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Emoji → role mappings for a reaction-role menu.
const reactionRoleMappings = pgTable('reaction_role_mappings', {
  id: serial('id').primaryKey(),
  menuId: integer('menu_id').notNull(),
  // The emoji as the bot stores it: a unicode emoji (e.g. "🎉") or a custom
  // emoji reference string (e.g. "rolemoji:1234567890"). We store the raw
  // identifier used to compare against incoming reactions.
  emoji: varchar('emoji', { length: 100 }).notNull(),
  roleId: varchar('role_id', { length: 50 }).notNull(),
  // Optional per-mapping label shown in the embed field list.
  label: varchar('label', { length: 255 }),
  createdAt: timestamp('created_at').defaultNow(),
});

const reactionRolesRelations = relations(reactionRoles, ({ many }) => ({
  mappings: many(reactionRoleMappings),
}));

const reactionRoleMappingsRelations = relations(reactionRoleMappings, ({ one }) => ({
  menu: one(reactionRoles, {
    fields: [reactionRoleMappings.menuId],
    references: [reactionRoles.id],
  }),
}));

// Logging settings table (per-guild log channel + webhook + event toggles)
const loggingSettings = pgTable('logging_settings', {
  guildId: varchar('guild_id', { length: 50 }).primaryKey(),
  enabled: boolean('enabled').default(false).notNull(),
  channelId: varchar('channel_id', { length: 50 }),
  webhookUrl: text('webhook_url'),
  webhookName: varchar('webhook_name', { length: 100 }).default('PrimeBot Logs'),
  events: jsonb('events').default([]).notNull(),
  includeBots: boolean('include_bots').default(false).notNull(),
  color: varchar('color', { length: 20 }).default('#5865F2'),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Automod settings table (per-guild premium automod config)
const automodSettings = pgTable('automod_settings', {
  guildId: varchar('guild_id', { length: 50 }).primaryKey(),
  enabled: boolean('enabled').default(false).notNull(),
  logChannelId: varchar('log_channel_id', { length: 50 }),
  muteRoleId: varchar('mute_role_id', { length: 50 }),
  exemptRoleIds: jsonb('exempt_role_ids').default([]).notNull(),
  exemptChannelIds: jsonb('exempt_channel_ids').default([]).notNull(),
  rules: jsonb('rules').default([]).notNull(),
  warnThreshold: integer('warn_threshold').default(3).notNull(),
  warnAction: varchar('warn_action', { length: 20 }).default('timeout'),
  warnActions: jsonb('warn_actions').default(['timeout']).notNull(),
  dmEnabled: boolean('dm_enabled').default(true).notNull(),
  dmMessages: jsonb('dm_messages').default({}).notNull(),
  appealChannelId: varchar('appeal_channel_id', { length: 50 }),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Automod warnings ledger (per-guild-per-user)
const automodWarnings = pgTable('automod_warnings', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  moderatorId: varchar('moderator_id', { length: 50 }),
  reason: text('reason').default('').notNull(),
  ruleType: varchar('rule_type', { length: 40 }),
  createdAt: timestamp('created_at').defaultNow(),
});

// Automod appeals (members can appeal automod punishments)
const automodAppeals = pgTable('automod_appeals', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  action: varchar('action', { length: 20 }).notNull(),
  reason: text('reason').default('').notNull(),
  status: varchar('status', { length: 20 }).default('pending').notNull(),
  decisionNote: text('decision_note'),
  decidedBy: varchar('decided_by', { length: 50 }),
  decidedAt: timestamp('decided_at'),
  reversed: boolean('reversed').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

// Premium Ticket panels — configurable only from the dashboard. A "panel" is
// the message the bot posts (embed or plain) with an "Open Ticket" button;
// clicking it creates a ticket *instance* (a private channel/thread). Both the
// bot (utils/ticketPanelManager.js / utils/ticketManager.js) and the dashboard
// (dashboard/db.js) read/write these through the TICKET_DATABASE_URL pool
// (falls back to DATABASE_URL).
const ticketPanels = pgTable('ticket_panels', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  name: varchar('name', { length: 100 }).default('Support Ticket').notNull(),
  channelId: varchar('channel_id', { length: 50 }),
  messageId: varchar('message_id', { length: 50 }),
  messageType: varchar('message_type', { length: 20 }).default('embed').notNull(),
  title: varchar('title', { length: 255 }),
  description: text('description'),
  color: varchar('color', { length: 20 }).default('#5865F2'),
  thumbnailUrl: text('thumbnail_url'),
  imageUrl: text('image_url'),
  footerText: varchar('footer_text', { length: 255 }),
  content: text('content'),
  buttonLabel: varchar('button_label', { length: 80 }).default('Open Ticket').notNull(),
  buttonStyle: varchar('button_style', { length: 20 }).default('Primary').notNull(),
  buttonEmoji: varchar('button_emoji', { length: 100 }),
  category: varchar('category', { length: 50 }).default('general'),
  ticketName: varchar('ticket_name', { length: 100 }),
  supportRoleIds: jsonb('support_role_ids').default([]).notNull(),
  pingRoleIds: jsonb('ping_role_ids').default([]).notNull(),
  ticketCategoryId: varchar('ticket_category_id', { length: 50 }),
  cooldownSeconds: integer('cooldown_seconds').default(0).notNull(),
  maxOpenPerUser: integer('max_open_per_user').default(1).notNull(),
  askReason: boolean('ask_reason').default(false).notNull(),
  reasonPlaceholder: varchar('reason_placeholder', { length: 255 }),
  welcomeMessage: text('welcome_message'),
  closeButtonLabel: varchar('close_button_label', { length: 80 }).default('Close Ticket'),
  closeButtonEmoji: varchar('close_button_emoji', { length: 100 }),
  claimButtonLabel: varchar('claim_button_label', { length: 80 }),
  claimButtonEmoji: varchar('claim_button_emoji', { length: 100 }),
  // Ticket channel name templates per status (open/claimed/closed).
  openNameTemplate: varchar('open_name_template', { length: 100 }),
  claimedNameTemplate: varchar('claimed_name_template', { length: 100 }),
  closedNameTemplate: varchar('closed_name_template', { length: 100 }),
  enabled: boolean('enabled').default(true).notNull(),
  createdBy: varchar('created_by', { length: 50 }),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Per-ticket instances (a private channel/thread tied to a panel + opener).
const ticketInstances = pgTable('ticket_instances', {
  id: serial('id').primaryKey(),
  panelId: integer('panel_id'),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  channelId: varchar('channel_id', { length: 50 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  category: varchar('category', { length: 50 }).default('general'),
  isThread: boolean('is_thread').default(false).notNull(),
  parentChannelId: varchar('parent_channel_id', { length: 50 }),
  controlMessageId: varchar('control_message_id', { length: 50 }),
  reason: text('reason'),
  status: varchar('status', { length: 20 }).default('open').notNull(),
  claimedBy: varchar('claimed_by', { length: 50 }),
  createdAt: integer('created_at').notNull(),
  closedAt: integer('closed_at'),
  closedBy: varchar('closed_by', { length: 50 }),
  reopenedAt: integer('reopened_at'),
  reopenedBy: varchar('reopened_by', { length: 50 }),
});

const ticketPanelsRelations = relations(ticketPanels, ({ many }) => ({
  instances: many(ticketInstances),
}));

const ticketInstancesRelations = relations(ticketInstances, ({ one }) => ({
  panel: one(ticketPanels, {
    fields: [ticketInstances.panelId],
    references: [ticketPanels.id],
  }),
}));

// ── Live giveaways ──────────────────────────────────────────────────────────
// Cross-server giveaways created with $lgiveway / /lgiveway. Mirrors the live
// polls system (shareable via giveaway ID + pass code, joinable from any
// server), but lives in the dedicated LIVE_DATABASE_URL pool (falling back to
// DATABASE_URL). A live giveaway has participants and, when ended, winners.
const liveGiveaways = pgTable('live_giveaways', {
  id: serial('id').primaryKey(),
  giveawayId: varchar('giveaway_id', { length: 100 }).notNull().unique(),
  passCode: varchar('pass_code', { length: 20 }).notNull(),
  prize: text('prize').notNull(),
  description: text('description'),
  creatorId: varchar('creator_id', { length: 50 }).notNull(),
  winnerCount: integer('winner_count').default(1),
  isActive: boolean('is_active').default(true),
  ended: boolean('ended').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  endsAt: timestamp('ends_at'),
  messageId: varchar('message_id', { length: 50 }),
  channelId: varchar('channel_id', { length: 50 }),
});

const liveGiveawayParticipants = pgTable('live_giveaway_participants', {
  id: serial('id').primaryKey(),
  giveawayId: varchar('giveaway_id', { length: 100 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  joinedAt: timestamp('joined_at').defaultNow(),
});

const liveGiveawayWinners = pgTable('live_giveaway_winners', {
  id: serial('id').primaryKey(),
  giveawayId: varchar('giveaway_id', { length: 100 }).notNull(),
  userId: varchar('user_id', { length: 50 }).notNull(),
  selectedAt: timestamp('selected_at').defaultNow(),
});

const liveGiveawaysRelations = relations(liveGiveaways, ({ many }) => ({
  participants: many(liveGiveawayParticipants),
  winners: many(liveGiveawayWinners),
}));

const liveGiveawayParticipantsRelations = relations(liveGiveawayParticipants, ({ one }) => ({
  giveaway: one(liveGiveaways, {
    fields: [liveGiveawayParticipants.giveawayId],
    references: [liveGiveaways.giveawayId],
  }),
}));

const liveGiveawayWinnersRelations = relations(liveGiveawayWinners, ({ one }) => ({
  giveaway: one(liveGiveaways, {
    fields: [liveGiveawayWinners.giveawayId],
    references: [liveGiveaways.giveawayId],
  }),
}));

// ── Event management ────────────────────────────────────────────────────────
// Per-guild event schedules. Each schedule has an optional start countdown; a
// list of tasks (actions) to run at relative offsets (in seconds) from the
// event start — lock/unlock/hide/unhide channels, add/remove roles, or send a
// text/embed message. Lives in the dedicated EVENT_DATABASE_URL pool (falling
// back to DATABASE_URL). Configured from the dashboard's 📅 Events tab.
const eventSchedules = pgTable('event_schedules', {
  id: serial('id').primaryKey(),
  guildId: varchar('guild_id', { length: 50 }).notNull(),
  name: varchar('name', { length: 100 }).notNull(),
  description: text('description'),
  status: varchar('status', { length: 20 }).notNull().default('scheduled'),
  countdownSeconds: integer('countdown_seconds').default(0),
  startAt: timestamp('start_at'),
  triggered: boolean('triggered').default(false),
  enabled: boolean('enabled').default(true),
  createdById: varchar('created_by_id', { length: 50 }),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

const eventTasks = pgTable('event_tasks', {
  id: serial('id').primaryKey(),
  scheduleId: integer('schedule_id').notNull(),
  offsetSeconds: integer('offset_seconds').notNull().default(0),
  action: varchar('action', { length: 30 }).notNull(),
  targetType: varchar('target_type', { length: 20 }).default('channel'),
  targetIds: jsonb('target_ids').notNull().default([]),
  messageContent: text('message_content'),
  embedTitle: varchar('embed_title', { length: 255 }),
  embedDescription: text('embed_description'),
  embedColor: varchar('embed_color', { length: 20 }).default('#5865F2'),
  embedImageUrl: text('embed_image_url'),
  channelId: varchar('channel_id', { length: 50 }),
  executedAt: timestamp('executed_at'),
  createdAt: timestamp('created_at').defaultNow(),
});

const eventSchedulesRelations = relations(eventSchedules, ({ many }) => ({
  tasks: many(eventTasks),
}));

const eventTasksRelations = relations(eventTasks, ({ one }) => ({
  schedule: one(eventSchedules, {
    fields: [eventTasks.scheduleId],
    references: [eventSchedules.id],
  }),
}));

// Exports
module.exports = {
  livePolls,
  livePollOptions,
  livePollVotes,
  livePollsRelations,
  livePollOptionsRelations,
  livePollVotesRelations,
  polls,
  pollOptions,
  pollVotes,
  pollsRelations,
  pollOptionsRelations,
  pollVotesRelations,
  giveaways,
  giveawayParticipants,
  giveawayWinners,
  giveawaysRelations,
  giveawayParticipantsRelations,
  giveawayWinnersRelations,
  userLevels,
  userBadges,
  userLevelsRelations,
  userBadgesRelations,
  sessions,
  users
  ,
  birthdaysGuilds,
  birthdays,
  countingGames,
  betaSettings,
  serverSettings,
  tickets,
  reactionRoles,
  reactionRoleMappings,
  reactionRolesRelations,
  reactionRoleMappingsRelations,
  loggingSettings,
  automodSettings,
  automodWarnings,
  automodAppeals,
  ticketPanels,
  ticketInstances,
  ticketPanelsRelations,
  ticketInstancesRelations,
  liveGiveaways,
  liveGiveawayParticipants,
  liveGiveawayWinners,
  liveGiveawaysRelations,
  liveGiveawayParticipantsRelations,
  liveGiveawayWinnersRelations,
  eventSchedules,
  eventTasks,
  eventSchedulesRelations,
  eventTasksRelations,
};