const { pgTable, text, integer, timestamp, boolean, varchar, serial } = require('drizzle-orm/pg-core');
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
};