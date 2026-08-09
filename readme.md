# Discord Bot Project

## Overview
A sophisticated Discord bot engineered for advanced community engagement, featuring a comprehensive ecosystem of interactive tools and community-building features.

## Stack
- Node.js backend
- Discord.js library
- PostgreSQL database with Drizzle ORM
- pg (node-postgres) driver for database connectivity
- 28+ fully deployed slash and prefix commands
- Advanced real-time server interaction mechanisms
- Modular command architecture with extensive plugin support
- Multi-server engagement tracking

## Recent Changes

### July 27, 2025 - Live Poll Winning Celebration System
✓ Added winning celebration messages for completed polls
✓ Created dynamic winner announcement embeds with random celebration emojis
✓ Implemented tie-breaker handling for multiple winners
✓ Updated poll end commands to show winners automatically
✓ Added celebration messages for expired polls with votes
✓ Enhanced user experience with festive winner announcements
✓ Fixed database schema issues with missing message_id and channel_id columns

### July 25, 2025 - Live Poll System Database Integration Fix
✓ Fixed live poll database initialization timing issues
✓ Updated LivePollManager to properly connect to PostgreSQL database
✓ Fixed all database operations to use correct database instances
✓ Added global database reference for consistent poll operations
✓ Poll results now display correctly after voting
✓ Status emoji updates properly reflect current poll state
✓ Voting system fully functional with persistent PostgreSQL storage

### July 24, 2025 - Database Setup & Button Fixes
✓ Configured PostgreSQL with Drizzle ORM
✓ Updated database schema for compatibility
✓ Added graceful database connection handling
✓ Updated environment configuration for PostgreSQL credentials
✓ Fixed button interaction errors (undefined 'action' variable)
✓ Restored full button functionality for all bot features
✓ Live poll system now fully operational with PostgreSQL backend

### July 23, 2025 - Live Poll System Implementation
✓ Added live poll system with `/lpoll` slash commands
✓ Created database schema for polls, options, and votes
✓ Implemented cross-server poll sharing with pass codes
✓ Added comprehensive poll management (create, join, results, end, list)
✓ Database integration with Drizzle ORM
✓ Interactive voting system with Discord buttons
✓ Added prefix command versions (`$lpoll`) with full functionality
✓ Integrated vote button handling in interaction events
✓ Fixed voting button functionality by removing duplicate handlers
✓ Hidden Poll ID and Pass Code from voting interface for cleaner UX

## Project Architecture

### Database Layer
- **PostgreSQL**: Main database for persistent data
- **pg (node-postgres)**: Database driver with Promise support
- **Drizzle ORM**: Type-safe database operations
- **Schema**: Located in `shared/schema.js`
  - `live_polls`: Poll metadata and settings
  - `live_poll_options`: Poll choices and vote counts
  - `live_poll_votes`: Individual vote records
- **Configuration**: Environment variables for PostgreSQL connection
  - `DATABASE_URL` (recommended) or individual vars: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- **Initialization**: Automated table creation via `server/init-db.js`

### Command System
- **Slash Commands**: Located in `commands/` directory
- **Prefix Commands**: Handled in `events/messageCreate.js`
- **Live Poll Commands**: Available as both slash and prefix commands
  - **Slash**: `/lpoll create|join|results|end|list`
  - **Prefix**: `$lpoll create|join|results|end|list`
  - Subcommands:
    - `create`: Create new cross-server polls
    - `join`: Join polls via ID or pass code
    - `results`: View poll results
    - `end`: End polls (creator only)
    - `list`: View user's created polls

### Utilities
- **LivePollManager**: `utils/livePollManager.js`
  - Poll creation and management
  - Vote processing and validation
  - Results calculation and display
  - Cross-server sharing capabilities

### Key Features
- **Pass Code System**: Secure poll sharing across servers
- **Vote Validation**: Prevents duplicate votes (configurable)
- **Expiration System**: Optional time-based poll expiration
- **Interactive UI**: Discord button integration for voting
- **Real-time Results**: Live vote count updates

## User Preferences
- Simple, everyday language for user communication
- Focus on functionality over technical details
- Comprehensive error handling and user feedback

## Database Setup Instructions

### PostgreSQL Configuration
1. **Environment Setup**: Copy `.env.example` to `.env` and configure:
   ```
   DATABASE_URL=postgresql://user:password@host:5432/database
   ```
   Or use individual variables:
   ```
   DB_HOST=your_database_host
   DB_PORT=5432
   DB_USER=your_database_user
   DB_PASSWORD=your_database_password
   DB_NAME=your_database_name
   ```

2. **Database Initialization**: Initialize tables directly:
   ```bash
   node server/init-db.js
   ```

### Fallback Mode
- Bot operates with memory-only storage when PostgreSQL is unavailable
- Live poll features gracefully degrade to temporary functionality
- Database connection attempts are retried automatically

## Next Steps
✓ Integrate live poll manager with main bot instance
✓ Add button interaction handlers for voting
✓ Add prefix command support
→ Test cross-server functionality
→ Validate poll expiration and cleanup systems

## Web Dashboard

PrimeBot ships with a standalone web dashboard that lets Discord server
admins configure the bot through a browser instead of slash commands.

### What it can do
- **Discord OAuth2 login** — admins sign in with Discord; only servers where
  they have *Manage Server* are listed.
- **Welcome system** — toggle welcome messages/DMs, set the channel, edit the
  message template, banner URL, embed color, and on-card extras (member count,
  join date, account age, custom title/footer).
- **Leveling & XP** — enable/disable leveling, set the level-up channel, tune
  the XP multiplier (0.1–5.0) and cooldown (5–300 s).
- **Command prefix** — set a per-server text-command prefix (max 3 chars).
- **Auto-reactions** — manage trigger-word → emoji rules with a master toggle.
- **Broadcasts** — opt in/out of official PrimeBot announcements and pick the
  channel.

Changes are written straight to the same PostgreSQL tables the bot reads
(`server_settings`, `welcome_settings`), so they take effect immediately — no
restart needed.

### Running it
```bash
npm run dashboard
```
The server listens on `DASHBOARD_PORT` (default `3000`).

### Required environment variables
Copy `.env.example` → `.env` and fill in:
- `DISCORD_TOKEN` — the bot token (used to look up guilds/channels).
- `DISCORD_CLIENT_ID` — the bot's application/client ID.
- `DISCORD_CLIENT_SECRET` — from the Discord Developer Portal → OAuth2.
- `SESSION_SECRET` — any long random string for signing session cookies.
- `DATABASE_URL` (and optionally `WELCOME_DATABASE_URL`) — same DBs the bot uses.

### OAuth2 redirect URI
Set `DISCORD_REDIRECT_URI` (or rely on the default
`<DASHBOARD_BASE_URL>/auth/callback`). Add this exact URL to your application's
**OAuth2 → Redirects** list in the Discord Developer Portal.

### How it fits alongside the bot
The dashboard is a separate process and does **not** need the bot running — it
talks directly to the database and Discord's REST API. Run them on the same
host or separately; both can run at once. Because settings live in PostgreSQL,
anything you change in the dashboard is picked up by the bot on its next
command/event.

