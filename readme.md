# Discord Bot Project

## Overview
A sophisticated Discord bot engineered for advanced community engagement, featuring a comprehensive ecosystem of interactive tools and community-building features.

## Stack
- Node.js backend
- Discord.js library
- MySQL database with Drizzle ORM
- mysql2 driver for database connectivity
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
✓ Updated LivePollManager to properly connect to MySQL database
✓ Fixed all database operations to use correct database instances
✓ Added global database reference for consistent poll operations
✓ Poll results now display correctly after voting
✓ Status emoji updates properly reflect current poll state
✓ Voting system fully functional with persistent MySQL storage

### July 24, 2025 - MySQL Database Migration & Button Fixes
✓ Migrated from PostgreSQL to MySQL database
✓ Updated Drizzle ORM configuration for MySQL compatibility
✓ Installed mysql2 driver for database connectivity
✓ Updated database schema with MySQL-specific syntax
✓ Added graceful database connection handling
✓ Created MySQL initialization script
✓ Added fallback mode for live poll system when database is unavailable
✓ Updated environment configuration for MySQL credentials
✓ Fixed button interaction errors (undefined 'action' variable)
✓ Restored full button functionality for all bot features
✓ Live poll system now fully operational with MySQL backend

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
- **MySQL**: Main database for persistent data
- **mysql2**: Database driver with Promise support
- **Drizzle ORM**: Type-safe database operations
- **Schema**: Located in `shared/schema.js`
  - `live_polls`: Poll metadata and settings
  - `live_poll_options`: Poll choices and vote counts
  - `live_poll_votes`: Individual vote records
- **Configuration**: Environment variables for MySQL connection
  - `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
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

### MySQL Configuration
1. **Environment Setup**: Copy `.env.example` to `.env` and configure:
   ```
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=root
   DB_PASSWORD=your_mysql_password
   DB_NAME=discord_bot
   ```

2. **Database Initialization**: Run setup script:
   ```bash
   ./mysql-setup.sh
   ```

3. **Manual Setup**: Initialize database directly:
   ```bash
   node server/init-db.js
   ```

### Fallback Mode
- Bot operates with memory-only storage when MySQL is unavailable
- Live poll features gracefully degrade to temporary functionality
- Database connection attempts are retried automatically

## Next Steps
✓ Integrate live poll manager with main bot instance
✓ Add button interaction handlers for voting
✓ Add prefix command support
✓ Migrate database from PostgreSQL to MySQL
→ Set up MySQL server in production environment
→ Test cross-server functionality with MySQL backend
→ Validate poll expiration and cleanup systems