# Leveling System Documentation

## Overview
The Discord bot includes a robust leveling system that tracks user activity and rewards engagement with XP and levels. The system is fully customizable for each server and includes features like badges, leaderboards, and server-specific settings.

## User Commands

### Checking Rank/Profile
```
/leveling rank [user]
```
- Shows your level, XP, rank position, and progress toward the next level
- You can optionally specify another user to view their rank

### Viewing the Leaderboard
```
/leveling leaderboard [page]
```
- Displays the server's XP leaderboard, showing top members
- You can specify a page number if there are multiple pages

### Viewing Badges
```
/leveling badges [user]
```
- Shows your earned badges and available badges
- You can optionally specify another user to view their badges

## Admin Commands

### Managing Settings
```
/leveling settings setting:[option] [parameters]
```
Available settings:
- `enable` - Enable the leveling system for your server
- `disable` - Disable the leveling system for your server
- `channel` - Set a channel for level-up announcements (with the `channel` parameter)
- `multiplier` - Set an XP multiplier for your server (with the `value` parameter)
- `cooldown` - Set the XP gain cooldown in seconds (with the `value` parameter)
- `reset` - Reset all user XP data for your server (requires confirmation)

### Awarding XP
```
/leveling award user:[user] amount:[number]
```
- Award a specific amount of XP to a user
- Requires the Manage Server permission

### Awarding Badges
```
/leveling awardbadge user:[user] badgetype:[type] badgeid:[id]
```
- Award a special badge to a user
- Badge types: achievement, special
- Requires the Manage Server permission

## How XP Works
- Users earn XP by sending messages in the server
- The amount of XP earned depends on message length and server settings
- There's a cooldown between XP gains (configurable per server)
- Levels are calculated based on total messages and XP
- Server administrators can customize XP multipliers to adjust progression speed

## Badges
The system includes three types of badges:
1. **Level Badges** - Automatically awarded when reaching specific levels
2. **Achievement Badges** - Awarded by server administrators for specific accomplishments
3. **Special Badges** - Rare badges awarded by server administrators for exceptional contributions

## Server Configuration
Server administrators can customize:
- Whether leveling is enabled
- Where level-up announcements are sent
- XP multiplier (0.1x to 5.0x)
- XP cooldown (5 to 300 seconds)

## Example Usage
1. Enable leveling in your server:
   ```
   /leveling settings setting:enable
   ```

2. Set a dedicated channel for level-up announcements:
   ```
   /leveling settings setting:channel channel:#level-ups
   ```

3. Set a custom XP multiplier:
   ```
   /leveling settings setting:multiplier value:1.5
   ```

4. Award a special badge to a dedicated member:
   ```
   /leveling awardbadge user:@username badgetype:achievement badgeid:helper
   ```

## Tips for Server Owners
- Use the leveling system to encourage engagement in your community
- Consider setting up special roles at certain level milestones
- Award badges to recognize helpful or active members
- Promote the leaderboard to encourage friendly competition