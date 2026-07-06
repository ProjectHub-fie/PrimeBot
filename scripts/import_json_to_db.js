const fs = require('fs');
const path = require('path');
const { pool } = require('../server/db');

async function main() {
  const dataDir = path.join(__dirname, '../data');
  const birthdayPath = path.join(dataDir, 'birthdays.json');
  const countingPath = path.join(dataDir, 'counting.json');

  const summary = { guilds: 0, users: 0, countingChannels: 0 };

  try {
    // Run SQL migration if present to ensure tables exist
    try {
      const migrationPath = path.join(__dirname, '../migrations/0001_add_birthdays_counting.sql');
      if (fs.existsSync(migrationPath)) {
        const migrationSql = fs.readFileSync(migrationPath, 'utf8');
        // Execute migration SQL (split by semicolon to run statements separately)
        const statements = migrationSql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean);
        for (const stmt of statements) {
          if (!stmt) continue;
          await pool.query(stmt);
        }
        console.log('Migration executed (if tables were missing).');
      }
    } catch (merr) {
      console.error('Migration execution failed (continuing):', merr.message || merr);
    }
    if (fs.existsSync(birthdayPath)) {
      const raw = fs.readFileSync(birthdayPath, 'utf8').trim();
      if (raw) {
        const data = JSON.parse(raw);
        for (const [guildId, guildData] of Object.entries(data)) {
          await pool.query(
            `INSERT INTO birthdays_guilds (guild_id, announcement_channel, role_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (guild_id) DO UPDATE SET announcement_channel = EXCLUDED.announcement_channel, role_id = EXCLUDED.role_id`,
            [guildId, guildData.announcementChannel || null, guildData.role || null]
          );

          summary.guilds++;

          if (guildData.users) {
            for (const [userId, userData] of Object.entries(guildData.users)) {
              await pool.query(
                `INSERT INTO birthdays (guild_id, user_id, month, day, year, last_celebrated)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT DO NOTHING`,
                [guildId, userId, userData.month, userData.day, userData.year || null, userData.lastCelebrated || null]
              );
              summary.users++;
            }
          }
        }
      }
    } else {
      console.log('No birthdays.json found, skipping.');
    }

    if (fs.existsSync(countingPath)) {
      const raw = fs.readFileSync(countingPath, 'utf8').trim();
      if (raw) {
        const data = JSON.parse(raw);
        for (const [channelId, countData] of Object.entries(data)) {
          const participantsJson = JSON.stringify(countData.participants || {});
          await pool.query(
            `INSERT INTO counting_games (channel_id, start_number, current_number, goal_number, last_user_id, highest_number, fail_count, participants, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
             ON CONFLICT (channel_id) DO UPDATE SET start_number = EXCLUDED.start_number, current_number = EXCLUDED.current_number, goal_number = EXCLUDED.goal_number, last_user_id = EXCLUDED.last_user_id, highest_number = EXCLUDED.highest_number, fail_count = EXCLUDED.fail_count, participants = EXCLUDED.participants, updated_at = NOW()`,
            [channelId, countData.startNumber || 1, countData.currentNumber || 0, countData.goalNumber || 100, countData.lastUserId || null, countData.highestNumber || 0, countData.failCount || 0, participantsJson]
          );
          summary.countingChannels++;
        }
      }
    } else {
      console.log('No counting.json found, skipping.');
    }

    console.log('Import completed:', summary);
  } catch (err) {
    console.error('Import failed:', err);
  } finally {
    try {
      await pool.end();
    } catch (e) {
      // ignore
    }
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
