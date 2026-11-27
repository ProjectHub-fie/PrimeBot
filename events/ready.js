const { ActivityType } = require("discord.js");
const { logServerActivity } = require('../utils/logUtils');
const { getFleetCounts, getFleetGuildCount, servesWholeFleet } = require('../utils/fleetStats');

module.exports = {
    name: "clientReady",
    once: true,
    // async: the ready log needs ONE REST round-trip for the fleet-wide server
    // count (a shard node's cache only holds its own guilds).
    async execute(client) {
        console.log(`Logged in as ${client.user.tag}!`);

        // Central custom-emoji catalog: fetch the emoji guilds + their `emoji
        // list` channels, validate every emoji against the live guild
        // collections, then cache. Non-blocking — a failed fetch leaves the
        // Unicode fallbacks in place and never stops the bot from serving.
        if (client.emojiManager && typeof client.emojiManager.start === 'function') {
            client.emojiManager.start(client)
                .then(() => {
                    if (typeof client.emojiManager.summary === 'function') {
                        console.log(client.emojiManager.summary());
                    }
                })
                .catch((err) => {
                    console.warn('[EMOJI] Startup catalog load failed:', err.message);
                });
        }

        // Giveaway checking will be started automatically by GiveawayManager after database initialization

        // Debug: List all registered slash commands
        console.log('\n===== SLASH COMMANDS DEBUG =====');
        console.log(`Commands collection size: ${client.commands.size}`);
        if (client.commands.size === 0) {
            console.log('WARNING: No commands are loaded in the collection!');
        } else {
            console.log('Registered commands:');
            client.commands.forEach((cmd, name) => {
                console.log(`- ${name}: ${cmd.data ? 'Has data' : 'No data'}, ${typeof cmd.execute === 'function' ? 'Has execute function' : 'No execute function'}`);
            });
        }
        console.log('=================================\n');

        // Set bot nickname for all guilds where possible (without detailed error logging)
        client.guilds.cache.forEach((guild) => {
            try {
                // Only attempt to set nickname if we have the right permissions
                if (guild.members?.me?.permissions?.has('ChangeNickname')) {
                    guild.members.me.setNickname("PrimeBot").catch(() => {
                        // Silent fail - this is not critical functionality
                    });
                }
            } catch (error) {
                // Ignore nickname errors - they're not critical
            }
        });

        // Set bot status
        const updateStatus = () => {
            // Active-active sharding: this process holds only its own shards, so
            // the presence must show the FLEET total (cached; refreshed from
            // Discord in the background — see utils/fleetStats.js).
            const serverCount = getFleetGuildCount(client);
            client.user.setPresence({
                activities: [
                    {
                        name: `${serverCount} servers | $help`,
                        type: ActivityType.Watching,
                    },
                ],
                status: "online",
            });
        };

        updateStatus();

        // Flagship slash commands surfaced on the bot's profile / "Apps" command
        // list. These are the commands every PrimeBot user should see first
        // when they open the bot's profile card. They are registered globally
        // via deploy-commands.js; here we just log the curated set on boot so
        // it is visible that the profile command list includes them.
        const PROFILE_COMMANDS = ['invite', 'help', 'lgiveway', 'lpoll', 'automod'];
        console.log('Bot profile flagship commands:', PROFILE_COMMANDS.join(', '));
        PROFILE_COMMANDS.forEach((name) => {
            const cmd = client.commands.get(name);
            if (!cmd) {
                console.warn(`[PROFILE] Expected command "${name}" is not loaded — it will not show on the bot profile.`);
            }
        });

        // Update activity every 5 minutes
        setInterval(updateStatus, 5 * 60 * 1000);

        // Fleet total first, this node's share second: a shard node's cache is
        // only its own guilds, and the ready log is what operators read.
        const fleet = await getFleetCounts(client, { force: true }).catch(() => null);
        const fleetSize = fleet ? fleet.guilds : client.guilds.cache.size;
        console.log(
            servesWholeFleet(client)
                ? `Bot is ready! Serving ${fleetSize} servers.`
                : `Bot is ready! Serving ${fleetSize} servers across the fleet (this node: ${client.guilds.cache.size}).`,
        );
        
        // Log server names for debugging
        logServerActivity(`This node (${client.guilds.cache.size} of ${fleetSize}) is serving:`);
        client.guilds.cache.forEach(guild => {
            logServerActivity(`- ${guild.name} (ID: ${guild.id}, Members: ${guild.memberCount})`);
        });

        // Private security audit: snapshot every guild (server name / owner /
        // member count) so a later guildDelete — which Discord may deliver with
        // partial data — can still report what was known. In-memory only, no DB.
        try {
            const securityAudit = require('../utils/securityAuditLogger').getSecurityAuditLogger();
            securityAudit.attach(client);
            securityAudit.verifyDestination().catch(() => {});
        } catch (err) {
            console.error('[SECURITY AUDIT] initialisation failed:', err.message);
        }

        // Start live poll checking system. The sweeps are adaptive: an expired poll
        // or giveaway is rare, so a fixed 60s scan kept Neon awake around the
        // clock for an almost-always-empty result. Both back off while nothing
        // is due and snap back to the fast interval when one is found (or when a
        // new poll/giveaway is created — see notifyActivity()).
        const { AdaptivePoller } = require('../utils/adaptivePoller');

        if (client.livePollManager) {
            console.log('Poll checking system started.');
            client._livePollPoller = new AdaptivePoller({
                name: 'LIVE POLLS',
                task: () => client.livePollManager.checkExpiredPolls(),
                initialMs: 60000,
            });
            client._livePollPoller.start();
        }

        // Start live giveaway checking system
        if (client.liveGiveawayManager) {
            console.log('Live giveaway checking system started.');
            client._liveGiveawayPoller = new AdaptivePoller({
                name: 'LIVE GIVEAWAYS',
                task: () => client.liveGiveawayManager.checkExpiredGiveaways(),
                initialMs: 60000,
            });
            client._liveGiveawayPoller.start();
        }

        // Event scheduler is self-driving (its own exec loop); just restore
        // schedules from the database on startup.
        if (client.eventManager && typeof client.eventManager.restore === 'function') {
            setTimeout(() => {
                client.eventManager.restore().catch(err =>
                    console.error('[EVENTS] Restore failed:', err.message)
                );
            }, 7000);
        }

        // Event Management (registration/reminders/announcements) restore.
        if (client.eventMgmtManager && typeof client.eventMgmtManager.restore === 'function') {
            setTimeout(() => {
                client.eventMgmtManager.restore().catch(err =>
                    console.error('[EVENTMGMT] Restore failed:', err.message)
                );
            }, 7500);
        }

        // Invite Tracking: load settings + invite baselines (persisted, so a
        // restart keeps history and never re-attributes an old join).
        if (client.inviteTracker && typeof client.inviteTracker.ready === 'function') {
            setTimeout(() => {
                client.inviteTracker.ready().catch(err =>
                    console.error('[INVITE] Restore failed:', err.message)
                );
            }, 7000);
        }

        // AI Assistant: ensure the tables/settings cache are ready and purge
        // expired sessions. Sessions themselves are persisted, so a restart
        // keeps an in-progress conversation.
        if (client.aiManager && typeof client.aiManager.ready === 'function') {
            setTimeout(() => {
                client.aiManager.ready().catch(err =>
                    console.error('[AI] Restore failed:', err.message)
                );
            }, 6500);
        }

        // Re-apply roles for persistent reaction-role menus so they survive
        // bot restarts and Discord reaction-cache evictions.
        if (client.reactionRoleManager && typeof client.reactionRoleManager.restorePersistentMenus === 'function') {
            // Defer slightly so guild caches are populated.
            setTimeout(() => {
                client.reactionRoleManager.restorePersistentMenus().catch(err =>
                    console.error('[REACTION ROLES] Restore failed:', err.message)
                );
            }, 5000);
        }

        // Restore ticket panels (re-bind live panel messages + open tickets).
        if (client.ticketPanelManager && typeof client.ticketPanelManager.restorePanels === 'function') {
            setTimeout(() => {
                client.ticketPanelManager.restorePanels().catch(err =>
                    console.error('[TICKETS] Restore failed:', err.message)
                );
            }, 6000);
        }

        // Restore 24/7 music sessions (the Linix `247` table): re-create a
        // player for every saved guild and re-join its voice channel. The voice
        // connection did NOT survive the restart, so it is recreated here.
        if (client.manager && typeof client.manager.players !== 'undefined') {
            setTimeout(() => {
                require('../music').restore247(client).catch(err =>
                    console.error('[MUSIC] Restore failed:', err.message)
                );
            }, 7000);
        }

        // Anti-Nuke readiness. The manager loads its own configuration cache in
        // its constructor; here we only log the per-guild permission state so a
        // misconfigured deployment (missing View Audit Log, or the
        // GuildModeration intent disabled) is visible on boot rather than
        // silently failing to detect anything. Detection itself is driven by
        // events/guildAuditLogEntryCreate.js + the index.js fallback listeners.
        if (client.antiNukeManager && typeof client.antiNukeManager.getPermissionReport === 'function') {
            setTimeout(() => {
                try {
                    let enabledGuilds = 0;
                    let withMissingPerms = 0;
                    client.guilds.cache.forEach(guild => {
                        try {
                            const settings = client.antiNukeManager.getSettings(guild.id);
                            if (!settings.enabled) return;
                            enabledGuilds++;
                            const report = client.antiNukeManager.getPermissionReport(guild);
                            if (!report.ok) {
                                withMissingPerms++;
                                console.warn(`[ANTINUKE] ${guild.name} (${guild.id}) is missing permissions: ${report.missing.join(', ')}`);
                            }
                        } catch (_) { /* one bad guild must not stop the sweep */ }
                    });
                    console.log(`[ANTINUKE] Ready — ${enabledGuilds} guild(s) protected${withMissingPerms ? `, ${withMissingPerms} with missing permissions` : ''}.`);
                } catch (err) {
                    console.error('[ANTINUKE] readiness check failed:', err.message);
                }
            }, 4000);
        }
    },
};
//
