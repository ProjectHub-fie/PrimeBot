/**
 * Auth middleware for the dashboard.
 *
 * The session (created by express-session) holds the Discord OAuth2 tokens
 * and the cached user object. This module attaches `req.user` and exposes
 * `requireAuth` / `requireGuildAdmin` guards.
 */

const discord = require('./discord');

function requireAuth(req, res, next) {
    if (req.session && req.session.user) {
        req.user = req.session.user;
        return next();
    }
    if (req.accepts('html')) {
        return res.redirect('/login');
    }
    return res.status(401).json({ error: 'Not authenticated' });
}

/**
 * Guard that loads the requested guild and verifies the logged-in user has
 * management rights over it (and the bot is a member). Attaches `req.guild`
 * on success.
 *
 * Strategy: pull the user's guild list from Discord (cached briefly in the
 * session) and check the permissions bitfield. Then confirm the bot is in the
 * guild via a bot-token REST call.
 */
async function requireGuildAdmin(req, res, next) {
    try {
        const guildId = req.params.guildId;
        if (!/^\d{17,20}$/.test(guildId)) {
            return res.status(400).json({ error: 'Invalid guild ID' });
        }

        const accessToken = req.session && req.session.accessToken;
        if (!accessToken) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        // Refresh the user's guild list if missing or stale (>10 min old).
        let guilds = req.session.guilds;
        const fetchedAt = req.session.guildsFetchedAt || 0;
        if (!Array.isArray(guilds) || Date.now() - fetchedAt > 10 * 60 * 1000) {
            guilds = await discord.getUserGuilds(accessToken);
            req.session.guilds = guilds;
            req.session.guildsFetchedAt = Date.now();
        }

        const userGuild = guilds.find(g => g.id === guildId);
        if (!userGuild || !discord.canManageGuild(userGuild.permissions)) {
            return res.status(403).json({ error: 'You do not have permission to manage this server.' });
        }

        // Confirm the bot is present in the guild. This uses the BOT token
        // (process.env.DISCORD_TOKEN), NOT the user's OAuth token, so a 401 here
        // means the bot token is missing/invalid — NOT that the user's session
        // expired. Destroying the session on a bot-token 401 would log the user
        // out for an unrelated reason, so we handle it separately below.
        let botGuild;
        try {
            botGuild = await discord.getBotGuild(guildId);
        } catch (err) {
            if (err.status === 401) {
                console.error('[AUTH] getBotGuild returned 401 — DISCORD_TOKEN is missing or invalid. Set DASHBOARD_BOT_TOKEN/DISCORD_TOKEN on Vercel.');
                return res.status(503).json({
                    error: 'PrimeBot is not reachable (bot token not configured). Ask an admin to set DISCORD_TOKEN on the dashboard deployment.',
                    reason: 'bot_token_unauthorized',
                });
            }
            if (err.status === 403 || err.status === 404) {
                return res.status(404).json({ error: 'PrimeBot is not in this server. Invite it first.' });
            }
            throw err;
        }

        req.guild = {
            id: botGuild.id,
            name: botGuild.name,
            icon: botGuild.icon,
            owner_id: botGuild.owner_id,
            approximate_member_count: botGuild.approximate_member_count,
            userIsOwner: userGuild.owner,
        };
        next();
    } catch (err) {
        console.error('[AUTH] requireGuildAdmin error:', err.message);
        // A 401 reaching here can only come from the user's OAuth access token
        // (getUserGuilds). That genuinely means the session expired — refresh it.
        if (err.status === 401) {
            req.session.destroy(() => {});
            if (req.accepts('html')) return res.redirect('/login');
            return res.status(401).json({ error: 'Session expired. Please log in again.' });
        }
        return res.status(500).json({ error: 'Failed to verify guild access.' });
    }
}

module.exports = { requireAuth, requireGuildAdmin };
