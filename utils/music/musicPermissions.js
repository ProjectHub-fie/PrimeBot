/**
 * Music permission model — "everyone with requester protection".
 *
 *   • Anyone in the bot's configured voice channel can request music.
 *   • A requester can remove/control their OWN active request.
 *   • DJ role holders, Manage Server holders and administrators can manage the
 *     entire queue and playback.
 *   • Users outside the voice channel cannot control playback by default.
 *   • Administrators configure music settings and 24/7 mode.
 *
 * Every check validates the guild + user identity passed in; it never trusts a
 * client-supplied guild id.
 */

const { PermissionsBitField } = require('discord.js');

function isAdmin(member) {
    if (!member) return false;
    try {
        return member.permissions.has(PermissionsBitField.Flags.ManageGuild)
            || member.permissions.has(PermissionsBitField.Flags.Administrator);
    } catch (_) { return false; }
}

function hasDjRole(member, djRoleId) {
    if (!member || !djRoleId) return false;
    try { return member.roles && member.roles.cache && member.roles.cache.has(djRoleId); }
    catch (_) { return false; }
}

function inChannel(member, channelId) {
    return !!(member && member.voice && member.voice.channelId && member.voice.channelId === channelId);
}

/**
 * Can this member control playback (pause/skip/stop/clear/shuffle/remove-any)?
 * Admins + DJ roles always can; otherwise the member must be in the music
 * channel.
 */
function canControl(member, session) {
    if (!member || !session) return false;
    if (isAdmin(member)) return true;
    if (hasDjRole(member, session.djRoleId)) return true;
    return inChannel(member, session.channelId);
}

/** Can this member remove the track at `position` (1-based) from the queue? */
function canRemoveTrack(member, session, position) {
    if (canControl(member, session)) return true;
    // A requester may remove their own queued track.
    const idx = Number(position) - 1;
    const track = session.queue && session.queue[idx];
    return !!(track && track.requesterId && member && track.requesterId === member.id);
}

/** Can this member configure music / 24/7 (admin only)? */
function canConfigure(member) {
    return isAdmin(member);
}

module.exports = { isAdmin, hasDjRole, inChannel, canControl, canRemoveTrack, canConfigure };
