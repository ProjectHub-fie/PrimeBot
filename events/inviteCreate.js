// Invite Tracking: keep the persisted invite baseline in step with Discord so
// a newly created invite is never mis-read as a "use" on the next join.
module.exports = {
    name: 'inviteCreate',
    async execute(invite, client) {
        try {
            if (!invite || !invite.guild) return;
            if (client.inviteTracker?.handleInviteCreate) {
                await client.inviteTracker.handleInviteCreate(invite);
            }
        } catch (err) {
            console.error('[INVITE] inviteCreate failed:', err.message);
        }
    },
};
