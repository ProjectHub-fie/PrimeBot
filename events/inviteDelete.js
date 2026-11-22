// Invite Tracking: a deleted invite is marked deleted (its historical uses
// stay in the join ledger) so it stops counting as an active invite.
module.exports = {
    name: 'inviteDelete',
    async execute(invite, client) {
        try {
            if (!invite || !invite.guild) return;
            if (client.inviteTracker?.handleInviteDelete) {
                await client.inviteTracker.handleInviteDelete(invite);
            }
        } catch (err) {
            console.error('[INVITE] inviteDelete failed:', err.message);
        }
    },
};
