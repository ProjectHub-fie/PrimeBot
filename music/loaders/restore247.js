/**
 * Linix `src/events/Node/ready.js` — reconnect every persisted 24/7 session.
 *
 * Preserved behaviour: on node ready, re-create a player for each saved
 * `247` row and re-join its voice channel. PrimeBot adaptation: it also
 * skips a guild this node does not hold (a standby shard node has no voice
 * state for it), so two nodes never fight over the same guild.
 */

const autoReconnect = require('../schema/247');

async function restoreAutoReconnect(client) {
    if (!client.manager) return 0;
    const rows = await autoReconnect.find({});
    let restored = 0;

    for (const data of rows) {
        const guild = client.guilds.cache.get(data.Guild);
        if (!guild) continue;

        const voice = guild.channels.cache.get(data.VoiceId);
        if (!voice) continue;

        const existing = client.manager.players.get(data.Guild);
        if (existing) {
            if (!existing.voiceId) existing.setVoiceChannel(data.VoiceId);
            if (!existing.textId) existing.setTextChannel(data.TextId);
            restored++;
            continue;
        }

        try {
            const player = await client.manager.createPlayer({
                guildId: data.Guild,
                voiceId: data.VoiceId,
                textId: data.TextId,
                deaf: true,
            });
            player.setVoiceChannel(data.VoiceId);
            player.setTextChannel(data.TextId);
            restored++;
        } catch (err) {
            console.error(`[MUSIC] 247 restore failed for guild ${data.Guild}:`, err.message);
        }
    }

    if (restored) client.logger.log(`Restored ${restored} 24/7 session(s)`, 'ready');
    return restored;
}

module.exports = { restoreAutoReconnect };
