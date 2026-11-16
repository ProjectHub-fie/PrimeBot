/**
 * Voice readiness helpers shared by the music and radio voice wrappers.
 *
 * discord.js's voice adapter (`Guild#voiceAdapterCreator`) drops the join
 * payload when the shard is not Ready:
 *
 *     sendPayload: data => {
 *       if (this.shard.status !== Status.Ready) return false;   // payload lost
 *       this.shard.send(data);
 *       return true;
 *     }
 *
 * `@discordjs/voice` treats a rejected payload as `AdapterUnavailable`
 * (`disconnected`) and still tracks the connection — so a join issued while the
 * shard is IDENTIFYING/RESUMING (i.e. immediately after a node restart) can
 * never reach Ready and only surfaces 20s later as
 * "Voice connection did not become ready: The operation was aborted".
 *
 * Waiting for the shard to be Ready first turns that silent, guaranteed
 * failure into a fast, clearly-reported one.
 */

/** How long to wait for the shard to become Ready before giving up. */
function shardReadyTimeoutMs() {
    return Math.max(1000, parseInt(process.env.VOICE_SHARD_READY_TIMEOUT_MS, 10) || 15000);
}

/**
 * Resolve once the guild's shard is Ready.
 *
 * Returns `true` when the shard is (or becomes) Ready, `false` on timeout or
 * when shard status is unavailable (a test double / partial client — in that
 * case the caller proceeds rather than blocking).
 */
async function waitForShardReady(client, guildId, { timeoutMs = shardReadyTimeoutMs() } = {}) {
    let Status;
    try { ({ Status } = require('discord.js')); } catch (_) { return true; }
    if (!Status || typeof Status.Ready === 'undefined') return true;

    const guild = client && client.guilds && client.guilds.cache && client.guilds.cache.get(guildId);
    const shard = guild && guild.shard;
    // No shard handle (test double or an unsharded mock) — do not block.
    if (!shard || typeof shard.status === 'undefined') return true;
    if (shard.status === Status.Ready) return true;

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 250));
        if (shard.status === Status.Ready) return true;
    }
    return shard.status === Status.Ready;
}

module.exports = { waitForShardReady, shardReadyTimeoutMs };
