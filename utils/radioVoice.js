/**
 * Thin wrapper around `@discordjs/voice` for the radio manager.
 *
 * Isolating the voice library behind this module lets the radio state machine
 * (utils/radioManager.js) be unit-tested with a mock — no real Discord gateway,
 * voice connection or ffmpeg process required. Every method here has a single,
 * obvious mapping onto the library API:
 *
 *   join()              → joinVoiceChannel + entersState(Ready)
 *   leave()             → connection.destroy()
 *   createPlayer()      → createAudioPlayer({ behaviors: { noSubscriber: Pause } })
 *   createResource()    → createAudioResource(url, { inputType: Arbitrary })
 *   playResource()      → player.play(resource)
 *   pausePlayer()       → player.pause()   (keeps the connection, keeps the track)
 *   stopPlayer()        → player.stop()
 *   subscribe()         → connection.subscribe(player)
 *
 * `noSubscriber: Pause` is the safety net that mirrors our own listener logic:
 * if the bot is somehow the only subscriber the player pauses rather than
 * blasting silence — but the authoritative pause/resume is driven by our
 * voice-state handler so the behaviour is explicit and testable.
 */

let lib = null;
function voice() {
    if (!lib) lib = require('@discordjs/voice');
    return lib;
}

// discord.js ChannelType.GuildVoice === 2, GuildStageVoice === 13
const VOICE_CHANNEL_TYPES = new Set([2, 13]);

// How long to wait for the voice handshake (signalling → ready) before giving
// up. Read per call so tests and operators can tune it without a reload.
function readyTimeoutMs() {
    return Math.max(1000, parseInt(process.env.VOICE_READY_TIMEOUT_MS, 10) || 20000);
}

/** Destroy a guild's tracked voice connection even without a session reference. */
function destroyGuildConnection(guildId) {
    if (!guildId) return false;
    try {
        const { getVoiceConnection } = voice();
        const existing = getVoiceConnection(String(guildId));
        if (existing) { existing.destroy(); return true; }
    } catch (_) {}
    return false;
}

function isVoiceChannel(channel) {
    return !!channel && (VOICE_CHANNEL_TYPES.has(channel.type) || (typeof channel.isVoiceBased === 'function' && channel.isVoiceBased()));
}

/** Is this connection object currently usable (Ready)? */
function isConnectionActive(connection) {
    if (!connection) return false;
    try {
        const { VoiceConnectionStatus } = voice();
        return connection.state && connection.state.status === VoiceConnectionStatus.Ready;
    } catch (_) {
        return !!connection && connection.state && connection.state.status === 'ready';
    }
}

function getConnectionState(connection) {
    if (!connection) return { connected: false, status: 'destroyed' };
    const status = connection.state ? connection.state.status : 'unknown';
    return { connected: status === 'ready', status };
}

/**
 * Join a voice channel and resolve once the connection is Ready. `onDisconnect`
 * is called when the connection drops so the manager can schedule a reconnect
 * (never when the channel merely empties — that is a state, not a disconnect).
 */
async function join({ client, guildId, channelId, onDisconnect }) {
    const { joinVoiceChannel, entersState, VoiceConnectionStatus } = voice();
    const guild = client.guilds.cache.get(guildId);
    const channel = guild && guild.channels.cache.get(channelId);
    if (!channel) throw new Error(`Voice channel ${channelId} not found in guild ${guildId}`);

    // A join issued while the shard is not Ready is silently dropped by
    // discord.js (AdapterUnavailable) and can only ever fail — wait for the
    // shard first, e.g. right after a node restart.
    const { waitForShardReady } = require('../voiceReadiness');
    if (!(await waitForShardReady(client, guildId))) {
        const shardStatus = guild && guild.shard && guild.shard.status;
        console.error(`[VOICE] guild=${guildId} channel=${channelId} aborted before join — shard not Ready (status=${shardStatus})`);
        throw new Error(`Voice shard is not ready (status=${shardStatus}) — the connection was not attempted.`);
    }

    const timeoutMs = readyTimeoutMs();
    const connection = joinVoiceChannel({
        channelId,
        guildId,
        adapterCreator: guild.voiceAdapterCreator,
        ...require('./voiceDefense').JOIN_OPTIONS,
    });

    if (typeof connection.on === 'function') {
        connection.on('stateChange', (oldState, newState) => {
            console.log(`[VOICE] guild=${guildId} channel=${channelId} ${oldState.status} -> ${newState.status}`);
        });
    }
    if (typeof onDisconnect === 'function') {
        connection.on(VoiceConnectionStatus.Disconnected, () => onDisconnect());
    }

    const statusBefore = connection.state && connection.state.status;
    try {
        await entersState(connection, VoiceConnectionStatus.Ready, timeoutMs);
    } catch (err) {
        // A failed ready handshake is recoverable — but report the real reason
        // (timeout vs cancellation) and destroy the half-open connection first
        // so it cannot wedge the guild for every later join.
        const statusAfter = connection.state && connection.state.status;
        const aborted = err && (err.name === 'AbortError' || err.code === 'ABORT_ERR');
        const reason = aborted
            ? `timed out after ${timeoutMs}ms (status stayed '${statusAfter}')`
            : `${err && err.name}: ${err && err.message}`;
        console.error(`[VOICE] guild=${guildId} channel=${channelId} connect FAILED — ${reason} [${statusBefore} -> ${statusAfter}]`);
        if (!aborted && err && err.stack) console.error(`[VOICE] original error:\n${err.stack}`);
        try { connection.destroy(); } catch (_) {}
        const out = new Error(`Voice connection did not become ready: ${reason}`);
        out.cause = err;
        out.voiceState = { guildId, channelId, statusBefore, statusAfter, timeoutMs, aborted };
        throw out;
    }
    // Voice defense: the bot is always self-deafened. `selfDeaf: true` above
    // already requests it; this re-asserts it right after the handshake so the
    // defended state holds even if the join request was adjusted server-side.
    require('./voiceDefense').defendGuild(client, guildId).catch(() => {});
    return connection;
}

function leave(connection) {
    if (!connection) return;
    try { connection.destroy(); } catch (_) {}
}

function createPlayer({ onError, onIdle, onStateChange } = {}) {
    const { createAudioPlayer, NoSubscriberBehavior, AudioPlayerStatus } = voice();
    const player = createAudioPlayer({ behaviors: { noSubscriber: NoSubscriberBehavior.Pause } });
    if (typeof onError === 'function') player.on('error', onError);
    if (typeof onIdle === 'function') {
        player.on(AudioPlayerStatus.Idle, () => onIdle());
    }
    if (typeof onStateChange === 'function') {
        player.on('stateChange', (oldState, newState) => onStateChange(oldState.status, newState.status));
    }
    return player;
}

/**
 * Build an audio resource from a resolved stream URL. The URL is a short-lived
 * SoundCloud CDN link (HLS `.m3u8` or progressive MP3) that ffmpeg reads
 * directly. `metadata.track` is attached so the track can be identified later.
 */
function createResource(streamUrl, { track } = {}) {
    const { createAudioResource, StreamType } = voice();
    return createAudioResource(streamUrl, {
        inputType: StreamType.Arbitrary,
        metadata: track ? { track } : undefined,
    });
}

function playResource(player, resource) {
    if (!player) throw new Error('playResource: no player');
    player.play(resource);
}

function pausePlayer(player) {
    if (!player) return;
    try {
        const { AudioPlayerStatus } = voice();
        if (player.state && player.state.status !== AudioPlayerStatus.Idle) player.pause();
    } catch (_) {}
}

function stopPlayer(player) {
    if (!player) return;
    try { player.stop(); } catch (_) {}
}

function destroyPlayer(player) {
    if (!player) return;
    try { player.stop(true); } catch (_) {}
}

function subscribe(connection, player) {
    if (!connection || !player) return null;
    try { return connection.subscribe(player); } catch (_) { return null; }
}

function setVolume(player, volume) {
    if (!player) return;
    try {
        if (player.state && player.state.resource && player.state.resource.volume) {
            player.state.resource.volume.setVolume(volume);
        }
    } catch (_) {}
}

module.exports = {
    voice,
    isVoiceChannel,
    isConnectionActive,
    getConnectionState,
    destroyGuildConnection,
    join,
    leave,
    createPlayer,
    createResource,
    playResource,
    pausePlayer,
    stopPlayer,
    destroyPlayer,
    subscribe,
    setVolume,
    VOICE_CHANNEL_TYPES,
};
