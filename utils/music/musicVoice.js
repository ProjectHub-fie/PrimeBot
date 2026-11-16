/**
 * Thin wrapper around `@discordjs/voice` for the music engine.
 *
 * Mirrors utils/radioVoice.js (the radio keeps its own copy so the two features
 * stay independent) and adds seek + volume support:
 *
 *   join()            → joinVoiceChannel + entersState(Ready)
 *   leave()           → connection.destroy()
 *   createPlayer()    → createAudioPlayer({ behaviors: { noSubscriber: Pause } })
 *   createResource()  → createAudioResource(url|stream, { inputType: Arbitrary, inlineVolume: true })
 *   playResource()    → player.play(resource)
 *   pausePlayer()     → player.pause()   (keeps the connection, keeps the track)
 *   resumePlayer()    → player.unpause()
 *   stopPlayer()      → player.stop()
 *   subscribe()       → connection.subscribe(player)
 *   setVolume()       → resource.volume.setVolume()
 *   seekStream()      → ffmpeg subprocess with an -ss input seek
 *
 * `noSubscriber: Pause` is a safety net: if the bot is somehow the only
 * subscriber the player pauses rather than streaming into the void.
 */

const { spawn } = require('child_process');
const { PassThrough } = require('stream');

let lib = null;
function voice() {
    if (!lib) lib = require('@discordjs/voice');
    return lib;
}

let ffmpegPath = null;
function ffmpeg() {
    if (ffmpegPath === null) {
        try { ffmpegPath = require('ffmpeg-static'); } catch (_) { ffmpegPath = 'ffmpeg'; }
    }
    return ffmpegPath;
}

// discord.js ChannelType.GuildVoice === 2, GuildStageVoice === 13
const VOICE_CHANNEL_TYPES = new Set([2, 13]);

// How long to wait for the voice handshake (signalling → ready) before giving
// up. Read per call so tests and operators can tune it without a reload.
function readyTimeoutMs() {
    return Math.max(1000, parseInt(process.env.VOICE_READY_TIMEOUT_MS, 10) || 20000);
}

/**
 * Destroy a guild's tracked voice connection, even when we hold no reference to
 * it. A connection can be tracked without a session reference when a join
 * timed out (join() threw before the manager stored it) — /leave must still be
 * able to disconnect in that case.
 */
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

async function join({ client, guildId, channelId, onDisconnect }) {
    const { joinVoiceChannel, entersState, VoiceConnectionStatus } = voice();
    const guild = client.guilds.cache.get(guildId);
    const channel = guild && guild.channels.cache.get(channelId);
    if (!channel) throw new Error(`Voice channel ${channelId} not found in guild ${guildId}`);

    const connection = joinVoiceChannel({
        channelId,
        guildId,
        adapterCreator: guild.voiceAdapterCreator,
        selfDeaf: true,
        selfMute: false,
    });

    if (typeof onDisconnect === 'function') {
        connection.on(VoiceConnectionStatus.Disconnected, () => onDisconnect());
    }

    try {
        await entersState(connection, VoiceConnectionStatus.Ready, readyTimeoutMs());
    } catch (err) {
        // CRITICAL: destroy the half-open connection before throwing. If we do
        // not, @discordjs/voice keeps it registered for the guild, so every
        // later joinVoiceChannel() returns this same wedged object — which can
        // never become Ready. The manager also never stores it (join() threw),
        // so a later /leave or /247 disable has no reference to destroy and the
        // bot reports success while still sitting in the voice channel.
        try { connection.destroy(); } catch (_) {}
        throw new Error(`Voice connection did not become ready: ${err.message}`);
    }
    return connection;
}

function leave(connection, guildId = null) {
    // Destroy the specific connection if we have it, then sweep the registry so
    // a connection we lost track of (failed join, restarted manager) cannot
    // linger. Without the sweep the bot reports a successful leave while still
    // sitting in the voice channel.
    if (connection) { try { connection.destroy(); } catch (_) {} }
    destroyGuildConnection(guildId);
}

function createPlayer({ onError, onIdle, onStateChange } = {}) {
    const { createAudioPlayer, NoSubscriberBehavior, AudioPlayerStatus } = voice();
    const player = createAudioPlayer({ behaviors: { noSubscriber: NoSubscriberBehavior.Pause } });
    if (typeof onError === 'function') player.on('error', onError);
    if (typeof onIdle === 'function') player.on(AudioPlayerStatus.Idle, () => onIdle());
    if (typeof onStateChange === 'function') player.on('stateChange', (oldState, newState) => onStateChange(oldState.status, newState.status));
    return player;
}

/**
 * Build an audio resource. `streamUrl` is a short-lived provider URL (or a
 * Readable produced by seekStream). `inlineVolume` lets us set volume live.
 */
function createResource(streamUrl, { track, seekSeconds = 0 } = {}) {
    const { createAudioResource, StreamType } = voice();
    const input = seekSeconds > 0 ? seekStream(streamUrl, seekSeconds) : streamUrl;
    return createAudioResource(input, {
        inputType: StreamType.Arbitrary,
        inlineVolume: true,
        metadata: track ? { track } : undefined,
    });
}

/** Produce a readable ffmpeg stream that starts at `seconds` into the source. */
function seekStream(sourceUrl, seconds) {
    const pass = new PassThrough();
    const args = ['-ss', String(seconds), '-i', String(sourceUrl), '-vn', '-f', 's16le', '-ar', '48000', '-ac', '2', 'pipe:1'];
    let proc;
    try {
        proc = spawn(ffmpeg(), args, { stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (err) {
        pass.destroy(err);
        return pass;
    }
    proc.stdout.pipe(pass);
    proc.on('error', (err) => pass.destroy(err));
    // Clean up the subprocess if the consumer goes away.
    pass.on('close', () => { try { proc.kill('SIGKILL'); } catch (_) {} });
    pass._ffmpegProcess = proc;
    return pass;
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

function resumePlayer(player) {
    if (!player) return;
    try { player.unpause(); } catch (_) {}
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
        const res = player.state && player.state.resource;
        if (res && res.volume) res.volume.setVolume(Math.max(0, Math.min(1, volume / 100)));
    } catch (_) {}
}

module.exports = {
    voice,
    ffmpeg,
    isVoiceChannel,
    isConnectionActive,
    getConnectionState,
    destroyGuildConnection,
    join,
    leave,
    createPlayer,
    createResource,
    seekStream,
    playResource,
    pausePlayer,
    resumePlayer,
    stopPlayer,
    destroyPlayer,
    subscribe,
    setVolume,
    VOICE_CHANNEL_TYPES,
};
