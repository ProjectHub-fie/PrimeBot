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
 *   transcodeStream() → ffmpeg subprocess (seek + REAL audio filters) → s16le PCM
 *   seekStream()      → transcodeStream with only a seek (kept for compatibility)
 *
 * `noSubscriber: Pause` is a safety net: if the bot is somehow the only
 * subscriber the player pauses rather than streaming into the void.
 *
 * Filtering is applied here, on the decoded PCM, using real ffmpeg `-af`
 * chains (utils/music/musicFilters.js). It is NOT an embed-only decoration.
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
        ...require('../voiceDefense').JOIN_OPTIONS,
    });

    // Log every state transition so a failed handshake is diagnosable from the
    // logs alone (which state it reached, and whether it was destroyed first).
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
        // Distinguish a real timeout from an intentional cancellation so the
        // operator sees what actually happened instead of a bare "The operation
        // was aborted". `entersState` aborts its OWN internal AbortController
        // when the timeout elapses, so `AbortError` here means the handshake
        // never reached Ready within the window.
        const statusAfter = connection.state && connection.state.status;
        const aborted = err && (err.name === 'AbortError' || err.code === 'ABORT_ERR');
        const reason = aborted
            ? `timed out after ${timeoutMs}ms (status stayed '${statusAfter}')`
            : `${err && err.name}: ${err && err.message}`;
        console.error(`[VOICE] guild=${guildId} channel=${channelId} connect FAILED — ${reason} [${statusBefore} -> ${statusAfter}]`);
        if (!aborted && err && err.stack) console.error(`[VOICE] original error:\n${err.stack}`);
        // Destroy the half-open connection before throwing. @discordjs/voice
        // keeps it registered for the guild otherwise, so every later
        // joinVoiceChannel() returns this same wedged object, and a later
        // /leave has no reference to destroy it.
        try { connection.destroy(); } catch (_) {}
        const out = new Error(`Voice connection did not become ready: ${reason}`);
        out.cause = err;
        out.voiceState = { guildId, channelId, statusBefore, statusAfter, timeoutMs, aborted };
        throw out;
    }
    // Voice defense: the bot is always self-deafened. `selfDeaf: true` above
    // already requests it; this re-asserts it right after the handshake so the
    // defended state holds even if the join request was adjusted server-side.
    require('../voiceDefense').defendGuild(client, guildId).catch(() => {});
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
 * Readable produced by transcodeStream).
 *
 * A `filter` id or explicit `filterArgs` (ffmpeg `-af` chain) routes the source
 * through ffmpeg so the audio is ACTUALLY processed — an empty chain streams
 * the provider URL directly (no needless transcode).
 */
function createResource(streamUrl, { track, seekSeconds = 0, filter = null, filterArgs = null } = {}) {
    const { createAudioResource, StreamType } = voice();
    const args = filterArgs || (filter ? require('./musicFilters').filterArgs(filter) : []);
    const needsTranscode = seekSeconds > 0 || (args && args.length > 0);
    const input = needsTranscode ? transcodeStream(streamUrl, { seekSeconds, filterArgs: args }) : streamUrl;
    return createAudioResource(input, {
        inputType: StreamType.Arbitrary,
        inlineVolume: true,
        metadata: track ? { track } : undefined,
    });
}

/**
 * Build the ffmpeg argument list for a transcode (seek and/or real audio
 * filters). Pure and exported so the filter wiring can be asserted without
 * spawning a process.
 */
function buildTranscodeArgs(sourceUrl, { seekSeconds = 0, filterArgs = [] } = {}) {
    const args = [];
    if (seekSeconds > 0) args.push('-ss', String(seekSeconds));
    args.push('-i', String(sourceUrl), '-vn');
    if (Array.isArray(filterArgs) && filterArgs.length) args.push(...filterArgs);
    args.push('-f', 's16le', '-ar', '48000', '-ac', '2', 'pipe:1');
    return args;
}

/** Produce a readable ffmpeg PCM stream, optionally seeking and/or filtering. */
function transcodeStream(sourceUrl, { seekSeconds = 0, filterArgs = [] } = {}) {
    const pass = new PassThrough();
    const args = buildTranscodeArgs(sourceUrl, { seekSeconds, filterArgs });
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

/** Produce a readable ffmpeg stream that starts at `seconds` into the source. */
function seekStream(sourceUrl, seconds) {
    return transcodeStream(sourceUrl, { seekSeconds: seconds });
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

/** The live playback position in ms (0 when unknown). */
function getPlaybackPosition(player) {
    if (!player) return 0;
    try {
        const pos = player.state && player.state.playbackDuration;
        return Number.isFinite(pos) ? pos : 0;
    } catch (_) { return 0; }
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
    transcodeStream,
    buildTranscodeArgs,
    seekStream,
    playResource,
    pausePlayer,
    resumePlayer,
    stopPlayer,
    destroyPlayer,
    subscribe,
    setVolume,
    getPlaybackPosition,
    VOICE_CHANNEL_TYPES,
};
