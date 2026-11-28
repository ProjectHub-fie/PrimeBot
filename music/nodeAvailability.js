/**
 * Lavalink node availability — the single "is music usable right now?" check.
 *
 * Lives in its own module (not `music/index.js`) so the player-manager loader
 * can guard `createPlayer` without a circular require, and so the command
 * runners share one definition of "unavailable".
 */

const { getMusicConfig, DEFAULT_NODE_NAME } = require('./config');
const { stateName } = require('./nodeDiagnostics');

/** Error code for "no Lavalink node is connected" — never a provider stack trace. */
const NODE_UNAVAILABLE = 'MUSIC_NODE_UNAVAILABLE';

/** Shoukaku `State.CONNECTED`. */
const STATE_CONNECTED = 1;

function listNodes(client) {
    const nodes = client && client.manager && client.manager.shoukaku && client.manager.shoukaku.nodes;
    return nodes ? [...nodes.values()] : [];
}

/** True when at least one registered node is CONNECTED. */
function hasUsableNode(client) {
    return listNodes(client).some(n => Number(n.state) === STATE_CONNECTED);
}

/** The configured audio-node name (`LNODE` unless LAVALINK_NAME overrides it). */
function configuredNodeName() {
    try {
        const nodes = getMusicConfig().nodes;
        return (nodes[0] && nodes[0].name) || DEFAULT_NODE_NAME;
    } catch (_) {
        return DEFAULT_NODE_NAME;
    }
}

/**
 * A typed, user-safe "music is unavailable" error, carrying the sanitized node
 * state for logs. Thrown *before* Kazagumo touches voice, so a missing node
 * never joins a channel or creates a player.
 */
function nodeUnavailableError(client, status = null) {
    const name = configuredNodeName();
    const err = new Error(
        `Music is temporarily unavailable — the audio node \`${name}\` isn't connected yet.`,
    );
    err.code = NODE_UNAVAILABLE;
    err.nodeName = name;
    err.nodeStatus = status;
    return err;
}

/** Recognises both our typed error and Kazagumo's raw `No node found`. */
function isNodeUnavailableError(err) {
    if (!err) return false;
    if (err.code === NODE_UNAVAILABLE) return true;
    return /no node found/i.test(String(err.message || err));
}

/** One sanitized line describing the live node states (never a credential). */
function describeNodes(client) {
    try {
        const nodes = listNodes(client);
        if (!nodes.length) return 'none registered';
        return nodes.map(n => `${n.name}=${Number(n.state)}`).join(', ');
    } catch (_) {
        return 'unavailable';
    }
}

module.exports = {
    NODE_UNAVAILABLE,
    STATE_CONNECTED,
    listNodes,
    hasUsableNode,
    configuredNodeName,
    nodeUnavailableError,
    isNodeUnavailableError,
    describeNodes,
};
