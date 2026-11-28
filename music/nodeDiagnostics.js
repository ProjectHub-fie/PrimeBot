/**
 * Sanitized Lavalink node diagnostics.
 *
 * Every string this module produces is safe to log: it describes the node
 * (host, port, TLS, whether a password is configured) and never the password
 * itself. The helpers are pure so they can be unit-tested without a socket.
 */

/** Shoukaku `State` enum (v4): 0 CONNECTING, 1 CONNECTED, 2 DISCONNECTING, 3 DISCONNECTED. */
const STATE_NAMES = {
    0: 'CONNECTING',
    1: 'CONNECTED',
    2: 'DISCONNECTING',
    3: 'DISCONNECTED',
};

function stateName(state) {
    if (state === null || state === undefined || state === '') return 'unknown';
    const n = Number(state);
    return Object.prototype.hasOwnProperty.call(STATE_NAMES, n) ? STATE_NAMES[n] : `unknown(${state})`;
}

/**
 * Split Shoukaku's bare `host:port` url (or a full ws/wss/http(s) URL) into its
 * parts. Returns `port: null` when the value carries no port — a bare host
 * silently dials :80, which is a configuration problem worth reporting.
 */
function splitHostPort(url) {
    let value = String(url || '').trim();
    const scheme = /^(wss?|https?):\/\//i.exec(value);
    if (scheme) value = value.slice(scheme[0].length);
    value = value.split('/')[0];

    if (!value) return { host: '', port: null, hasPort: false };

    // IPv6 literal: [::1]:2336
    const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
    if (v6) {
        return { host: v6[1], port: v6[2] ? Number(v6[2]) : null, hasPort: Boolean(v6[2]) };
    }
    const idx = value.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(value.slice(idx + 1))) {
        return { host: value.slice(0, idx), port: Number(value.slice(idx + 1)), hasPort: true };
    }
    return { host: value, port: null, hasPort: false };
}

/**
 * The exact WebSocket URL Shoukaku dials (`ws(s)://host:port/v4/websocket`),
 * built from the node's `url` + `secure` flag. Never includes the password.
 */
function nodeEndpoint(node) {
    if (!node) return 'no node configured';
    const { host, port } = splitHostPort(node.url);
    if (!host) return 'no host configured';
    const scheme = node.secure ? 'wss' : 'ws';
    return `${scheme}://${host}${port ? `:${port}` : ''}/v4/websocket`;
}

/** Password presence only — the value itself is never returned. */
function maskAuth(auth) {
    const value = typeof auth === 'string' ? auth.trim() : '';
    if (!value) return { hasAuth: false, authLength: 0, hint: 'missing' };
    return { hasAuth: true, authLength: value.length, hint: `set (${value.length} chars)` };
}

/**
 * Redact the configured password if a library error ever embeds it (defense in
 * depth — Shoukaku does not send the auth header in its error messages).
 */
function sanitizeText(text, node) {
    let out = String(text === null || text === undefined ? '' : text);
    const auth = node && typeof node.auth === 'string' ? node.auth.trim() : '';
    if (auth && auth.length >= 4) out = out.split(auth).join('[redacted]');
    // A URL that carries userinfo (ws://user:pass@host) is redacted too.
    out = out.replace(/(\bwss?:\/\/)[^\s/@]+@/gi, '$1[redacted]@');
    return out;
}

/** One sanitized, log-safe summary of a configured node. */
function describeNode(node) {
    const { host, port, hasPort } = splitHostPort(node && node.url);
    const auth = maskAuth(node && node.auth);
    return {
        name: (node && node.name) || 'unknown',
        host,
        port,
        hasPort,
        secure: Boolean(node && node.secure),
        endpoint: nodeEndpoint(node),
        hasAuth: auth.hasAuth,
        authLength: auth.authLength,
        authHint: auth.hint,
        authSource: (node && node.authSource) || 'unknown',
    };
}

/**
 * Boot-time report: one sanitized line plus the problems that will stop the
 * node from connecting. Nothing here throws or prints a credential.
 */
function buildBootReport(nodes = []) {
    const described = nodes.map(describeNode);
    const problems = [];
    for (const node of described) {
        if (!node.host) {
            problems.push(`node "${node.name}" has no host — set NODE_URL (or LAVALINK_HOST / LAVALINK_NODES url).`);
            continue;
        }
        if (!node.hasPort) {
            problems.push(`node "${node.name}" has no port in "${node.host}" — a bare host dials :80; set NODE_PORT (or host:port).`);
        }
        if (!node.hasAuth) {
            problems.push(`node "${node.name}" has no password — set NODE_AUTH (or LAVALINK_PASSWORD); Lavalink rejects the handshake without it.`);
        }
    }
    const line = described
        .map(n => `${n.name} (${n.endpoint}, ${n.secure ? 'TLS' : 'plaintext'}, auth ${n.authHint} from ${n.authSource})`)
        .join(', ');
    return { described, problems, line };
}

/**
 * The "still not connected" diagnostic. Distinguishes "no answer at all"
 * (nothing came back — typically a blocked port or the wrong scheme) from an
 * explicit library error (typically a wrong password or a rejected handshake),
 * because the two need completely different fixes.
 */
function buildConnectDiagnostic({ node, status = {}, elapsedMs = 0, lastError = null } = {}) {
    const d = describeNode(node);
    const seconds = Math.max(1, Math.round(Number(elapsedMs || 0) / 1000));
    const state = stateName(status.state);
    const registered = Number.isFinite(Number(status.registered)) ? Number(status.registered) : 0;
    const err = lastError ? sanitizeText(lastError, node).slice(0, 300) : null;

    const facts = [
        `node state: ${state}`,
        `${registered} node(s) registered`,
        `auth ${d.authHint} from ${d.authSource}`,
        d.secure ? 'TLS on' : 'plaintext',
    ].join(', ');

    const hint = err
        ? 'An authentication/handshake error means NODE_AUTH does not match the node password; a TLS error (EPROTO / wrong version number) means NODE_SECURE does not match the node scheme.'
        : 'Nothing came back from the node, which usually means the host/port is unreachable from this server or NODE_SECURE does not match the node scheme (ws:// vs wss://).';

    return `[MUSIC] Lavalink "${d.name}" is not connected after ${seconds}s — `
        + `${d.endpoint} (${facts}; last error: ${err || 'none reported'}). ${hint}`;
}

module.exports = {
    STATE_NAMES,
    stateName,
    splitHostPort,
    nodeEndpoint,
    maskAuth,
    sanitizeText,
    describeNode,
    buildBootReport,
    buildConnectDiagnostic,
};
