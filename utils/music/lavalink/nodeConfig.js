/**
 * Lavalink node configuration — parsing, validation and redaction.
 *
 * Nodes are supplied through environment variables so no credential is ever
 * committed:
 *
 *   LAVALINK_NODES='[{"name":"main","host":"lavalink.example.com","port":443,
 *                     "password":"...","secure":true}]'
 *
 * A single node may instead be described with the individual variables
 * (matching PrimeBot's existing per-setting env conventions):
 *
 *   LAVALINK_HOST / LAVALINK_PORT / LAVALINK_PASSWORD / LAVALINK_SECURE
 *   LAVALINK_NAME (optional identifier, default "main")
 *
 * Shoukaku expects `{ name, url: 'host:port', auth, secure }`, so this module
 * converts whatever was configured into that shape. Passwords are NEVER logged
 * or returned by `describeNodes()` — only `hasPassword` is exposed.
 *
 * Validation happens once, at startup: an invalid entry is dropped with a
 * reason rather than producing a node that can only ever fail.
 */

/** Shoukaku's own default port — kept here so we do not import shoukaku at config time. */
const DEFAULT_PORT = 2333;
const MAX_NODES = 16;

function isPlainObject(v) {
    return !!v && typeof v === 'object' && !Array.isArray(v);
}

function parseBoolean(value, fallback = false) {
    if (value == null || value === '') return fallback;
    if (typeof value === 'boolean') return value;
    const s = String(value).trim().toLowerCase();
    if (['true', '1', 'yes', 'on', 'y'].includes(s)) return true;
    if (['false', '0', 'no', 'off', 'n'].includes(s)) return false;
    return fallback;
}

function parsePort(value) {
    const n = parseInt(value, 10);
    if (!Number.isFinite(n) || n < 1 || n > 65535) return null;
    return n;
}

/**
 * Normalize one raw node object into Shoukaku's NodeOption shape.
 * Returns `{ ok: true, node }` or `{ ok: false, reason }`.
 */
function normalizeNode(raw, index) {
    if (!isPlainObject(raw)) return { ok: false, reason: `entry #${index} is not an object` };

    // `url` may be given as "host:port", a full URL, or split host/port.
    let host = raw.host != null ? String(raw.host).trim() : '';
    let port = raw.port != null ? parsePort(raw.port) : null;
    let secure = parseBoolean(raw.secure, false);

    if (!host && raw.url != null) {
        const u = String(raw.url).trim();
        const m = u.match(/^(?:(\w+):\/\/)?([^/:]+)(?::(\d+))?$/);
        if (m) {
            if (m[1]) secure = m[1].toLowerCase() === 'https' || m[1].toLowerCase() === 'wss';
            host = m[2];
            if (m[3]) port = parsePort(m[3]);
        } else {
            host = u;
        }
    }

    if (!host) return { ok: false, reason: `entry #${index} is missing a host` };
    if (/\s/.test(host)) return { ok: false, reason: `entry #${index} host contains whitespace` };
    if (/^https?:\/\//i.test(host)) host = host.replace(/^https?:\/\//i, '');
    host = host.replace(/\/+$/, '');
    if (!host) return { ok: false, reason: `entry #${index} has an empty host` };

    // A default port is applied when none was supplied; `secure` decides the
    // protocol so operators do not have to state both.
    const finalPort = port != null ? port : (secure ? 443 : DEFAULT_PORT);

    const name = raw.name != null && String(raw.name).trim()
        ? String(raw.name).trim().slice(0, 64)
        : `node-${index + 1}`;

    const password = raw.password != null ? String(raw.password) : (raw.auth != null ? String(raw.auth) : '');
    if (!password) return { ok: false, reason: `entry #${index} ("${name}") is missing a password` };

    const group = raw.group != null && String(raw.group).trim() ? String(raw.group).trim().slice(0, 64) : undefined;

    return {
        ok: true,
        node: {
            name,
            url: `${host}:${finalPort}`,
            auth: password,
            secure,
            ...(group ? { group } : {}),
            // Kept alongside the Shoukaku shape purely for diagnostics.
            host,
            port: finalPort,
        },
    };
}

/** Parse the LAVALINK_NODES JSON array. Throws with a clear message on bad JSON. */
function parseNodesJson(raw) {
    const text = String(raw || '').trim();
    if (!text) return [];
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (err) {
        throw new Error(`LAVALINK_NODES is not valid JSON: ${err.message}`);
    }
    if (!Array.isArray(parsed)) throw new Error('LAVALINK_NODES must be a JSON array of node objects.');
    return parsed;
}

/** Build a single node from the individual LAVALINK_* variables (or null). */
function nodeFromIndividualEnv(env) {
    const host = env.LAVALINK_HOST;
    if (!host) return null;
    return {
        name: env.LAVALINK_NAME || 'main',
        host,
        port: env.LAVALINK_PORT,
        password: env.LAVALINK_PASSWORD,
        secure: env.LAVALINK_SECURE,
    };
}

/**
 * Read + validate the configured nodes.
 *
 * Returns `{ nodes, errors, source }` where `nodes` is a list of Shoukaku
 * NodeOption objects (never containing an invalid entry) and `errors` explains
 * every entry that was dropped. Never throws for a bad entry — a single typo
 * must not take the whole music engine down when another node is valid.
 */
function loadNodeConfig(env = process.env) {
    const errors = [];
    let raw = [];
    let source = 'none';

    if (env.LAVALINK_NODES && String(env.LAVALINK_NODES).trim()) {
        source = 'LAVALINK_NODES';
        try {
            raw = parseNodesJson(env.LAVALINK_NODES);
        } catch (err) {
            return { nodes: [], errors: [err.message], source };
        }
    } else {
        const single = nodeFromIndividualEnv(env);
        if (single) {
            source = 'LAVALINK_HOST';
            raw = [single];
        }
    }

    const nodes = [];
    const seenNames = new Set();
    raw.slice(0, MAX_NODES).forEach((entry, i) => {
        const res = normalizeNode(entry, i);
        if (!res.ok) {
            errors.push(res.reason);
            return;
        }
        // Duplicate node names would collide in Shoukaku's Map — make them unique.
        if (seenNames.has(res.node.name)) {
            let n = 2;
            while (seenNames.has(`${res.node.name}-${n}`)) n++;
            res.node.name = `${res.node.name}-${n}`;
        }
        seenNames.add(res.node.name);
        nodes.push(res.node);
    });
    if (raw.length > MAX_NODES) {
        errors.push(`only the first ${MAX_NODES} nodes are used (${raw.length} configured)`);
    }

    return { nodes, errors, source };
}

/** Is Lavalink configured at all? */
function hasNodeConfig(env = process.env) {
    return loadNodeConfig(env).nodes.length > 0;
}

/**
 * A credential-free description of a node, safe for logs, dashboards and API
 * responses. The password is never included — only whether one is set.
 */
function describeNode(node) {
    if (!node) return null;
    return {
        name: node.name,
        url: node.url,
        secure: !!node.secure,
        group: node.group || null,
        hasPassword: !!node.auth,
    };
}

/** Credential-free description of every node. */
function describeNodes(nodes) {
    return (nodes || []).map(describeNode);
}

module.exports = {
    DEFAULT_PORT,
    MAX_NODES,
    parseBoolean,
    parsePort,
    normalizeNode,
    parseNodesJson,
    loadNodeConfig,
    hasNodeConfig,
    describeNode,
    describeNodes,
};
