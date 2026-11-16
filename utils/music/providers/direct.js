/**
 * Direct audio URL provider.
 *
 * Accepts legitimate, compatible direct audio streams. The URL is validated
 * before it is ever handed to ffmpeg:
 *   • protocol must be http/https,
 *   • the host must not be a private/loopback address (SSRF guard),
 *   • a HEAD (falling back to a ranged GET) checks the response status and, when
 *     present, the Content-Type — the body is never downloaded.
 *
 * Unsupported content and error responses are rejected with a clear reason.
 * Redirects are followed by the fetch implementation but the FINAL URL is
 * re-checked against the same rules.
 */

const { PROVIDERS, looksLikeAudioUrl, AUDIO_CONTENT_TYPES, AUDIO_EXTENSIONS } = require('../../../shared/musicConstants');

let _fetch = null;
function http() { if (!_fetch) _fetch = globalThis.fetch; return _fetch; }

const PRIVATE_HOST = /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|::1$|\[::1\])|^172\.(1[6-9]|2\d|3[01])\./i;

function assertSafeUrl(raw) {
    let u;
    try { u = new URL(String(raw)); } catch (_) { throw new Error('That is not a valid URL.'); }
    if (!/^https?:$/.test(u.protocol)) throw new Error('Only http(s) audio URLs are supported.');
    if (PRIVATE_HOST.test(u.hostname)) throw new Error('That URL points to a private address and is not allowed.');
    return u;
}

function canHandle(input) {
    return typeof input === 'string' && /^https?:\/\//i.test(input) && looksLikeAudioUrl(input);
}

function titleFromUrl(u) {
    const base = u.pathname.split('/').filter(Boolean).pop() || 'Direct audio';
    try { return decodeURIComponent(base); } catch (_) { return base; }
}

/** Validate that a URL is reachable and plausibly audio (no body download). */
async function probe(url) {
    const u = assertSafeUrl(url);
    let res;
    try {
        res = await http()(u.href, { method: 'HEAD', redirect: 'follow' });
    } catch (_) {
        res = null;
    }
    // Some CDNs reject HEAD — fall back to a 1-byte ranged GET.
    if (!res || res.status === 405 || res.status === 501) {
        try {
            res = await http()(u.href, { method: 'GET', headers: { Range: 'bytes=0-0' }, redirect: 'follow' });
        } catch (err) {
            throw new Error(`The audio URL could not be reached: ${err.message}`);
        }
    }
    if (!res.ok && res.status !== 206) {
        throw new Error(`The audio URL responded with HTTP ${res.status}.`);
    }
    const finalUrl = res.url || u.href;
    assertSafeUrl(finalUrl);
    const type = (res.headers && res.headers.get ? res.headers.get('content-type') : null) || '';
    const extOk = AUDIO_EXTENSIONS.some(e => u.pathname.toLowerCase().endsWith(e));
    const typeOk = AUDIO_CONTENT_TYPES.some(t => type.toLowerCase().includes(t));
    if (type && !typeOk && !extOk) {
        throw new Error(`That URL is not a supported audio stream (content-type: ${type}).`);
    }
    return { finalUrl, contentType: type || null };
}

async function resolve(url) {
    const probeResult = await probe(url);
    const u = new URL(probeResult.finalUrl);
    return {
        provider: PROVIDERS.DIRECT,
        id: u.href,
        title: titleFromUrl(u),
        artist: u.hostname,
        durationMs: null,
        url: u.href,
        artworkUrl: null,
        source: 'Direct URL',
    };
}

async function resolveStream(track) {
    const url = typeof track === 'string' ? track : (track && track.url);
    if (!url) throw new Error('Direct URL track has no URL.');
    const probeResult = await probe(url);
    return { streamUrl: probeResult.finalUrl, durationMs: null };
}

module.exports = { id: PROVIDERS.DIRECT, canHandle, resolve, resolveStream, probe, assertSafeUrl };
