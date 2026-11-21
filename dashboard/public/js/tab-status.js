/* Live browser-tab status indicator for the /stats page.
 *
 * Paints a status dot onto the existing PrimeBot favicon and rewrites the tab
 * title from the SAME monitoring payload the status board renders
 * (`/api/status/detailed`), so the tab can never disagree with the page:
 *
 *   green  — every required service healthy (standby shard nodes included)
 *   yellow — degraded / partial outage, OR monitoring data unavailable
 *   red    — the bot (or a critical service) is genuinely offline
 *
 * Health comes only from the backend classification (`overall.key` +
 * per-component `status`, produced by utils/statusWorker). A standby node is
 * `operational` there, so it can never be mistaken for offline. A failed,
 * timed-out or malformed response paints YELLOW — never green.
 *
 * The module is dependency-injected (document / location / fetch / timers) so
 * it is unit-testable in a vm sandbox, and it owns exactly one poll chain (the
 * next request is scheduled only after the previous one settles), so requests
 * can never overlap.
 */
(function () {
    'use strict';

    const FETCH_PATH = '/api/status/detailed';
    const DEFAULT_INTERVAL_MS = 45000; // 30–60s window
    const DEFAULT_TIMEOUT_MS = 12000;

    const BOLT = 'M13 2 L3 14 L12 14 L11 22 L21 10 L12 10 Z';
    const BOLT_STROKE = '#5865f2';
    const DOT_RING = '#0a0b10';
    const STATS_PATH = /^\/stats\/?$/;

    const LEVELS = {
        operational: { key: 'operational', emoji: '🟢', label: 'Operational', dot: '#23a55a' },
        degraded: { key: 'degraded', emoji: '🟡', label: 'Degraded', dot: '#f0b232' },
        outage: { key: 'outage', emoji: '🔴', label: 'Outage', dot: '#f23f43' },
    };

    // Service components that gate GREEN. A stale/unknown reading is not a
    // confirmed failure, but it is also not "healthy" — it is yellow.
    const HEALTHY_GATE = ['bot', 'gateway'];

    function levelMeta(level) {
        return LEVELS[level] || LEVELS.degraded;
    }

    /**
     * Map the monitoring summary to one of the three tab levels.
     * Anything unrecognised or missing degrades to yellow, never green.
     */
    function levelForSummary(summary) {
        if (!summary || typeof summary !== 'object' || Array.isArray(summary)) return 'degraded';
        const overall = summary.overall;
        const key = overall && typeof overall === 'object' ? overall.key : null;

        const byKey = {};
        for (const c of Array.isArray(summary.components) ? summary.components : []) {
            if (c && c.key) byKey[c.key] = c;
        }

        // A genuinely unavailable bot is an outage regardless of the banner.
        if (byKey.bot && byKey.bot.status === 'unavailable') return 'outage';

        switch (key) {
            case 'critical':
            case 'major':
                return 'outage';
            case 'degraded':
            case 'no_data':
            case 'maintenance':
                return 'degraded';
            case 'operational':
                break;
            default:
                return 'degraded';
        }

        // Green requires the gating services to be actually measured AND
        // healthy: outdated data means "needs verification", i.e. yellow.
        for (const name of HEALTHY_GATE) {
            const comp = byKey[name];
            if (!comp) return 'degraded';
            if (comp.status !== 'operational') return 'degraded';
        }
        // A shard node reported offline (never a stale one) reduces redundancy.
        for (const role of ['sn1', 'sn2', 'sn3']) {
            const node = byKey[role];
            if (node && node.status === 'unavailable') return 'degraded';
        }
        return 'operational';
    }

    function titleForLevel(level) {
        const meta = levelMeta(level);
        return `${meta.emoji} PrimeBot — ${meta.label}`;
    }

    function buildSvg(level) {
        const dot = levelMeta(level).dot;
        return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">`
            + `<g transform="translate(1.5 1) scale(0.86)">`
            + `<path d="${BOLT}" fill="none" stroke="${BOLT_STROKE}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`
            + `</g>`
            + `<circle cx="24.5" cy="24.5" r="6.6" fill="${DOT_RING}"/>`
            + `<circle cx="24.5" cy="24.5" r="4.6" fill="${dot}"/>`
            + `</svg>`;
    }

    // Rasterize the badge with canvas when available (iOS/older Safari do not
    // render SVG favicons), falling back to the SVG data URI.
    function drawPng(level, doc) {
        try {
            if (!doc || typeof doc.createElement !== 'function') return null;
            const canvas = doc.createElement('canvas');
            if (!canvas || typeof canvas.getContext !== 'function' || typeof canvas.toDataURL !== 'function') return null;
            canvas.width = 64;
            canvas.height = 64;
            const ctx = canvas.getContext('2d');
            if (!ctx || typeof ctx.beginPath !== 'function') return null;

            ctx.clearRect(0, 0, 64, 64);
            ctx.beginPath();
            ctx.moveTo(26, 4);
            ctx.lineTo(6, 28);
            ctx.lineTo(24, 28);
            ctx.lineTo(22, 44);
            ctx.lineTo(42, 20);
            ctx.lineTo(24, 20);
            ctx.closePath();
            ctx.lineWidth = 4;
            ctx.lineJoin = 'round';
            ctx.lineCap = 'round';
            ctx.strokeStyle = BOLT_STROKE;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(49, 49, 13, 0, Math.PI * 2);
            ctx.fillStyle = DOT_RING;
            ctx.fill();
            ctx.beginPath();
            ctx.arc(49, 49, 9.2, 0, Math.PI * 2);
            ctx.fillStyle = levelMeta(level).dot;
            ctx.fill();

            const url = canvas.toDataURL('image/png');
            return typeof url === 'string' && url.indexOf('data:image/png') === 0 ? url : null;
        } catch (_) {
            return null;
        }
    }

    function buildFaviconHref(level, doc) {
        return drawPng(level, doc) || ('data:image/svg+xml,' + encodeURIComponent(buildSvg(level)));
    }

    function isStatsPath(location) {
        if (!location) return false;
        const pathname = typeof location.pathname === 'string' ? location.pathname : '';
        return STATS_PATH.test(pathname);
    }

    /**
     * Create the indicator. Every dependency is injectable for testing; in the
     * browser the defaults are used.
     */
    function create(options) {
        const opts = options || {};
        const doc = opts.document || (typeof document !== 'undefined' ? document : null);
        const win = opts.window || (typeof window !== 'undefined' ? window : null);
        const loc = opts.location || (win && win.location) || (typeof location !== 'undefined' ? location : null);
        const fetchFn = opts.fetchFn || (typeof fetch === 'function' ? fetch : null);
        const setT = opts.setTimeoutFn || (typeof setTimeout === 'function' ? setTimeout : null);
        const clearT = opts.clearTimeoutFn || (typeof clearTimeout === 'function' ? clearTimeout : null);
        const intervalMs = Number(opts.intervalMs) > 0 ? Number(opts.intervalMs) : DEFAULT_INTERVAL_MS;
        const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : DEFAULT_TIMEOUT_MS;
        const onUpdate = typeof opts.onUpdate === 'function' ? opts.onUpdate : null;
        const logger = typeof opts.logger === 'function' ? opts.logger : function () {};
        const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : function () { return Date.now(); };

        const state = {
            level: null,
            polls: 0,
            failures: 0,
            lastError: null,
            lastCheckedAt: null,
            applied: 0, // number of times the tab chrome actually changed
        };

        let timer = null;
        let inFlight = false;
        let running = false;
        let attached = false;
        let level = null;
        let originalTitle = null;
        let originalFavicon = null;
        let originalCaptured = false;
        let lastPollAt = 0;
        const listeners = [];

        function faviconLink() {
            if (!doc || typeof doc.querySelector !== 'function') return null;
            const link = doc.querySelector('link[rel="icon"]') || doc.querySelector('link[rel="shortcut icon"]');
            if (link) return link;
            if (doc.head && typeof doc.createElement === 'function' && typeof doc.head.appendChild === 'function') {
                const created = doc.createElement('link');
                if (!created) return null;
                created.setAttribute('rel', 'icon');
                doc.head.appendChild(created);
                return created;
            }
            return null;
        }

        function captureOriginals() {
            if (originalCaptured || !doc) return;
            originalCaptured = true;
            originalTitle = typeof doc.title === 'string' ? doc.title : null;
            const link = faviconLink();
            originalFavicon = link ? link.getAttribute('href') : null;
        }

        function applyLevel(next) {
            state.level = next;
            if (!doc || next === level) return false;
            level = next;
            doc.title = titleForLevel(next);
            const link = faviconLink();
            if (link) link.setAttribute('href', buildFaviconHref(next, doc));
            state.applied++;
            return true;
        }

        function restoreOriginals() {
            level = null;
            state.level = null;
            if (!doc || !originalCaptured) return;
            if (originalTitle != null) doc.title = originalTitle;
            const link = faviconLink();
            if (link && originalFavicon != null) link.setAttribute('href', originalFavicon);
        }

        function scheduleNext(delay) {
            if (!running || !setT) return;
            if (timer != null && clearT) clearT(timer);
            timer = setT(function () {
                timer = null;
                poll();
            }, delay == null ? intervalMs : delay);
        }

        function requestSummary() {
            return new Promise(function (resolve, reject) {
                if (!fetchFn) return reject(new Error('fetch unavailable'));
                let settled = false;
                let timeoutId = null;
                const finish = function (fn, value) {
                    if (settled) return;
                    settled = true;
                    if (timeoutId != null && clearT) clearT(timeoutId);
                    fn(value);
                };
                if (setT) {
                    timeoutId = setT(function () {
                        finish(reject, new Error('timeout'));
                    }, timeoutMs);
                }
                let pending;
                try {
                    pending = fetchFn(FETCH_PATH, { headers: { Accept: 'application/json' }, cache: 'no-store' });
                } catch (err) {
                    return finish(reject, err);
                }
                Promise.resolve(pending).then(function (res) {
                    if (settled) return null;
                    if (!res || res.ok === false) {
                        throw new Error('request failed' + (res && res.status ? ' (' + res.status + ')' : ''));
                    }
                    return res.json();
                }).then(function (json) {
                    if (settled) return;
                    if (!json || typeof json !== 'object' || Array.isArray(json)
                        || !json.overall || typeof json.overall !== 'object' || !json.overall.key) {
                        return finish(reject, new Error('invalid response'));
                    }
                    finish(resolve, json);
                }).catch(function (err) {
                    finish(reject, err);
                });
            });
        }

        function poll() {
            if (!running || inFlight) return;
            inFlight = true;
            state.polls++;
            lastPollAt = nowFn();
            requestSummary().then(function (summary) {
                inFlight = false;
                if (!running) return;
                state.failures = 0;
                state.lastError = null;
                state.lastCheckedAt = new Date().toISOString();
                applyLevel(levelForSummary(summary));
                if (onUpdate) {
                    try { onUpdate(summary); } catch (err) { logger('onUpdate failed: ' + err.message); }
                }
                scheduleNext();
            }, function (err) {
                inFlight = false;
                if (!running) return;
                state.failures++;
                state.lastError = err && err.message ? err.message : String(err);
                // No monitoring data is NOT "all healthy": yellow.
                applyLevel('degraded');
                scheduleNext();
            });
        }

        function addListener(target, evt, fn) {
            if (!target || typeof target.addEventListener !== 'function') return;
            target.addEventListener(evt, fn);
            listeners.push({ target: target, evt: evt, fn: fn });
        }

        function detach() {
            attached = false;
            for (const l of listeners.splice(0)) {
                try { l.target.removeEventListener(l.evt, l.fn); } catch (_) {}
            }
        }

        const onVisibility = function () {
            if (!running) return;
            if (doc && doc.hidden) return;
            // Coming back to the tab: refresh immediately, but never stack a
            // second request on an in-flight one or hammer within 5s.
            if (inFlight || nowFn() - lastPollAt < 5000) return;
            scheduleNext(0);
        };
        const onPageHide = function () {
            running = false;
            if (timer != null && clearT) { clearT(timer); timer = null; }
            restoreOriginals();
        };
        const onPageShow = function (event) {
            if (event && event.persisted) start();
        };

        function attach() {
            if (attached) return;
            attached = true;
            addListener(doc, 'visibilitychange', onVisibility);
            addListener(win, 'pagehide', onPageHide);
            addListener(win, 'pageshow', onPageShow);
            addListener(win, 'beforeunload', onPageHide);
        }

        function start(seed) {
            if (!doc || running) return api;
            if (!isStatsPath(loc)) return api;
            running = true;
            captureOriginals();
            attach();
            const seedSummary = seed && (seed.summary || seed);
            if (seedSummary && typeof seedSummary === 'object' && seedSummary.overall) {
                state.lastCheckedAt = new Date().toISOString();
                applyLevel(levelForSummary(seedSummary));
                scheduleNext();
            } else {
                poll();
            }
            return api;
        }

        function stop(settings) {
            const restore = !settings || settings.restore !== false;
            running = false;
            if (timer != null && clearT) { clearT(timer); timer = null; }
            detach();
            if (restore) restoreOriginals();
            return api;
        }

        const api = {
            start: start,
            stop: stop,
            update: function (summary) {
                return applyLevel(levelForSummary(summary));
            },
            state: state,
            intervalMs: intervalMs,
            timeoutMs: timeoutMs,
        };
        return api;
    }

    const api = {
        create: create,
        levelForSummary: levelForSummary,
        titleForLevel: titleForLevel,
        buildFaviconHref: buildFaviconHref,
        buildSvg: buildSvg,
        isStatsPath: isStatsPath,
        LEVELS: LEVELS,
        FETCH_PATH: FETCH_PATH,
        DEFAULT_INTERVAL_MS: DEFAULT_INTERVAL_MS,
    };

    if (typeof window !== 'undefined' && window) window.PrimeBotTabStatus = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
