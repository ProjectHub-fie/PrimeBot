/**
 * Supported languages, resolved from Judge0's `/languages` endpoint.
 *
 * No language id is hardcoded: each target declares name patterns, and the id
 * is taken from whatever the provider currently reports. Results are cached
 * (`JUDGE0_LANGUAGE_CACHE_TTL_MS`, 6h by default) and refreshed on demand.
 */

const TARGET_LANGUAGES = Object.freeze([
    {
        key: 'python', label: 'Python', aliases: ['py', 'python3', 'python2', 'py3'],
        patterns: [/^python \(3\.\d/, /^python \(3/, /^python/],
    },
    {
        key: 'javascript', label: 'JavaScript (Node.js)', aliases: ['js', 'node', 'nodejs', 'node.js'],
        patterns: [/^javascript \(node\.js/, /^javascript/],
    },
    {
        key: 'typescript', label: 'TypeScript', aliases: ['ts'],
        patterns: [/^typescript/],
    },
    {
        key: 'c', label: 'C', aliases: ['gcc'],
        patterns: [/^c \(gcc/, /^c \(clang/, /^c \(/],
    },
    {
        key: 'cpp', label: 'C++', aliases: ['c++', 'cplusplus', 'g++', 'cpp17'],
        patterns: [/^c\+\+ \(gcc/, /^c\+\+ \(clang/, /^c\+\+ \(/],
    },
    {
        key: 'java', label: 'Java', aliases: ['jdk'],
        patterns: [/^java \(openjdk/, /^java \(/],
    },
    {
        key: 'csharp', label: 'C#', aliases: ['c#', 'cs', 'dotnet'],
        patterns: [/^c# \(mono/, /^c#/],
    },
    {
        key: 'go', label: 'Go', aliases: ['golang'],
        patterns: [/^go \(/, /^go$/],
    },
    {
        key: 'rust', label: 'Rust', aliases: ['rs'],
        patterns: [/^rust/],
    },
    {
        key: 'php', label: 'PHP', aliases: [],
        patterns: [/^php/],
    },
    {
        key: 'ruby', label: 'Ruby', aliases: ['rb'],
        patterns: [/^ruby/],
    },
    {
        key: 'kotlin', label: 'Kotlin', aliases: ['kt'],
        patterns: [/^kotlin/],
    },
]);

const LANGUAGE_KEYS = Object.freeze(TARGET_LANGUAGES.map(t => t.key));

function squash(value) {
    return String(value == null ? '' : value).trim().toLowerCase().replace(/[\s._-]+/g, '');
}

/** Map any user spelling (`js`, `Node.js`, `c++`, `C#`) onto a target key. */
function normalizeLanguageInput(input) {
    const raw = String(input == null ? '' : input).trim().toLowerCase();
    if (!raw) return null;
    const squashed = squash(raw);
    for (const target of TARGET_LANGUAGES) {
        if (target.key === raw) return target.key;
        if (target.label.toLowerCase() === raw) return target.key;
        if ((target.aliases || []).includes(raw)) return target.key;
        const candidates = [target.key, target.label, ...(target.aliases || [])].map(squash);
        if (candidates.includes(squashed)) return target.key;
    }
    return null;
}

function versionOf(name) {
    const match = String(name).match(/(\d+(?:\.\d+)+)/);
    return match ? match[1].split('.').map(n => parseInt(n, 10)) : [];
}

function compareVersions(a, b) {
    const left = versionOf(a);
    const right = versionOf(b);
    for (let i = 0; i < Math.max(left.length, right.length); i++) {
        const l = left[i] || 0;
        const r = right[i] || 0;
        if (l !== r) return r - l; // newest first
    }
    return 0;
}

/** Highest version wins; ties keep the provider's own order. */
function pickBest(entries) {
    return [...entries].sort((a, b) => compareVersions(a.name, b.name))[0] || null;
}

/**
 * Pure resolution step: given the provider's language list, work out which id
 * backs each target. Returns `{ supported, unsupported }`.
 */
function resolveFromLanguages(list, targets = TARGET_LANGUAGES) {
    const entries = (Array.isArray(list) ? list : [])
        .filter(entry => entry && Number.isFinite(Number(entry.id)) && typeof entry.name === 'string')
        .map(entry => ({ id: Number(entry.id), name: entry.name }));

    const supported = [];
    const unsupported = [];

    for (const target of targets) {
        let picked = null;
        for (const pattern of target.patterns) {
            const matches = entries.filter(entry => pattern.test(entry.name.toLowerCase()));
            if (matches.length) {
                picked = pickBest(matches);
                break;
            }
        }
        if (picked) {
            supported.push({ key: target.key, label: target.label, id: picked.id, name: picked.name });
        } else {
            unsupported.push({ key: target.key, label: target.label });
        }
    }

    return {
        supported,
        unsupported,
        providerLanguageCount: entries.length,
        byKey: new Map(supported.map(l => [l.key, l])),
        byId: new Map(supported.map(l => [l.id, l])),
    };
}

class LanguageCatalog {
    constructor({ provider, ttlMs = 6 * 60 * 60 * 1000, now = () => Date.now(), logger = console } = {}) {
        if (!provider || typeof provider.listLanguages !== 'function') {
            throw new TypeError('LanguageCatalog needs a provider with listLanguages()');
        }
        this.provider = provider;
        this.ttlMs = ttlMs;
        this.now = now;
        this.logger = logger;
        this.snapshot = null;
        this.fetchedAt = 0;
        this._inflight = null;
    }

    isStale() {
        return !this.snapshot || (this.now() - this.fetchedAt) > this.ttlMs;
    }

    /** Cached snapshot; concurrent callers share one provider request. */
    async load({ force = false } = {}) {
        if (!force && this.snapshot && !this.isStale()) return this.snapshot;
        if (this._inflight) return this._inflight;

        this._inflight = (async () => {
            try {
                const list = await this.provider.listLanguages();
                const snapshot = resolveFromLanguages(list);
                this.snapshot = snapshot;
                this.fetchedAt = this.now();
                return snapshot;
            } catch (err) {
                // A stale snapshot is better than no languages at all.
                if (this.snapshot) {
                    this.logger.warn?.('[COMPILE] Language refresh failed, keeping cached list:', err?.message || err);
                    return this.snapshot;
                }
                throw err;
            }
        })().finally(() => { this._inflight = null; });

        return this._inflight;
    }

    /** `{ target, language, snapshot }` or `null` when the language is unknown. */
    async find(input) {
        const key = normalizeLanguageInput(input);
        if (!key) return null;
        const snapshot = await this.load();
        const language = snapshot.byKey.get(key) || null;
        if (!language) return { target: key, language: null, snapshot };
        return { target: key, language, snapshot };
    }

    invalidate() {
        this.snapshot = null;
        this.fetchedAt = 0;
    }
}

module.exports = {
    TARGET_LANGUAGES,
    LANGUAGE_KEYS,
    LanguageCatalog,
    normalizeLanguageInput,
    resolveFromLanguages,
    pickBest,
    compareVersions,
};
