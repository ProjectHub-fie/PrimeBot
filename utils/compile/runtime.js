/**
 * Process-wide Code Compile runtime (config + provider + language cache +
 * limiter). Tests inject a runtime instead of touching the public API.
 */

const { getCompileConfig } = require('./compileConfig');
const { createJudge0Provider } = require('./judge0Provider');
const { LanguageCatalog } = require('./languageCatalog');
const { CompileLimiter } = require('./compileLimiter');

let current = null;

function createCompileRuntime(overrides = {}) {
    const config = getCompileConfig(overrides.config || {});
    const provider = overrides.provider || createJudge0Provider({
        baseUrl: config.apiUrl,
        requestTimeoutMs: config.requestTimeoutMs,
        fetchFn: overrides.fetchFn,
    });
    const catalog = overrides.catalog || new LanguageCatalog({
        provider,
        ttlMs: config.languageCacheTtlMs,
    });
    const limiter = overrides.limiter || new CompileLimiter(config);
    return { config, provider, catalog, limiter };
}

function getCompileRuntime(overrides) {
    if (!current) current = createCompileRuntime(overrides);
    return current;
}

function setCompileRuntime(runtime) {
    current = runtime || null;
    return current;
}

function resetCompileRuntime() {
    current = null;
}

module.exports = {
    createCompileRuntime,
    getCompileRuntime,
    setCompileRuntime,
    resetCompileRuntime,
};
