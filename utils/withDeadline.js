/**
 * Race a promise against a deadline, rejecting with a clear, non-hanging error.
 *
 * Used on serverless HTTP paths (the dashboard on Vercel) so a slow upstream
 * dependency — a YouTube feed fetch, a Discord REST call, a Postgres query on a
 * cold pool — can never hold a function open past its invocation budget and
 * surface as a generic FUNCTION_INVOCATION_TIMEOUT (504). Fail fast with a
 * structured status instead.
 *
 * @param {Promise} promise
 * @param {number}  ms       deadline in milliseconds
 * @param {string}  [message] custom timeout message
 * @returns {Promise} rejects with an Error carrying `.status = 504`
 */
function withDeadline(promise, ms, message) {
    if (!promise || typeof promise.then !== 'function') return promise;
    let timer = null;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
            const err = new Error(message || `Operation timed out after ${ms}ms`);
            err.status = 504;
            reject(err);
        }, Math.max(1, Number(ms) || 1000));
        if (timer.unref) timer.unref();
    });
    return Promise.race([promise, timeout]).finally(() => {
        if (timer) clearTimeout(timer);
    });
}

module.exports = { withDeadline };