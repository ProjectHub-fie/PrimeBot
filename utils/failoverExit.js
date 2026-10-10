/**
 * Exit code a failover node uses when it STEPS DOWN (yields to a higher-priority
 * node) and needs to be replaced by a fresh process that boots back into standby.
 *
 * It must be non-zero. Both a hosting panel (Wispbyte/Pterodactyl) and the local
 * launcher (start-bot.js) read exit code 0 as a clean, intentional shutdown and
 * do NOT restart. A stepped-down node is not "done" — it should come back as a
 * standby to cover the next outage — so exiting 0 left it permanently down while
 * the higher-priority node was online.
 *
 * 75 (EX_TEMPFAIL) is the conventional "try again later" code and is not one of
 * the values a shell uses for a signal, so it is unambiguous.
 */
const DEFAULT_STEP_DOWN_EXIT_CODE = 75;

/**
 * Resolve the step-down exit code from an environment bag. Values outside the
 * 1-255 range (or non-numeric / zero) fall back to the default, so a typo can
 * never turn a step-down into a clean-exit that never restarts.
 *
 * @param {Record<string,string|undefined>} [env]
 * @returns {number}
 */
function stepDownExitCode(env = process.env) {
    const n = parseInt(env.STEP_DOWN_EXIT_CODE, 10);
    return Number.isInteger(n) && n > 0 && n <= 255 ? n : DEFAULT_STEP_DOWN_EXIT_CODE;
}

const STEP_DOWN_EXIT_CODE = stepDownExitCode();

module.exports = { stepDownExitCode, STEP_DOWN_EXIT_CODE, DEFAULT_STEP_DOWN_EXIT_CODE };
