const { spawn } = require('child_process');
const path = require('path');

const defaultHeapMb = 1024;
const configuredHeapMb = Number(process.env.BOT_HEAP_SIZE_MB || process.env.NODE_MAX_OLD_SPACE_SIZE || defaultHeapMb);
const heapMb = Number.isFinite(configuredHeapMb) && configuredHeapMb > 0 ? configuredHeapMb : defaultHeapMb;
const heapArg = `--max-old-space-size=${heapMb}`;

const BASE_DELAY_MS = 3000;
const MAX_DELAY_MS  = 30000;
const MAX_RESTARTS  = 20;

let restartCount = 0;
let lastStartTime = 0;

function startBot() {
    lastStartTime = Date.now();

    const execArgs = (process.execArgv || []).filter(
        (arg) => !arg.startsWith('--max-old-space-size=') && arg !== '--expose-gc'
    );

    console.log(`[BOOT] Starting bot with ${heapArg} heap limit (attempt ${restartCount + 1})`);

    const child = spawn(
        process.execPath,
        [...execArgs, heapArg, '--expose-gc', path.join(__dirname, 'index.js')],
        { stdio: 'inherit', env: process.env }
    );

    child.on('error', (err) => {
        console.error('[BOOT ERROR] Failed to spawn bot process:', err);
        scheduleRestart(1);
    });

    child.on('exit', (code, signal) => {
        if (signal === 'SIGTERM' || signal === 'SIGINT') {
            console.log(`[BOOT] Bot received ${signal}, shutting down launcher.`);
            process.kill(process.pid, signal);
            return;
        }
        if (code === 0) {
            console.log('[BOOT] Bot exited cleanly (code 0). Launcher will not restart.');
            process.exit(0);
        }
        console.error(`[BOOT] Bot exited with code=${code} signal=${signal}.`);
        scheduleRestart(code);
    });
}

function scheduleRestart(exitCode) {
    restartCount++;

    if (restartCount > MAX_RESTARTS) {
        console.error(`[BOOT] Reached max restarts (${MAX_RESTARTS}). Giving up.`);
        process.exit(1);
    }

    // If the last run lived for more than 5 minutes, reset the backoff counter
    if (Date.now() - lastStartTime > 5 * 60 * 1000) {
        restartCount = 1;
    }

    const delay = Math.min(BASE_DELAY_MS * restartCount, MAX_DELAY_MS);
    console.log(`[BOOT] Restarting in ${delay / 1000}s... (restart #${restartCount})`);
    setTimeout(startBot, delay);
}

startBot();
