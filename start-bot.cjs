const { spawn } = require('child_process');
const path = require('path');

const defaultHeapMb = 1024;
const configuredHeapMb = Number(process.env.BOT_HEAP_SIZE_MB || process.env.NODE_MAX_OLD_SPACE_SIZE || defaultHeapMb);
const heapMb = Number.isFinite(configuredHeapMb) && configuredHeapMb > 0 ? configuredHeapMb : defaultHeapMb;
const heapArg = `--max-old-space-size=${heapMb}`;
const execArgs = (process.execArgv || []).filter((arg) => !arg.startsWith('--max-old-space-size='));

console.log(`[BOOT] Starting bot with ${heapArg} heap limit`);

const child = spawn(process.execPath, [...execArgs, heapArg, path.join(__dirname, 'index.js')], {
    stdio: 'inherit',
    env: process.env,
});

child.on('exit', (code, signal) => {
    if (signal) {
        process.kill(process.pid, signal);
        return;
    }
    process.exit(code ?? 0);
});

child.on('error', (error) => {
    console.error('[BOOT ERROR] Failed to start bot process:', error);
    process.exit(1);
});
