const nodeFailover = require('../utils/nodeFailover');

async function main() {
    console.log('NODE_ROLE env:', nodeFailover.NODE_ROLE);
    console.log('NODE_NAME env:', nodeFailover.NODE_NAME);
    try {
        const p = await nodeFailover.getStatus('primary');
        const s = await nodeFailover.getStatus('secondary');
        console.log('Primary status:', p || null);
        console.log('Secondary status:', s || null);
    } catch (err) {
        console.error('Failed to read node status:', err.message || err);
    }
}

main().catch(e => console.error(e));