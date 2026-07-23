const nodeFailover = require('../utils/nodeFailover');

async function main() {
    console.log('NODE_ROLE env:', nodeFailover.NODE_ROLE);
    console.log('NODE_NAME env:', nodeFailover.NODE_NAME);
    try {
        const sn1 = await nodeFailover.getStatus('sn1');
        const sn2 = await nodeFailover.getStatus('sn2');
        const sn3 = await nodeFailover.getStatus('sn3');
        console.log('sn1 status:', sn1 || null);
        console.log('sn2 status:', sn2 || null);
        console.log('sn3 status:', sn3 || null);
    } catch (err) {
        console.error('Failed to read node status:', err.message || err);
    }
}

main().catch(e => console.error(e));
