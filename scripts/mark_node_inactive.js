const nodeFailover = require('../utils/nodeFailover');

const role = process.argv[2] || process.env.ROLE;
if (!role) {
    console.error('Usage: node scripts/mark_node_inactive.js <primary|secondary>');
    process.exit(2);
}

async function main() {
    try {
        await nodeFailover.markInactive(role);
        console.log(`Marked ${role} inactive.`);
    } catch (err) {
        console.error('Failed to mark inactive:', err.message || err);
        process.exit(1);
    }
}

main();