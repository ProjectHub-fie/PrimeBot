const betaManager = require('../utils/betaManager');
const nodeFailover = require('../utils/nodeFailover');

async function main() {
    const guildId = process.argv[2] || process.env.GUILD_ID || null;
    console.log('NODE_ROLE:', nodeFailover.NODE_ROLE);
    console.log('NODE_NAME:', nodeFailover.NODE_NAME);
    console.log('--- Checking DB health ---');
    const health = await betaManager.checkDbHealth();
    console.log('DB health:', health);
    if (betaManager._lastError) {
        console.log('Last betaManager error:', betaManager._lastError.message || betaManager._lastError);
    }

    if (guildId) {
        console.log(`--- Checking beta status for guild ${guildId} ---`);
        const allowed = await betaManager.isAllowed(guildId);
        const enabled = await betaManager.isEnabled(guildId);
        const access = await betaManager.canAccess(guildId);
        console.log('isAllowed:', allowed);
        console.log('isEnabled:', enabled);
        console.log('canAccess:', access);
    } else {
        console.log('No guild id provided. Run: node scripts/check_beta.js <guildId>');
    }
}

main().catch(err => {
    console.error('check_beta failed:', err);
    process.exit(1);
});