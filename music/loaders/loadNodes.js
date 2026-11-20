/**
 * Linix `src/loaders/loadNodes.js` — register Shoukaku (Lavalink) node events.
 *
 * Preserved verbatim in behaviour: every file in `events/Node` is bound to
 * `client.manager.shoukaku` by its exported `name`. Guarded so the listeners are
 * bound once per process.
 */

const fs = require('fs');
const path = require('path');

module.exports = function loadNodes(client) {
    if (!client.manager) {
        client.logger.log('Lavalink Node Events not loaded: no player manager', 'warn');
        return 0;
    }
    if (client.__musicNodeEventsLoaded) return 0;
    client.__musicNodeEventsLoaded = true;

    const nodeEventsPath = path.join(__dirname, '../events/Node');
    let totalEvents = 0;

    fs.readdirSync(nodeEventsPath).forEach((file) => {
        if (!file.endsWith('.js')) return;
        const event = require(path.join(nodeEventsPath, file));
        client.manager.shoukaku.on(event.name, (...args) => event.run(client, ...args));
        totalEvents++;
    });

    client.logger.log(`Lavalink Node Events Loaded: ${totalEvents}`, 'event');
    return totalEvents;
};
