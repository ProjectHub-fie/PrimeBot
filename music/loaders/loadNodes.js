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
        // A node event must never take the process down: `ready` touches the
        // 24/7 store, so an unreachable music database would otherwise surface
        // as an unhandled rejection and kill the bot the moment Lavalink
        // connects. Log it and carry on — playback does not need that table.
        client.manager.shoukaku.on(event.name, (...args) => {
            try {
                const result = event.run(client, ...args);
                if (result && typeof result.catch === 'function') {
                    result.catch((err) => {
                        client.logger.log(`Lavalink event "${event.name}" failed: ${err && err.message ? err.message : err}`, 'error');
                    });
                }
            } catch (err) {
                client.logger.log(`Lavalink event "${event.name}" failed: ${err && err.message ? err.message : err}`, 'error');
            }
        });
        totalEvents++;
    });

    client.logger.log(`Lavalink Node Events Loaded: ${totalEvents}`, 'event');
    return totalEvents;
};
