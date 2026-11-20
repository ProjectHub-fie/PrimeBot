/**
 * Linix `src/loaders/loadPlayers.js` — register Kazagumo player events.
 *
 * Preserved verbatim in behaviour: every file in `events/Players` is required
 * and bound to `client.manager` by its exported `name`. Registration is
 * guarded so a second call (a reconnect, a failover takeover) cannot double-bind
 * the listeners and double-answer every player event.
 */

const fs = require('fs');
const path = require('path');

module.exports = function loadPlayers(client) {
    if (!client.manager) {
        client.logger.log('Player Events not loaded: no player manager', 'warn');
        return 0;
    }
    if (client.__musicPlayerEventsLoaded) return 0;
    client.__musicPlayerEventsLoaded = true;

    const playerEventsPath = path.join(__dirname, '../events/Players');
    let totalEvents = 0;

    fs.readdirSync(playerEventsPath).forEach((file) => {
        if (!file.endsWith('.js')) return;
        const event = require(path.join(playerEventsPath, file));
        client.manager.on(event.name, (...args) => event.run(client, ...args));
        totalEvents++;
    });

    client.logger.log(`Player Events Loaded: ${totalEvents}`, 'event');
    return totalEvents;
};
