/**
 * Linix `src/loaders/loadCommands.js` — load the prefix (`client.commands`) and
 * slash (`client.slashCommands`) music command trees.
 *
 * Linix has ONE command system: a prefix command collection with `execute`
 * handlers, plus a separate slash collection with `run` handlers. Both trees are
 * loaded here exactly as Linix does (`commands/<Category>/<file>.js` and
 * `slashCommands/<Category>/<file>.js`), into PrimeBot's client.
 *
 * PrimeBot adaptation: PrimeBot's own `client.commands` collection already holds
 * its slash commands (`command.data.name` → `command`), so the Linix trees get
 * their own collections — `client.musicCommands` (prefix) and
 * `client.slashCommands` (slash). Merging them into `client.commands` would let
 * `$play` shadow PrimeBot's own slash dispatch. This is the ONLY music command
 * registration.
 */

const fs = require('fs');
const path = require('path');

function readCategoryDirs(root) {
    if (!fs.existsSync(root)) return [];
    return fs.readdirSync(root)
        .filter((dir) => fs.statSync(path.join(root, dir)).isDirectory())
        .map((dir) => path.join(root, dir));
}

module.exports = function loadCommands(client) {
    if (!client.musicCommands) client.musicCommands = new Map();
    if (!client.slashCommands) client.slashCommands = new Map();
    if (client.__musicCommandsLoaded) {
        return { prefix: client.musicCommands.size, slash: client.slashCommands.size };
    }
    client.__musicCommandsLoaded = true;

    const commandsRoot = path.join(__dirname, '../commands');
    const slashRoot = path.join(__dirname, '../slashCommands');

    let prefixCount = 0;
    for (const dir of readCategoryDirs(commandsRoot)) {
        for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.js'))) {
            const command = require(path.join(dir, file));
            if (!command || !command.name) continue;
            client.musicCommands.set(command.name, command);
            prefixCount++;
        }
    }

    let slashCount = 0;
    for (const dir of readCategoryDirs(slashRoot)) {
        for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.js'))) {
            const slashCommand = require(path.join(dir, file));
            if (!slashCommand.name || !slashCommand.description) continue;
            client.slashCommands.set(slashCommand.name, slashCommand);
            slashCount++;
        }
    }

    client.logger.log(`Prefix Commands Loaded: ${prefixCount}`, 'cmd');
    client.logger.log(`Slash Commands Loaded: ${slashCount}`, 'cmd');

    return { prefix: prefixCount, slash: slashCount };
};
