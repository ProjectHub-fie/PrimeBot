/**
 * Tolerance layer for Linix's permission declarations.
 *
 * Linix declares slash/prefix `botPrams` / `userPrams` with SCREAMING_SNAKE
 * aliases (e.g. `["EMBED_LINKS"]`, `["Connect", "Speak"]`) exactly as they
 * were written for an older discord.js. The installed discord.js v14
 * `PermissionsBitField.Flags` only knows the camelCase names (`EmbedLinks`,
 * `Connect`, `Speak`), and `PermissionsBitField.resolve()` **throws** on an
 * unknown flag — which broke every music command on startup. These helpers map
 * the legacy snake-case spellings onto the real flag names and skip any that
 * still have no equivalent, so a permission check can never crash.
 */

const { PermissionsBitField } = require('discord.js');

/** Alias map: SCREAMING_SNAKE -> camelCase discord.js flag. */
const SNAKE_TO_FLAG = {};
for (const flag of Object.keys(PermissionsBitField.Flags)) {
    SNAKE_TO_FLAG[flag] = flag; // camelCase itself
    // EMBED_LINKS (only a lowercase→uppercase boundary gets an underscore,
    // so the leading letter is not doubled)
    const snake = flag.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();
    SNAKE_TO_FLAG[snake] = flag;
}

/**
 * Resolve a list of permission names to a permission bitfield, accepting both
 * the discord.js camelCase names and Linix's legacy SCREAMING_SNAKE names.
 * Unknown names are dropped; an empty/absent list yields `0n`.
 * @param {string[]} [perms]
 * @returns {bigint}
 */
function resolvePerms(perms) {
    const names = Array.isArray(perms) ? perms : [];
    const flags = [];
    for (const name of names) {
        const flag = SNAKE_TO_FLAG[String(name)];
        if (flag) flags.push(flag);
    }
    return flags.length ? PermissionsBitField.resolve(flags) : 0n;
}

module.exports = { resolvePerms };