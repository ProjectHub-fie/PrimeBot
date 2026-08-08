const config = require('../config');

function normalizeGuildPrefix(prefix, fallbackPrefix = config.prefix) {
    const value = typeof prefix === 'string' ? prefix.trim() : '';
    if (!value) return fallbackPrefix;
    if (value.length > 3 || /\s/.test(value)) return fallbackPrefix;
    return value;
}

module.exports = {
    normalizeGuildPrefix,
};
