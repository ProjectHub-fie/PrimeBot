/**
 * Ergonomic emoji helpers.
 *
 *   const { emoji } = require('../utils/emoji');
 *   content: `${emoji('success')} Saved`
 *   .setTitle(`${emoji('music')} Now playing`)
 *
 * Every call resolves against the central catalog (`utils/emojiManager.js`) and
 * degrades to Unicode when the custom emoji is not available.
 */

const manager = require('./emojiManager');

function emoji(name, fallback) {
    return manager.emoji(name, fallback);
}

function renderText(text) {
    return manager.renderText(text);
}

function componentEmoji(name, fallback) {
    const instance = manager.getEmojiManager();
    if (instance) return instance.forComponent(name, fallback);
    return fallback || manager.fallbackFor(name);
}

function getEmojiManager() {
    return manager.getEmojiManager();
}

module.exports = {
    emoji,
    renderText,
    componentEmoji,
    getEmojiManager,
    fallbackFor: manager.fallbackFor,
};
