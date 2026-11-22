const { EmbedBuilder } = require('discord.js');

/**
 * Linix's chainable embed helpers, with one deliberate difference: no colour.
 * Discord renders `color` as a coloured bar down the left edge, and PrimeBot's
 * cards are monochrome.
 */
class LinixEmbed extends EmbedBuilder {
    t(title) {
        this.setTitle(title);
        return this;
    }

    d(text) {
        this.setDescription(text);
        return this;
    }

    thumb(url) {
        if (url) this.setThumbnail(url);
        return this;
    }

    img(url) {
        if (url) this.setImage(url);
        return this;
    }

    a(text, icon) {
        if (text) this.setAuthor({ name: text, iconURL: icon });
        return this;
    }

    f(text, icon) {
        if (text) this.setFooter({ text, iconURL: icon });
        return this;
    }
}

function linixEmbed() {
    return new LinixEmbed();
}

module.exports = {
    LinixEmbed,
    linixEmbed,
};
