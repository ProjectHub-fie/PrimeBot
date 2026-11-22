const { EmbedBuilder } = require('discord.js');

// Linix uses one flat embed colour for every card. PrimeBot's help cards follow
// Linix's layout but deliberately leave the colour unset, so Discord renders no
// coloured side stripe. Set LINIX_EMBED_COLOR if you ever want the stripe back.
const LINIX_COLOR = process.env.LINIX_EMBED_COLOR || null;
const LINIX_IMAGE = process.env.LINIX_EMBED_IMAGE || null;

class LinixEmbed extends EmbedBuilder {
    constructor({ color = LINIX_COLOR } = {}) {
        super();
        if (color) this.setColor(color);
    }

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

function linixEmbed(options) {
    return new LinixEmbed(options);
}

function applyLinixImage(embed, url = LINIX_IMAGE) {
    if (url) embed.setImage(url);
    return embed;
}

module.exports = {
    LINIX_COLOR,
    LINIX_IMAGE,
    LinixEmbed,
    linixEmbed,
    applyLinixImage,
};
