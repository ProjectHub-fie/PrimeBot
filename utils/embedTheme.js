const config = require('../config');

const LEGACY_COLOR_MAP = new Map([
    [0x5865F2, 'primary'],
    [0x4752C4, 'secondary'],
    [0x57F287, 'success'],
    [0xED4245, 'error'],
    [0xFEE75C, 'warning'],
    [0xFFD700, 'gold'],
    [0xCD7F32, 'bronze'],
    [0xC0C0C0, 'silver'],
    [0xE5E4E2, 'platinum'],
]);

function colorToInteger(color) {
    if (typeof color === 'number' && Number.isInteger(color)) return color;
    if (typeof color === 'string' && /^#?[0-9a-f]{6}$/i.test(color)) {
        return Number.parseInt(color.replace(/^#/, ''), 16);
    }
    return null;
}

function themedColor(color) {
    const numericColor = colorToInteger(color);
    if (numericColor === null) return colorToInteger(config.colors.primary);
    const paletteKey = LEGACY_COLOR_MAP.get(numericColor);
    if (!paletteKey) return numericColor;
    return Number.parseInt(config.colors[paletteKey].replace(/^#/, ''), 16);
}

function createThemedEmbedBuilder(BaseEmbedBuilder) {
    if (BaseEmbedBuilder.__primeBotEmbedTheme) return BaseEmbedBuilder;

    class PrimeBotEmbedBuilder extends BaseEmbedBuilder {
        setColor(color) {
            const result = super.setColor(color);
            if (typeof this.data?.color === 'number') {
                this.data.color = themedColor(this.data.color);
            }
            return result;
        }

        toJSON() {
            const embed = super.toJSON();
            embed.color = themedColor(embed.color ?? config.colors.primary);
            return embed;
        }
    }

    Object.defineProperty(PrimeBotEmbedBuilder, '__primeBotEmbedTheme', {
        value: true,
    });

    return PrimeBotEmbedBuilder;
}

function installEmbedTheme(discord) {
    if (!discord?.EmbedBuilder) {
        throw new TypeError('A Discord.js module with EmbedBuilder is required.');
    }

    discord.EmbedBuilder = createThemedEmbedBuilder(discord.EmbedBuilder);
    return discord.EmbedBuilder;
}

module.exports = { installEmbedTheme };
