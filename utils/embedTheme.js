/**
 * Global embed presentation.
 *
 * PrimeBot's embeds use the Linix card layout with NO colour: Discord would
 * otherwise paint a coloured bar down the left edge. Every `EmbedBuilder`
 * serializes without a `color`, and `shared/embedStyle.js` removes `color`
 * from raw object payloads / webhook bodies at the REST boundary.
 *
 * `setColor()` still exists on the builder (call sites keep working), but the
 * value is never serialized.
 */

function createPlainEmbedBuilder(BaseEmbedBuilder) {
    if (BaseEmbedBuilder.__primeBotEmbedTheme) return BaseEmbedBuilder;

    class PrimeBotEmbedBuilder extends BaseEmbedBuilder {
        toJSON() {
            const embed = super.toJSON();
            delete embed.color;
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

    discord.EmbedBuilder = createPlainEmbedBuilder(discord.EmbedBuilder);
    return discord.EmbedBuilder;
}

module.exports = { installEmbedTheme };
