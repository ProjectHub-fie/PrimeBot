#!/usr/bin/env node
/**
 * Static emoji migration report.
 *
 * Prints the catalog that PrimeBot ships (Linix's exact mapping) plus the
 * semantic/Unicode mapping coverage. This does NOT contact Discord — live
 * guild emoji counts, the `emoji list` channel ids and per-guild availability
 * come from `client.emojiManager.report()` at bot runtime (see the boot log).
 *
 * Usage:
 *   node scripts/emoji-report.js
 *   node scripts/emoji-report.js --json
 */

const {
    DEFAULT_EMOJI_GUILDS,
    LINIX_EMOJI_CATALOG,
    SEMANTIC_ALIASES,
    UNICODE_TO_SEMANTIC,
    EMOJI_FALLBACKS,
    HELP_CATEGORY_EMOJI,
} = require('../shared/emojiCatalog');

function buildReport() {
    const entries = Object.entries(LINIX_EMOJI_CATALOG);
    const uniqueIds = new Set(entries.map(([, e]) => e.id));
    const semanticKeys = new Set(Object.values(SEMANTIC_ALIASES));

    const byKey = entries.map(([key, entry]) => ({
        key,
        name: entry.name,
        id: entry.id,
        animated: entry.animated,
        raw: `<${entry.animated ? 'a' : ''}:${entry.name}:${entry.id}>`,
        fallback: EMOJI_FALLBACKS[key] || null,
    }));

    const missingFallbacks = [...semanticKeys].filter(key => !EMOJI_FALLBACKS[key]);
    const unmappedUnicode = Object.entries(UNICODE_TO_SEMANTIC).map(([unicode, key]) => ({ unicode, key }));

    return {
        configuredGuildIds: [...DEFAULT_EMOJI_GUILDS],
        priority: [...DEFAULT_EMOJI_GUILDS],
        catalogEntries: entries.length,
        catalogUniqueIds: uniqueIds.size,
        animated: entries.filter(([, e]) => e.animated).length,
        static: entries.filter(([, e]) => !e.animated).length,
        semanticAliases: Object.keys(SEMANTIC_ALIASES).length,
        unicodeMappings: unmappedUnicode.length,
        helpCategories: { ...HELP_CATEGORY_EMOJI },
        missingFallbacks,
        byKey,
        unicode: unmappedUnicode,
    };
}

const report = buildReport();

if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
    console.log('PrimeBot custom-emoji catalog (Linix mapping, no credentials)');
    console.log('='.repeat(68));
    console.log(`Guilds (priority order): ${report.configuredGuildIds.join(', ')}`);
    console.log(`Catalog entries: ${report.catalogEntries} (${report.catalogUniqueIds} unique ids)`);
    console.log(`Animated: ${report.animated}  Static: ${report.static}`);
    console.log(`Semantic aliases: ${report.semanticAliases}  Unicode mappings: ${report.unicodeMappings}`);
    console.log(`Missing Unicode fallbacks: ${report.missingFallbacks.length ? report.missingFallbacks.join(', ') : 'none'}`);
    console.log('');
    console.log('key              emoji                       id                   animated  fallback');
    for (const row of report.byKey) {
        console.log(
            row.key.padEnd(16),
            row.raw.padEnd(27),
            row.id.padEnd(20),
            String(row.animated).padEnd(9),
            row.fallback || ''
        );
    }
    console.log('');
    console.log('Live report at runtime: client.emojiManager.report()  (or the [EMOJI] boot log)');
}

module.exports = { buildReport };
