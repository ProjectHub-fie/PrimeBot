---
name: Discord embed style
description: PrimeBot's embed appearance direction and emoji ownership.
---

Use the user's Figma Page 1 as the reference for PrimeBot embeds: Discord's dark native embed layout with a violet primary accent and distinct semantic colors for status. Do not add emoji glyphs to new embed styling. The user plans to add custom emojis from the Discord Developer Portal later. Preserve existing and user-supplied emoji content unless they ask to remove or replace it.

**Why:** the user requested consistent embeds based on Page 1, with different colors, and said they will add the bot's custom emojis later.

**How to apply:** when creating or restyling bot embeds, keep the common layout and color system consistent, and leave new emoji placement to the user.

**Palette (config.colors — the only source of truth for system embed colors):**
`primary #7B2CBF` (violet accent), `secondary #572080`, `success #2E9D75`, `error #D94F5D`, `warning #D99A35`, `gold #C18D32`, `bronze #A7653A`, `silver #929BA6`, `platinum #788493`. User-chosen colors (embed builder, ticket panels, broadcast wizard options, per-guild logging colors) are preserved as-is and never remapped.

**Theme layer:** `utils/embedTheme.js` installs a themed `EmbedBuilder` at boot. Embeds without an explicit color get `primary`; explicit legacy Discord colors (`0x5865F2`, `0x57F287`, `0xED4245`, `0xFEE75C`, `0xFFD700`, `0x4752C4`, `0xCD7F32`) are remapped to the palette. Arbitrary custom hexes are preserved unchanged (pinned by `tests/embedTheme.test.js`).

**Source-site rule (learned):** do NOT extend the theme map to cover more legacy/off-palette colors — custom colors must stay preserved (`#FFC0CB` stays). Fix non-preset system colors at their source instead (use `config.colors.*` directly).

**Catalog colors now on the palette:** `utils/automodRules.js` SEVERITIES (low=success, medium=warning, high=gold, critical=error), `utils/botRoles.js` ROLE_INFO (user=silver, moderator=success, admin=warning, developer=primary, owner=gold), `shared/eventConstants.js` EVENT_TYPES/EVENT_STATUSES/PARTICIPANT_STATUSES/ATTENDANCE_STATUSES all palette hexes. `utils/logEvents.js` + `shared/ticketLogging.js` still use legacy presets but the theme layer remaps them at runtime (asserted in `tests/embedPaletteConsistency.test.js`).

**Raw-object bypass:** `utils/webhookLogger.js` posts raw embed objects via `https.request` (skips the themed EmbedBuilder), so its `COLORS` map now derives from `config.colors`. When adding a new raw-HTTP webhook embed, map colors from `config.colors` explicitly.

**Existing tests:** `tests/embedPaletteConsistency.test.js` (new) locks catalogs to the palette and statically forbids off-palette hexes in countingManager/birthdayManager/webhookLogger/appeal/snipe.
