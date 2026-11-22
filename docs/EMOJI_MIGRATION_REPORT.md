# Custom emoji migration report

This report describes the PrimeBot custom-emoji integration built from Linix's
emoji mapping. It contains no credentials.

## Emoji servers

| Priority | Guild ID | Role |
| --- | --- | --- |
| 1 | `1190256755096158208` | first choice for duplicate names |
| 2 | `1127600524586401792` | second choice |
| 3 | `1222896507838009394` | third choice |

Priority is the array order in `shared/emojiCatalog.js` (`DEFAULT_EMOJI_GUILDS`)
and can be overridden with `EMOJI_GUILD_IDS` (comma separated, left to right).

Each guild is expected to contain a read-only text channel named **`emoji list`**
(`emoji-list`, `emojilist`, `emojis` and `emoji` are also accepted). PrimeBot
reads those channels and never writes to them.

## Catalog size

| Metric | Value |
| --- | --- |
| Linix catalog entries | **98** |
| Unique emoji ids | **92** |
| Animated emojis | **2** (`Playing`, `loading`) |
| Static emojis | **96** |
| Semantic aliases | **128** |
| Unicode → semantic mappings | **138** |

The 98/92 figures are the exact Linix mapping reproduced from Linix
`index.js` → `client.emoji`. The live per-guild counts (and the actual source
guild of every emoji) are produced at runtime by
`client.emojiManager.report()` — see the `[EMOJI]` boot log. No Discord token
was used to generate this static report.

## How it works

1. **Discovery** — `utils/emojiManager.js` fetches the configured guilds
   (retry + timeout + backoff), fetches each `guild.emojis` collection, and
   reads every message in the `emoji list` channel (paginated).
2. **Parsing** — every `<:name:id>` / `<a:name:id>` token is recorded with its
   name, id and animated flag. Lines such as `success : <:yes:…>`,
   `:success: <:yes:…>` and embed titles/fields add semantic aliases and
   category headings.
3. **Validation** — a candidate is usable only when its id exists in the live
   `guild.emojis` collection, `emoji.available !== false`, and the guild is
   available. Being a member of the emoji guild is not treated as proof of
   access.
4. **Deduplication** — duplicate names are resolved by the guild priority
   order above (channel-declared aliases beat generic names inside the same
   guild). Every conflict is recorded in `report().conflicts`; nothing is
   silently overwritten.
5. **Caching** — the resolved map is held in memory. It is rebuilt on
   `emojiCreate` / `emojiDelete` / `emojiUpdate` / `guildCreate` / `guildDelete`
   (debounced 5s) and on a 6-hour TTL. No per-message API call is made.
6. **Fallback** — `emoji('key')` returns the custom emoji when validated,
   otherwise the caller's fallback, otherwise the catalog's Unicode fallback.
   Missing guilds, missing emojis, renamed emojis and permission errors never
   throw into a command.
7. **Rendering** — `utils/emojiTransformer.js` installs a REST-boundary
   transformer on the bot client. It rewrites `content`, embed text and
   component `emoji` fields for message routes only, and skips code spans,
   fenced code blocks, URLs and existing custom emoji markup.

## Implementation files

| File | Purpose |
| --- | --- |
| `shared/emojiCatalog.js` | single source of truth: guild ids, Linix 98-entry catalog, semantic aliases, Unicode map, Unicode fallbacks, help-category map |
| `utils/emojiManager.js` | discovery, validation, caching, priority, fallbacks, report, legacy `$emoji` store |
| `utils/emoji.js` | `emoji('success')` / `renderText()` / `componentEmoji()` helpers |
| `utils/emojiTransformer.js` | REST-boundary payload transformer (content + embeds + components) |
| `index.js` | creates the manager and installs the transformer |
| `events/ready.js` | starts the catalog fetch on ready and logs the report |
| `commands/help.js` | slash help category headings + buttons |
| `utils/prefixHelp.js` | prefix/sash help category headings, fields and select options |
| `events/interactionCreate.js` | help button menu + Sash menu categories |
| `music/clientBridge.js` | overlays validated custom emoji onto `client.emoji` |
| `music/config.js` | uses the shared fallback map instead of a duplicated literal table |
| `music/utils/progressbar.js` | resolves the slider emoji through the manager |
| `scripts/emoji-report.js` | static report (`npm run emoji:report`) |
| `tests/emojiCatalog.test.js` | catalog, discovery, priority, fallback, renderer and transformer tests |

## References replaced

* **Help menu** — every category renders as `<custom emoji> Category` in the
  main embed fields, drill-down titles, slash-command buttons, Sash menu fields
  and buttons, and the prefix category select menu.
* **Music** — `client.emoji.*` is resolved through the manager, so all vendored
  Linix music embeds/buttons use the validated custom emoji. The progress-bar
  slider (`dot`) is resolved the same way. The old duplicated Unicode table in
  `music/config.js` was removed; it now reads the shared fallback map.
* **All outgoing Discord messages** — the REST transformer replaces mapped
  Unicode in message content and embed text across commands, events, utilities,
  tickets, automod, anti-nuke, events, moderation, leveling, music, logs and
  audit messages. Component `emoji` fields (buttons/select options) are upgraded
  from Unicode to validated emoji objects.
* **Legacy `$emoji` list** — the pagination buttons and title use the manager.

Measured in the bot source tree (`commands/`, `events/`, `utils/`, `music/`,
`shared/`, `server/`, `index.js`, `config.js`, `deploy-commands.js`):
**936 mapped Unicode occurrences** are covered by the transformer, plus the
explicit helper calls above.

## Intentionally retained symbols

* Functional arrows and bullets: `→`, `←`, `↔`, `⇒`, `➜`, `❯`, `•`, `●`, `◉`.
* The progress-bar line character `▬` (it is a bar, not an emoji).
* Unicode variation selectors (`U+FE0F`) that are part of a sequence.
* Emojis with no Linix equivalent, e.g. `🧪`, `🔒`, `🔓`, `🔑`, `📨`, `📅`,
  `➕`, `🤖`, `🔗`, `🎯`, `⭕`, `🕐`, `🤔`, `🔥`, `🌌`, `🎨`, `🏛`, `🔜`, `📡`,
  `🖥`, `📜`, `💀`, `🏁`, `🌍`, `🚀`, `🔮`, `🙈`, `🧩`, `🔌`, `💾`, `🍀`, `🌱`.
  These keep their Unicode form so the bot never renders a broken custom emoji.
* **Reaction emoji** (e.g. the giveaway entry reaction) are left untouched:
  the reaction route is not transformed, so the bot's reaction and the text
  instructions stay identical.
* **Dashboard UI** is not a Discord message surface and is unchanged (it uses
  the SVG icon system).

## Duplicate / unavailable emojis

Duplicates and unavailable entries are not hardcoded — they depend on the live
emoji servers. Call `client.emojiManager.report()` (or read the `[EMOJI]` boot
log) to get:

* `guilds[]` — per-guild `emojiCount`, `channelFound`, `channelId`,
  `discoveredCount`, `error`
* `entries[]` — every resolved emoji with its `sourceGuildId`
* `conflicts[]` — kept vs rejected id + guild for each duplicate name
* `unavailable[]` — catalog/channel entries not present in a live collection,
  with the reason (`not_in_live_guild_emoji_collection`, `emoji_unavailable`)

## Validation

* `node --test tests/emojiCatalog.test.js` — 16 tests covering catalog
  integrity, semantic + animated resolution, live-collection validation,
  deterministic priority and conflict reporting, channel parsing, unavailable
  guild handling, permission errors, caching, Unicode-safe rendering, embeds,
  buttons/selects, interaction callbacks, token redaction and route filtering.
* `node --test tests/*.test.js` — full suite (1177 tests) passes.
* `npm run emoji:report` — prints the static catalog.
