---
name: Discord.js runtime compatibility
description: Node and Discord.js dependency constraints needed for reliable bot startup.
---

Use Node.js 18 or newer for the bot. A malformed `@discordjs/util` package release can fail before application code loads with a syntax error, so keep Discord.js and its utility dependency on known-good compatible releases and verify the resolved installed versions after package changes.

**Why:** The bot initially combined an old Node runtime with a malformed transitive utility package; the process crashed before connecting to Discord.

**How to apply:** After dependency or `.replit` changes, check `node --version`, the installed Discord.js version, the installed `@discordjs/util` version, and the workflow logs before declaring the bot healthy.