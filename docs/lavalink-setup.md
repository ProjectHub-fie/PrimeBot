# Lavalink setup (optional playback engine)

PrimeBot ships two playback engines and **defaults to the original direct
engine**. Nothing in this document is required for normal operation.

| Engine | How audio is produced | Default |
| --- | --- | --- |
| `direct` | In-process: `@distube/ytdl-core` / `soundcloud-core` / plain HTTP → `ffmpeg` → `@discordjs/voice` | ✅ yes |
| `lavalink` | A [Lavalink](https://github.com/lavalink-devs/Lavalink) server (Shoukaku + Kazagumo) decodes and streams; the bot only sends voice updates | no |

Both engines serve the **same commands, aliases, embeds, queue, playlists, DJ
permissions, 24/7 sessions and dashboard**. Only *where the audio is decoded*
changes.

## 1. Enable Lavalink

```bash
# .env
MUSIC_ENGINE=lavalink
LAVALINK_NODES=[{"name":"main","host":"lavalink.example.com","port":443,"password":"CHANGE_ME","secure":true}]
```

A single node can also be described with individual variables:

```bash
LAVALINK_HOST=lavalink.example.com
LAVALINK_PORT=2333
LAVALINK_PASSWORD=CHANGE_ME
LAVALINK_SECURE=false
LAVALINK_NAME=main
```

Restart the bot. The startup log prints the resolved engine and the configured
nodes (host + port only — **passwords are never logged**):

```
[MANAGERS] MusicManager loaded (engine: lavalink).
[LAVALINK] Manager created — 1 node(s) from LAVALINK_NODES (main@lavalink.example.com:443 (secure))
```

If `MUSIC_ENGINE=lavalink` but no usable node is configured, or the packages
are missing, the bot logs the reason and **falls back to `direct`** so music
never breaks:

```
[MUSIC] Lavalink engine unavailable (<reason>) — falling back to the direct engine.
```

## 2. Configuration reference

### Node entries

| Field | Required | Notes |
| --- | --- | --- |
| `name` | no | Defaults to `node-<n>`; duplicates are made unique automatically. |
| `host` | **yes** | Hostname or IP. |
| `port` | no | Defaults to `443` when `secure`, else `2333`. |
| `password` | **yes** | The Lavalink `lavalink.server.password`. |
| `secure` | no | `true` for `wss://`/`https://` (default `false`). |

A `url` field is also accepted (`wss://host:8443`) and is split into
host/port/secure.

Invalid entries are **dropped with a logged reason** — a bad entry never
aborts startup and never produces a node the bot silently cannot reach.

### Tuning (all optional)

| Variable | Default | Meaning |
| --- | --- | --- |
| `LAVALINK_SEARCH_ENGINE` | `ytsearch` | Kazagumo default search engine. |
| `LAVALINK_RECONNECT_TRIES` | `3` | Shoukaku's own reconnect attempts per node. |
| `LAVALINK_RECONNECT_INTERVAL_MS` | `5000` | Shoukaku's reconnect interval. |
| `LAVALINK_REST_TIMEOUT_MS` | `10000` | REST request timeout. |
| `LAVALINK_VOICE_TIMEOUT_S` | `20` | Lavalink's voice-connect timeout. |
| `LAVALINK_MAX_RECONNECT_ATTEMPTS` | `5` | PrimeBot's bounded backoff attempts before parking a node. |
| `LAVALINK_NODE_COOLDOWN_MS` | `60000` | How long a parked node is skipped before retrying. |
| `LAVALINK_BACKOFF_BASE_MS` / `_MAX_MS` | `2000` / `120000` | Exponential backoff base and cap (jittered ±20%). |

## 3. Audio sources (per source, honest status)

A source only works if the **node** advertises it. PrimeBot reads the node's
`sourceManagers` and never claims a source it cannot see.

| Source | Requirement | Status |
| --- | --- | --- |
| **Direct audio URLs** (`http`/`https` to an audio file) | Lavalink's built-in `http` source | Works on a stock node. |
| **YouTube** | Built-in `youtube` source | Works on a stock Lavalink v4 node. YouTube sometimes requires an updated `youtube-source` plugin — install it if search/playback returns `LOAD_FAILED`. |
| **SoundCloud** | Built-in `soundcloud` source | Works on a stock node. |
| **Search (free text)** | The node's search engine (`ytsearch`/`scsearch`) | Works on a stock node. |
| **Spotify** | **Plugin required** (e.g. LavaSrc, or Lavalink v4's Spotify source with a client id/secret) | **Not native.** Without a plugin, PrimeBot keeps its existing behaviour: Spotify links are resolved for *metadata* (title/artist/artwork) and then matched to a streamable source (YouTube/SoundCloud). It never claims native Spotify audio streaming. |

To add Spotify audio on the server side, install and configure a plugin on the
Lavalink node and set its credentials **on the node**, not in PrimeBot:

```yaml
# Lavalink application.yml (node side)
plugins:
  lavasrc:
    sources:
      spotify: true
    spotify:
      clientId: "${SPOTIFY_CLIENT_ID}"
      clientSecret: "${SPOTIFY_CLIENT_SECRET}"
```

PrimeBot does not need those credentials. It detects the advertised source at
runtime and will then accept `sp:...` identifiers.

## 4. Running a Lavalink node

`docker-compose.yml`:

```yaml
services:
  lavalink:
    image: ghcr.io/lavalink-devs/lavalink:4
    restart: unless-stopped
    environment:
      - _JAVA_OPTIONS=-Xmx1G
      - SERVER_PORT=2333
      - LAVALINK_SERVER_PASSWORD=CHANGE_ME
      - LAVALINK_SERVER_SOURCES_YOUTUBE=true
      - LAVALINK_SERVER_SOURCES_BANDCAMP=true
      - LAVALINK_SERVER_SOURCES_SOUNDCLOUD=true
      - LAVALINK_SERVER_SOURCES_TWITCH=true
      - LAVALINK_SERVER_SOURCES_HTTP=true
    volumes:
      - ./plugins:/opt/Lavalink/plugins
    ports:
      - "2333:2333"
```

The node needs outbound UDP/TCP to Discord's voice servers (`*.discord.gg`,
port range 50000–65535) to join voice channels. If a node is behind a
restrictive firewall, players will connect but never become ready.

**Capacity:** Lavalink does the decoding, so the bot process stays light. A
single modest node (1 vCPU / 1 GB) comfortably handles the 5–20 simultaneous
sessions PrimeBot targets, but that is a planning figure, **not** a measured
result — see the limitations section of the migration report.

## 5. Troubleshooting

| Symptom | Meaning | Action |
| --- | --- | --- |
| `[LAVALINK] … config problem(s)` at boot | An entry was dropped | Fix `LAVALINK_NODES` (host + password are required). |
| `No healthy Lavalink node is available (n1:failed)` | Every node is parked | Check the node is up, the password matches, and UDP to Discord is open. |
| `Lavalink could not resolve "<title>"` | The node could not find/stream the track | Install the `youtube-source` plugin, or try another source. |
| `[LAVALINK] Node n1 closed (code 4001)` | Bad password | Recheck `password` in `LAVALINK_NODES` vs `application.yml`. |
| Player connects but no audio | UDP blocked, or a `voiceConnectionTimeout` | Open UDP to Discord, raise `LAVALINK_VOICE_TIMEOUT_S`. |
| `MUSIC_ENGINE=lavalink` but log says `falling back to the direct engine` | Not configured / packages missing | Read the logged reason; music keeps working on `direct`. |

## 6. Rolling back to direct playback

```bash
MUSIC_ENGINE=direct     # or delete the variable entirely
```

Restart the bot. Existing 24/7 sessions are re-created by the direct engine on
`ready`; queues are not carried across an engine switch (see the limitations
section). No database change and no migration are involved — the engine switch
is pure configuration.
