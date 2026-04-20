# flux configuration

Every knob is an environment variable. Flux has no config file.

## Required (or near-required)

| Var | Default | Notes |
| --- | --- | --- |
| `TRACEBIT_ENV_HOSTS_CSV` | *(empty)* | Comma-separated list of `Host` header values to treat as "trap sensors". Leave empty on a control sensor — flux will 404 every trap path. |

## Tracebit Community integration (optional)

If `TRACEBIT_API_KEY` is unset, flux still works: the tarpit and webshell
traps do not need it. Only `/.env` and `/.git/*` require a key, because
those traps mint per-request canaries at hit time.

| Var | Default | Notes |
| --- | --- | --- |
| `TRACEBIT_API_KEY` | *(empty)* | Bearer token. **When unset, `/.env` and `/.git/*` are disabled and return 404.** |
| `TRACEBIT_API_BASE_URL` | `https://community.tracebit.com` | |
| `TRACEBIT_ENV_CANARY_TYPES_CSV` | `aws` | Any of `aws`, `ssh`, `gitlab-cookie`, `gitlab-username-password`. |
| `TRACEBIT_ENV_CANARY_SOURCE` | `flux` | `source` label on issued canaries. |
| `TRACEBIT_ENV_CANARY_SOURCE_TYPE` | `endpoint` | `sourceType` label. |
| `SENSOR_ID` | *(empty)* | Optional free-text sensor id, included in canary labels and request names. |

## Logging

| Var | Default | Notes |
| --- | --- | --- |
| `TRACEBIT_ENV_LOG_PATH` | `/var/log/honeypot/tracebit/env-canary.jsonl` | One JSON line per event. Parent dir is created on first write. |

## Tarpit

| Var | Default | Notes |
| --- | --- | --- |
| `TRACEBIT_ENV_TARPIT_ENABLED` | **on** | Master switch for the tarpit + fingerprint modules. |
| `TRACEBIT_ENV_TARPIT_SECONDS` | `0` | Max duration per response. `0` = stream until the client hangs up. |
| `TRACEBIT_ENV_TARPIT_CHUNK_BYTES` | `32` | |
| `TRACEBIT_ENV_TARPIT_INTERVAL_MS` | `2000` | |
| `TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS` | `8` | Concurrent tarpit responses per process. Shared with the fake-git drip. |

### Fingerprint paths

The tarpit originally only fired on `.env` variants; that missed scanners
who weren't hunting for `.env` files. These paths route into the same
tarpit + module chain for first-contact fingerprinting.

| Var | Default | Notes |
| --- | --- | --- |
| `FINGERPRINT_PATHS_ENABLED` | **on** | Route generic paths through the fingerprint chain. |
| `FINGERPRINT_PATHS_CSV` | `/,/index.html,/index.php,/robots.txt,/sitemap.xml,/favicon.ico` | Case-insensitive exact-match. |

### Tarpit modules

Each is independently toggleable. When multiple *terminal* modules are
enabled, the first match wins in module-registration order.

**All default to ON** — flux is a honeypot, the whole point is to
fingerprint. Set any single var to `false` / `0` to disable just that one.

| Var | Default | Notes |
| --- | --- | --- |
| `TARPIT_MOD_DNS_CALLBACK_ENABLED` | on | Redirect to `<uuid>.$TARPIT_MOD_DNS_CALLBACK_DOMAIN` to fingerprint DNS resolution. **No-op unless `TARPIT_MOD_DNS_CALLBACK_DOMAIN` is also set.** |
| `TARPIT_MOD_DNS_CALLBACK_DOMAIN` | *(empty)* | Needs a wildcard record pointing back at a logging endpoint. |
| `TARPIT_MOD_COOKIE_ENABLED` | on | Set `_hp_tid=<uuid>`; detect persistent cookie jars and cross-IP reuse. |
| `TARPIT_MOD_REDIRECT_CHAIN_ENABLED` | on | Issue a chain of 302s up to N hops, then fall through to the tarpit stream. |
| `TARPIT_MOD_REDIRECT_CHAIN_MAX_HOPS` | `5` | |
| `TARPIT_MOD_VARIABLE_DRIP_ENABLED` | on | Start fast (500ms) and exponentially slow down to `MAX_MS` to fingerprint client timeouts. |
| `TARPIT_MOD_VARIABLE_DRIP_INITIAL_MS` | `500` | |
| `TARPIT_MOD_VARIABLE_DRIP_MAX_MS` | `16000` | |
| `TARPIT_MOD_CONTENT_LENGTH_MISMATCH_ENABLED` | on | Claim `Content-Length: 1048576` then drip slowly. |
| `TARPIT_MOD_CONTENT_LENGTH_CLAIMED_BYTES` | `1048576` | |
| `TARPIT_MOD_ETAG_PROBE_ENABLED` | on | Set `ETag` / `Last-Modified`; log conditional requests on repeat visits. |

## Canary-backed file traps

A table of paths that serve a plausible file format with a freshly-minted
Tracebit canary embedded. See [`ROADMAP.md`](./ROADMAP.md) for the current
list. Gated on `ALLOWED_HOSTS` being non-empty (trap sensor) **and**
`TRACEBIT_API_KEY` being set. Per-IP cache keeps scanner fan-out from
burning quota.

| Var | Default | Notes |
| --- | --- | --- |
| `CANARY_TRAPS_ENABLED` | **on** | Master switch. |
| `CANARY_TRAP_CACHE_TTL_SECONDS` | `3600` | Per-(IP, canary types) TTL. |
| `CANARY_TRAP_CACHE_MAX_ENTRIES` | `1024` | |

## Fake `/.git/*` tree

Requires `TRACEBIT_API_KEY`.

| Var | Default | Notes |
| --- | --- | --- |
| `FAKE_GIT_ENABLED` | off | Master switch. |
| `FAKE_GIT_CACHE_TTL_SECONDS` | `3600` | Per-IP cache TTL — keeps object SHAs consistent across a scanner's fan-out. |
| `FAKE_GIT_CACHE_MAX_ENTRIES` | `1024` | |
| `FAKE_GIT_DRIP_BYTES` | `1024` | |
| `FAKE_GIT_DRIP_INTERVAL_MS` | `3000` | |
| `FAKE_GIT_AUTHOR` | `ops <ops@internal-tools.lan>` | Appears in the synthetic commit. |
| `FAKE_GIT_COMMIT_MESSAGE` | `Initial import of internal-tools` | |
| `FAKE_GIT_REMOTE_URL` | `git@github.com:internal/tools.git` | |

## Fake webshell

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_WEBSHELL_ENABLED` | on | |
| `HONEYPOT_WEBSHELL_PATHS_CSV` | *(built-in default list)* | Override to add/remove paths without a code change. |
| `HONEYPOT_WEBSHELL_BODY_READ_LIMIT` | `65536` | Max body bytes read off the wire. |
| `HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT` | `8192` | Max body bytes decoded for the log `bodyPreview`. |

## Bind address / port

Flux listens on `127.0.0.1:18081`. To change, edit `flux/server.py`:`main()`
— there's no env var because this is always a local backend behind a
reverse proxy in our use.
