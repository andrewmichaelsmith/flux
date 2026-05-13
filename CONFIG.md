# flux configuration

Every knob is an environment variable. Flux has no config file.

Flux does **not** gate on the `Host` header. Every trap responds on every
host the sensor receives. If you don't want traps, don't run flux.

## Tracebit Community integration (optional)

If `TRACEBIT_API_KEY` is unset, flux still works: the tarpit and webshell
traps do not need it. Only the canary-backed traps (`/.env`, `/.git/*`,
and the canary file trap table) need a key, because those mint per-request
canaries at hit time.

| Var | Default | Notes |
| --- | --- | --- |
| `TRACEBIT_API_KEY` | *(empty)* | Bearer token. **When unset, canary-backed traps are disabled and return 404.** |
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
| `TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS` | `256` | Concurrent tarpit responses per process. Shared with the fake-git drip. Each held drip is ~8 KB of coroutine state (not a thread). |

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
Tracebit canary embedded. See [README](./README.md#canary-file-trap-table)
for the full list of paths and per-trap canary types. Gated on
`TRACEBIT_API_KEY` being set. Per-IP cache keeps scanner fan-out from
burning quota.

| Var | Default | Notes |
| --- | --- | --- |
| `CANARY_TRAPS_ENABLED` | **on** | Master switch. |
| `CANARY_TRAP_CACHE_TTL_SECONDS` | `3600` | Per-(IP, canary types) TTL. |
| `CANARY_TRAP_CACHE_MAX_ENTRIES` | `1024` | |

## Fake `/.git/*` tree

Requires `TRACEBIT_API_KEY`. Default-on, but still 404s on every hit
when `TRACEBIT_API_KEY` is unset — the dispatch requires both.

| Var | Default | Notes |
| --- | --- | --- |
| `FAKE_GIT_ENABLED` | **on** | Master switch. |
| `FAKE_GIT_CACHE_TTL_SECONDS` | `3600` | Per-IP cache TTL — keeps object SHAs consistent across a scanner's fan-out. |
| `FAKE_GIT_CACHE_MAX_ENTRIES` | `1024` | |
| `FAKE_GIT_DRIP_BYTES` | `1024` | |
| `FAKE_GIT_DRIP_INTERVAL_MS` | `3000` | |
| `FAKE_GIT_AUTHOR` | `ops <ops@internal-tools.lan>` | Appears in the synthetic commit. |
| `FAKE_GIT_COMMIT_MESSAGE` | `Initial import of internal-tools` | |
| `FAKE_GIT_REMOTE_URL` | *unset* | Operator override for the `[remote "origin"] url` line. When unset (default), the URL is built per-request from the Tracebit canary so that scrapers who only fetch `.git/config` still leak a canary in the URL userinfo. Set this to a static string to suppress that embedding (e.g. in staging where you don't want canary burn on every hit). |
| `FAKE_GIT_REMOTE_HOST` | `github.com` | Host portion of the generated canary URL. |
| `FAKE_GIT_REMOTE_PATH` | `internal/tools.git` | Path portion of the generated canary URL. |

## Fake webshell

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_WEBSHELL_ENABLED` | on | |
| `HONEYPOT_WEBSHELL_PATHS_CSV` | *(built-in default list)* | Override to add/remove paths without a code change. |
| `HONEYPOT_WEBSHELL_BODY_READ_LIMIT` | `65536` | Max body bytes read off the wire. |
| `HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT` | `8192` | Max body bytes decoded for the log `bodyPreview`. |

## Fake file-upload responder

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_FILE_UPLOAD_ENABLED` | on | Master switch. Covers KCFinder, jquery.filer, and Blueimp jQuery-File-Upload. |
| `HONEYPOT_FILE_UPLOAD_BODY_DECODE_LIMIT` | `8192` | Max body bytes decoded for the log `bodyPreview`. Full body sha256 is always recorded via the standard envelope. |
| `HONEYPOT_FILE_UPLOAD_MAX_PARTS` | `16` | Multipart parts enumerated per request (cap on `fileUploadFieldNames` / `fileUploadFilenames` / `fileUploadPartContentTypes`). |

## Web-app form responder

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_WEBAPP_FORM_ENABLED` | on | Master switch. |
| `HONEYPOT_WEBAPP_FORM_EXTRA_PATHS_CSV` | empty | Operator extras claimed in addition to the built-in path set; mapped to the generic `webapp-form-form` result tag (built-ins keep their per-group classification: `login`/`signup`/`checkout`/`contact`/`profile`). |
| `HONEYPOT_WEBAPP_FORM_BODY_PREVIEW_LIMIT` | `400` | Bytes of POST body decoded into the `bodyPreview` log field. Full body sha256 is always recorded via the standard envelope. |

## Fake LLM-API endpoint

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_LLM_ENDPOINT_ENABLED` | on | Master switch. |
| `HONEYPOT_LLM_ENDPOINT_PATHS_CSV` | *(built-in — `/v1/models`, `/anthropic/v1/models`, `/api/version`, `/api/tags`, `/api/ps`, `/api/show`, `/api/chat`, `/api/generate`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/messages`, `/anthropic/v1/messages`)* | Exact, case-insensitive. Override to add/remove without a code change. |
| `HONEYPOT_LLM_BODY_DECODE_LIMIT` | `4096` | Max chars of the extracted `llmPromptPreview` written to the log. The raw body is still capped by `HONEYPOT_WEBSHELL_BODY_READ_LIMIT` (shared cap, default 64 KiB off the wire). |

## Fake SonicWall SSL VPN

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_SONICWALL_ENABLED` | on | Master switch. |
| `HONEYPOT_SONICWALL_PATHS_CSV` | *(built-in — `/api/sonicos/is-sslvpn-enabled`, `/api/sonicos/auth`, `/api/sonicos/tfa`)* | Exact, case-insensitive. Override to add/remove without a code change. |

The POST body read cap is shared with the webshell trap
(`HONEYPOT_WEBSHELL_BODY_READ_LIMIT`, default 64 KiB off the wire) and
the decoded preview written to the log is capped by
`HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT` (default 8 KiB).

## Fake FortiGate SSL VPN (CVE-2024-21762 / CVE-2023-27997 / CVE-2024-48887 bait)

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_FORTIGATE_VPN_ENABLED` | on | Master switch. |
| `HONEYPOT_FORTIGATE_VPN_PATHS_CSV` | *(built-in — `/remote/login`, `/remote/logincheck`, `/remote/fgt_lang`, `/remote/error`, `/api/v2/cmdb/system/admin`, `/api/v2/cmdb/system/status`, `/api/v2/cmdb/system/global`, `/api/v2/monitor/router/policy`)* | Exact, case-insensitive. Override to add/remove without a code change. |
| `HONEYPOT_FORTIGATE_VPN_VERSION` | `7.4.4` | FortiOS version banner shown in the HTML comment + REST envelopes. Pinned to a build inside the CVE-2024-21762 / CVE-2023-27997 vulnerable window so banner-grab scrapers ship the exploit body. |
| `HONEYPOT_FORTIGATE_VPN_BUILD` | `2662` | FortiOS build number paired with the version string. |

The `SVPNCOOKIE` minted on `/remote/logincheck` and the `FGVM…` serial
in the `/api/v2/cmdb/system/{status,global}` and
`/api/v2/monitor/router/policy` envelopes are per-request unique
(`uuid4().hex`). No fixed credential / serial literals.

## Fake Citrix NetScaler / Gateway portal (CVE-2019-19781 / CVE-2023-3519 / CVE-2023-4966 / CVE-2022-27510 bait)

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_CITRIX_GATEWAY_ENABLED` | on | Master switch. |
| `HONEYPOT_CITRIX_GATEWAY_PATHS_CSV` | *(built-in — `/vpn/index.html`, `/logon/LogonPoint/index.html`, `/vpn/js/rdx/core/lang/rdx_en.json.gz`, `/cgi/login`, `/p/u/doAuthentication.do`, `/Citrix/XenApp/auth/login.aspx`)* | Exact, case-insensitive. The Gateway / NetScaler ADC SSL VPN endpoints exploited by Shitrix (CVE-2019-19781) and CitrixBleed (CVE-2023-4966), plus the StoreFront / XenApp auth surface targeted by CVE-2022-27510 / CVE-2023-24486. |
| `HONEYPOT_CITRIX_GATEWAY_VERSION` | `NS13.1: Build 49.13.nc` | NetScaler version banner embedded in the portal HTML comment. Pinned to a build inside the CVE-2023-4966 / CVE-2023-3519 vulnerable window so fingerprint scrapers ship the next-stage probe. |

The `NSC_AAAC` cookie minted on `/cgi/login` and `/p/u/doAuthentication.do`
is per-request unique (`uuid4().hex`); the cookie name matches the
real NetScaler Gateway session cookie that CVE-2023-4966 ("CitrixBleed")
leaks via heap memory, so any later request replaying a captured
cookie is attributable to the issuance event in the trap log. The
`citrixHasCmdInjection` flag fires on shell-meta indicators **and**
on CVE-2019-19781 path-traversal patterns (`/../`, `%2f..`, `..%2f`).

## Fake Microsoft RDWeb (RD Web Access)

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_RDWEB_ENABLED` | on | Master switch. |
| `HONEYPOT_RDWEB_PATHS_CSV` | *(built-in — `/RDWeb`, `/RDWeb/`, `/RDWeb/Pages/`, `/RDWeb/Pages/en-US/login.aspx`, `/RDWeb/Pages/en-US/Default.aspx`)* | Exact, case-insensitive. The Server 2019 RD Web Access landing + login + post-auth resource list. |
| `HONEYPOT_RDWEB_SERVER_BUILD` | `10.0.17763` | Windows Server build advertised in the RDWeb logon HTML footer. Server 2019 LTSC build matches the broad install base password-spraying scanners target. |

The `__VIEWSTATE` value embedded in the login HTML and the
`TSWAAuthHttpOnlyCookie` minted on `/RDWeb/Pages/en-US/login.aspx`
POSTs are per-request unique (`uuid4().hex`). The trap responds with
`Server: Microsoft-IIS/10.0` + `X-Powered-By: ASP.NET` so banner-grab
fingerprint scrapers ship the credential POST.

## Fake ColdFusion admin / component browser

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_COLDFUSION_ENABLED` | on | Master switch. |
| `HONEYPOT_COLDFUSION_PATHS_CSV` | *(built-in — `/indice.cfm`, `/menu.cfm`, `/base.cfm`, `/CFIDE/componentutils/`, `/CFIDE/administrator/index.cfm`, `/CFIDE/adminapi/administrator.cfc`)* | Exact, case-insensitive seeds. The handler also serves subpaths under `/CFIDE/componentutils/`, `/CFIDE/administrator/`, and `/CFIDE/adminapi/`. |
| `HONEYPOT_COLDFUSION_VERSION` | `2021.0.05` | Version string shown in HTML/XML responses. |

The POST body read cap is shared with the webshell trap
(`HONEYPOT_WEBSHELL_BODY_READ_LIMIT`, default 64 KiB off the wire).
ColdFusion log previews are capped at 512 chars for exploit triage.

## Fake Atlassian Confluence (CVE-2022-26134 OGNL RCE bait)

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_CONFLUENCE_ENABLED` | on | Master switch. |
| `HONEYPOT_CONFLUENCE_PATHS_CSV` | *(built-in — `/login.action`, `/pages/createpage-entervariables.action`, `/pages/doenterpagevariables.action`, `/templates/editor-preload-container`, `/users/user-dark-features` plus the same set under `/confluence/` and `/wiki/` deployment prefixes)* | Exact, case-insensitive seeds. The handler also matches any path containing `${@...}` or its URL-encoded form `%24%7B%40...` — those are the canonical CVE-2022-26134 OGNL injection payloads, embedded in the request path itself. |
| `HONEYPOT_CONFLUENCE_VERSION` | `7.18.1` | Version banner shown in the login page and `meta` tags. Pinned to a build in the public-disclosure window for CVE-2022-26134 so the scanner ships the exploit body instead of bailing on a patched banner. |

The handler decodes URL-encoded payloads and lifts any OAST-family
callback hostname (`oast.me`, `oast.fun`, `interact.sh`, `dnslog.cn`,
`burpcollaborator.net`, `ceye.io`, `requestbin.net`, `pipedream.net`,
…) into the `confluenceOastCallback` log field. The same callback
hostname recurring across sensors is a strong attribution signal
regardless of source IP rotation.

### Fake SAP NetWeaver Visual Composer MetadataUploader

No Tracebit key required.

| Var | Default | Notes |
| --- | --- | --- |
| `HONEYPOT_SAP_METADATAUPLOADER_ENABLED` | on | Master switch. Covers `/developmentserver/metadatauploader` (CVE-2025-31324 unauth file-upload + CVE-2017-9844 XXE) under the bare, `/irj/`, `/nwa/`, and `/sap/` webroot prefixes. |
| `HONEYPOT_SAP_METADATAUPLOADER_BODY_DECODE_LIMIT` | `8192` | Max bytes of the request body decoded into `bodyPreview` and scanned for the JSP / XXE / cmd-injection indicator flags. The full body is still hashed via `bodySha256`. |

The handler always advertises `Server: SAP NetWeaver Application Server / ABAP (7.50)`
on responses — pinned to a build in the CVE-2025-31324 public-disclosure
window so scanners deciding whether to ship the upload body don't bail
on a patched banner.

## Bind address / port

Flux listens on `127.0.0.1:18081` (aiohttp). To change, edit
`flux/server.py`:`main()` — there's no env var because this is always a
local backend behind a reverse proxy in our use.

## Concurrency model

Single-process aiohttp event loop. Slow-drip traps (tarpit + fake-git)
share a connection cap of `TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS` (default
256) — the 257th concurrent drip gets a 503. Because the event loop is
cooperative, each drip costs ~8 KB of coroutine state, not an OS thread,
so raising the cap another 10× is usually cheap if a real burst trips it.

Non-drip traps (webshell, canary file traps, /.env canary, /.git/* cache
hit) return immediately; they're not subject to the cap.

The Tracebit API client is one shared `aiohttp.ClientSession` per
process, created lazily on first use and closed on shutdown. TCP + TLS
connections to `community.tracebit.com` get pooled across cache-miss
bursts.
