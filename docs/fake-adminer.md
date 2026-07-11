# Fake Adminer login trap

Serves the canonical Adminer 4.x login page across the classic
install-path aliases scanner dictionaries fan out on, then captures any
credential POST that follows. Real Adminer installs are a single-file
PHP DB admin tool (`adminer.php`) — if a real deployment left one on the
webroot, discovered credentials give instant DB takeover. Real Adminer
returns 200 on both the bare GET and on a failed login POST, so the
trap matches the on-the-wire shape banner-grab plus brute clients
expect.

| Path | Methods | Response |
| --- | --- | --- |
| `/adminer.php`, `/adminer/adminer.php`, `/adminer/index.php`, `/adminer/`, `/adminer`, `/admin/adminer.php`, `/admin/adminer/adminer.php`, `/db/adminer.php`, `/database/adminer.php`, `/mysql/adminer.php`, `/tools/adminer.php`, `/tools/adminer/adminer.php`, `/backup/adminer.php`, `/_adminer/adminer.php`, `/wp-content/plugins/adminer/adminer.php` | `GET`, `HEAD` | Adminer 4.x login HTML with per-request hidden `token` + per-request `adminer_sid_<slot>=<session>` cookie |
| Per-version aliases `/adminer-4.8.1.php`, `/adminer-4.8.0.php`, `/adminer-4.7.9.php`, `/adminer-4.7.8.php`, `/adminer-4.7.7.php` | `GET`, `HEAD` | Same login HTML — dictionaries commonly probe the exact release version |
| Any of the above | `POST` | Captures `auth[username]`, `auth[password]` length (never the password itself), `auth[server]`, `auth[db]`, `auth[driver]`, `auth[permanent]`, submitted `token`; re-serves the login HTML with the standard `Invalid credentials.` error notice, the submitted user / server / db echoed back into the form, and the Tracebit AWS canary embedded in a `<datalist>` server-history preset |

All matched paths return `200` with `Server: Apache/2.4.41 (Ubuntu)`,
`X-Powered-By: PHP/8.1.27 Adminer/<version>`, and the standard Adminer
no-cache headers. Disabled deployments and unmatched paths return
`404`. Path matching is case-insensitive — scanner dictionaries send
both `/adminer.php` and `/Adminer.php` and route to the same handler.
Query strings are stripped before matching so `/adminer.php?server=…`
still dispatches.

The handler logs:

- `result` tags (`adminer-login`, `adminer-credential-post`)
- `adminerPath` (exact request path)
- `adminerMethod` (HTTP verb, GET/HEAD only — POST captures land under
  the credential-post branch)
- `adminerUsername`, `adminerServer`, `adminerDb`, `adminerDriver`,
  `adminerPermanent` for any POST to a matched path
- `adminerHasPwd` and `adminerPwdLen` — password value is never
  stored, only presence and length, so common-dictionary vs
  random-blob brute strategies are separable
- `adminerTokenSubmitted` — the hidden `token` returned with the
  POST; truncated to 48 chars
- `adminerSessionCookiePresent` — whether the request carried a prior
  `adminer_sid_<slot>` cookie, so cookie-replay scanners separate
  from fresh probes
- `canaryTypes` on the POST branch (`["aws"]` when Tracebit issued,
  empty when `TRACEBIT_API_KEY` is unset)
- `bodyPreview` (first 4096 bytes of the credential POST, decoded
  best-effort) and `bytes` (response payload length)

## Why

`/adminer.php` and its siblings show up as a coherent scripted-kit
dictionary in the trap 404 tail, sitting alongside `/.DS_Store` and
`/whm` from `python-requests/2.32.5` clients — a small DB-admin-hunter
population that returns to the same target every few days. Every hit
was previously 404'd, so credential-brute fleets walking Adminer
dictionaries bailed before POSTing any credential bytes and we lost
the username + password material plus the chance to plant a per-hit
session-cookie canary.

Adminer is architecturally more dangerous than phpMyAdmin (a real
exposed `adminer.php` is a single-file webroot upload with no
`config.inc.php` gating access) — a working credential gives instant
DB takeover. That combination — high-value target, distinctive
scripted-kit signature, recurring return visits — motivates the
dedicated trap rather than folding into the phpMyAdmin handler.

## Canary placement

The AWS canary is only embedded on the POST error re-serve, not on
the bare GET. That way a banner-grab scanner probing `GET /adminer.php`
walks away with nothing to harvest; only clients that actually POST
credentials trigger the mint. The canary lands inside a `<datalist>`
server-history preset entry named `s3-backup.internal.example.com:3306`
with `data-aws-key=…` / `data-aws-secret=…` attributes — the same
shape a leaky shared-host Adminer install would carry if a previous
admin had connected to an RDS backup restore. Grep-by-field scanners
that scrape post-login pages for `AKIA…` harvest a replay-fireable
canary; a live-eyeball scanner sees a plausible page.

The canary is minted through `_get_or_issue_canary(('aws',), ...)`,
so a brute burst reuses one canary per source-IP within the TTL rather
than N. Keyless deployments (`TRACEBIT_API_KEY` unset) still capture
credentials — the canary slot just goes empty.

## Config

- `HONEYPOT_ADMINER_ENABLED` — master switch, defaults on.
- `HONEYPOT_ADMINER_VERSION` — displayed on the login page and in
  the `X-Powered-By` header, defaults to `4.8.1` (the last major
  release before Adminer 5.x).
- `HONEYPOT_ADMINER_PATHS_CSV` — comma-separated exact-match path
  set. Defaults to the built-in list above; override for
  site-specific dictionaries.
- `HONEYPOT_ADMINER_BODY_DECODE_LIMIT` — bytes of a POST body
  decoded into `bodyPreview`, defaults to 4096.
