# Fake Laravel Telescope debug-panel trap

Simulates the [Laravel Telescope](https://laravel.com/docs/telescope)
debug-assistant package at `/telescope/...`. Telescope captures every
HTTP request, executed DB query, dispatched mail, raised exception, and
log emission for a Laravel app — when `APP_DEBUG=true` and the
`Telescope::auth(...)` gate is left at its default empty closure, the
entire panel is reachable unauthenticated. The HTML SPA + JSON API
combination ships shape-correct responses so scanners walking the panel
keep moving from fingerprint into the credential-disclosure slots a
real deployment would have leaked.

| Path | Methods | Response |
| --- | --- | --- |
| `/telescope`, `/telescope/`, `/telescope/<panel>` | `GET`, `HEAD` | `200` HTML Vue-SPA shell (every panel returns the same HTML; the SPA's router does in-page routing) |
| `/telescope/telescope-api/requests` | `GET`, `HEAD` | `200` JSON; captured admin POST with the Tracebit AWS canary in the `payload.AWS_ACCESS_KEY_ID` / `payload.AWS_SECRET_ACCESS_KEY` slot a real `RequestWatcher` would have stored, plus a per-hit synthetic `Authorization: Bearer ...` header |
| `/telescope/telescope-api/queries` | `GET`, `HEAD` | `200` JSON; executed `insert into settings ...` with the Tracebit AWS canary in `content.bindings` (the slot the SPA renders verbatim) |
| `/telescope/telescope-api/exceptions` | `GET`, `HEAD` | `200` JSON; thrown `Illuminate\Database\QueryException` with the Tracebit AWS canary in `content.context.env.AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (the `$_ENV` dump Telescope captures on throw) |
| `/telescope/telescope-api/mail` | `GET`, `HEAD` | `200` JSON; captured `PasswordResetMail` dispatch with the Tracebit AWS canary in `content.transport.key` / `content.transport.secret` (the SES driver config a `MailWatcher` row carries) |
| `/telescope/telescope-api/logs` | `GET`, `HEAD` | `200` JSON; `error`-level log entry with the Tracebit AWS canary in `content.context.AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (the shape of `Log::error('...', ['AWS_ACCESS_KEY_ID' => ...])`) |
| `/telescope/telescope-api/{cache,redis,gates,dumps,schedule,jobs,batches,views,models,events,commands,notifications,monitored-tags,clients}` | `GET`, `HEAD` | `200` JSON `{"entries":[]}` — the empty state a fresh install renders for these panels (fingerprint slots, no credentials) |
| `/telescope/api/<panel>` | `GET`, `HEAD` | Same dispatch as `/telescope/telescope-api/<panel>` (reverse-proxy rewrite placement scanners walk) |
| `/{admin,dashboard,panel,backend,app,laravel,monitor,dev,internal}/telescope/...` | any | Same dispatch as the bare `/telescope/...` form (sub-directory placements that mirror Laravel-under-an-admin-prefix proxy rewrites) |
| `/telescope/telescope-api/<unknown>` | any | `404` JSON `{"message":"Not Found."}` (Telescope's router 404 envelope) |

The handler logs:

- `result` tags (`telescope-shell`, `telescope-api-requests`,
  `telescope-api-queries`, `telescope-api-exceptions`,
  `telescope-api-mail`, `telescope-api-logs`,
  `telescope-api-<empty-panel>`, `telescope-api-miss`)
- `telescopePath` (exact request path)
- `telescopeMethod` (HTTP verb)
- `telescopePanel` (set when the request resolved to a known panel —
  both on the SPA HTML branch and the JSON API branch)
- `canaryTypes` and `bytes`

Every credential-shaped field is per-hit unique:

- AWS slots (`payload.AWS_*` on requests; SQL `bindings[]` on queries;
  `context.env.AWS_*` on exceptions; `transport.key` / `transport.secret`
  on mail; `context.AWS_*` on logs) ship the per-request Tracebit AWS
  canary.
- Bearer tokens, CSRF tokens, `laravel_session` cookies, `APP_KEY`,
  `DB_PASSWORD`, `REDIS_PASSWORD`, and the `/api/v1/login` captured
  password slot ship per-hit `secrets.token_urlsafe(...)` /
  `secrets.token_hex(...)` synthetics — no fixed literals.

The trap defaults on (`HONEYPOT_TELESCOPE_ENABLED`). Keyless
deployments still serve every endpoint; the AWS canary slots simply
go empty.

## Why

Telescope is one of the highest-signal Laravel debug surfaces because
every Telescope panel persists captured application state that maps
directly onto a credential-extractor's grep targets:

1. **SPA enumeration.** Scanner dictionaries walk
   `/telescope/requests`, `/telescope/queries`, `/telescope/exceptions`,
   `/telescope/logs` — the same way they walk `/wp-json/`
   namespace endpoints — looking for a `200` with Telescope-shaped
   HTML. The shell returns the Vue-app marker (`id="telescope"`) so
   that fingerprint check passes; the credential harvest happens on
   the next call.
2. **JSON-API credential harvest.** The SPA fetches
   `/telescope/telescope-api/<panel>` (and `/telescope/api/<panel>`
   on some reverse-proxy placements) for the entries list. Bytes-grep
   harvesters scrape that JSON for `AKIA…` literals, `DB_PASSWORD=`,
   `Authorization: Bearer …`. The `requests` panel's captured POST
   body, the `queries` panel's SQL bindings, the `exceptions` panel's
   env dump, the `mail` panel's SES transport config, and the `logs`
   panel's context dict are each grep-equivalent to the credential
   slots scrapers harvest from `.env` / `wp-config.php` /
   Ignition's HTML stack trace.
3. **Reverse-proxy rewrite placements.** Many Laravel apps mount the
   admin surface under `/admin/`, `/dashboard/`, `/panel/`, etc. and
   the same Telescope routes show up under those prefixes. Scanner
   dictionaries enumerate both shapes; the trap accepts every
   common prefix so the credential harvest fires regardless of where
   the install is mounted.

Returning shape-correct Telescope JSON on each credential-disclosure
panel keeps each probe alive past fingerprint and harvests an
AWS-replayable canary from five distinct entry types. Other panels
return an empty `entries[]` — more realistic than synthesised data on
every cell, and avoids burning a Tracebit canary on fingerprint-only
walks.
