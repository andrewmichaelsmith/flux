# Fake Apache `mod_status` canary trap

Flux serves a plausible Apache `mod_status` page on `/server-status`
that embeds a per-request Tracebit AWS canary in the scoreboard's
recent-request URLs. Credential-scrapers that grep `mod_status`
output for `AKIA…` patterns walk away with a key that fires on AWS
replay.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/server-status`         | any | HTML mod_status page with canary URLs in the scoreboard `Request` column |
| `/server-status/`        | any | same as `/server-status` |
| `/server-status?auto`    | any | machine-parseable text format (Munin / Nagios shape), canary URLs in `LastReq*` lines |
| `/server-status?refresh=N` | any | HTML page with `<meta http-equiv="refresh">` (clamped to 1-3600s) |

## Response shape

The HTML format mirrors Apache 2.4's `mod_status` layout:

- Server-version banner (`Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13`),
  pinned inside the public-disclosure window for the 2024 mod_proxy
  / mod_rewrite CVEs so version-gated scanners don't bail.
- Server MPM (`event`), uptime, total accesses, request-rate, CPU
  load, busy/idle worker counts.
- A textual scoreboard (`WWWWWWW_______`) and a per-worker `Srv /
  PID / Acc / M / CPU / SS / Req / Dur / Conn / Child / Slot /
  Client / VHost / Request` table whose `Request` column carries
  the recent-request URLs the canary lives in.

The `?auto` format emits the canonical `Key: Value` lines monitoring
tools parse (`Total Accesses:`, `BusyWorkers:`, `IdleWorkers:`,
`Scoreboard:`, …) plus synthetic `LastReq<N>:` lines that hold the
canary URLs.

## Per-hit uniqueness

The page is rendered fresh per request with a new Tracebit AWS canary
issuance. Two URLs in the scoreboard embed the canary in query-string
slots (`aws_access_key_id` / `aws_secret_access_key`); the other
five are plausible app endpoints (`/api/v1/users/me`, `/healthz`,
`/metrics`, …) so the canary URLs don't stick out. No fixed
credential literals.

## Why

`mod_status` exposure is a long-standing info-leak class — it's the
top recommendation in the Apache hardening guides and every web-server
scan profile probes for it. Scanners hit it because the `Request`
column in mod_status canonically leaks full URLs (including query
strings carrying session tokens or API keys) and the version banner
identifies the vulnerability surface for the next exploit pass.

The trap turns that recurring scanner interest into a credential
issuance: the canary URLs are exactly the slot credential-scrapers
grep `AKIA…` patterns from, and the Tracebit canary will fire on
AWS replay so we attribute the theft to the original `/server-status`
hit. The `?auto` variant lives in the same code path because some
scripted scanner fleets (Munin-style harvesters retooled for offense)
request `?auto` first and skip the HTML page entirely.
