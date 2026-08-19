# Observability / debug surface

The operational endpoints a framework exposes for monitoring — Prometheus
exposition, Go expvar, health probes, Apache `mod_info`, nginx
`stub_status`, the Spring actuator discovery index, ELMAH, and the
profiler index. flux already answered three neighbours in this family
(`/server-status`, `/debug/pprof/`, `/_profiler`); the rest were a flat
404, which is both a miss and an inconsistency a scanner can see.

| Method | Path | Response | Log tag |
| --- | --- | --- | --- |
| GET / HEAD | `/actuator`, `/actuator/` | `200` + HAL `_links` index | `observability-actuator-index` |
| GET / HEAD | `/metrics`, `/metrics/`, `/prometheus`, `/actuator/prometheus` | `200` + Prometheus text exposition | `observability-metrics` |
| GET / HEAD | `/debug/vars` | `200` + Go expvar JSON | `observability-expvar` |
| GET / HEAD | `/health`, `/healthz`, `/_health`, `/api/health`, `/readyz`, `/livez`, `/health/ready`, `/health/live`, `/api/status` | `200` + Spring-style health JSON | `observability-health` |
| GET / HEAD | `/server-info`, `/server-info/` | `200` + `mod_info` HTML | `observability-server-info` |
| GET / HEAD | `/nginx_status`, `/basic_status`, `/stub_status`, `/nginx-status` | `200` + `stub_status` counters | `observability-nginx-status` |
| GET / HEAD | `/elmah.axd`, `/elmah` | `200` + ASP.NET error-log HTML | `observability-elmah` |
| GET / HEAD | `/debug`, `/_debug`, `/debug/profiler`, `/profiler`, `/__profiler__`, `/_profiler/panel.html` | `200` + profiler index HTML | `observability-profiler-index` |

Matching is **exact-path only, never a prefix**. `/debug` and
`/server-info` are generic enough that a prefix rule would swallow
`/debug/pprof/` and `/server-status`, both of which have closer-fitting
handlers; the dispatch also sits after every exact-path trap so those
claim their own paths first. Every line carries `obsKind` and `obsPath`;
the actuator index adds `obsAdvertised`, and the ELMAH branch logs the
connection string it handed out.

## Why

Each body is written so that reading it **names a further target** — an
internal database host, a config-file path, a link to another endpoint.
That is the whole design. A dictionary sweeper fires the path because it
is in its list, reads a body with no secret in it, and moves on. A client
that parses the disclosure and comes back for what it named is a
different and much narrower population, and the follow-up request is the
measurement.

The actuator index is the clearest case. The canary-trap table already
answers 18 endpoints beneath `/actuator`, but the index that Spring Boot
serves at the base path was a 404 — so a client that *discovers* rather
than guesses reached none of them. Restoring the index reconnects a
broken chain into a trap that was already there, and the index advertises
exactly the endpoints flux really answers: an advertised link that then
404s is the cheapest possible tell that the document is canned, so a test
asserts the two sets match.

No branch issues a canary. The credential-bearing things these bodies
point at — `/actuator/env`, the `.env` named in the expvar `cmdline`, the
config files named by `mod_info` — mint their own. So a broad sweep
across this surface costs nothing upstream, and the spend happens only
when a lead is actually followed, the same split the metadata traps use.

The host and service names (`HONEYPOT_OBSERVABILITY_DB_HOST`,
`…_CACHE_HOST`, `…_APP_NAME`) are fixed non-secret filler. They must be
stable for the chain to be followable, and a hostname authenticates
nothing. The one credential-shaped field in the family — the SQL Server
connection-string password in the ELMAH error detail — is a **per-hit
synthetic**, never a literal: a fixed one would be a single string shared
across every deployment and would provide no detection on replay.

Advertised uptimes and counters advance with process age rather than
being frozen constants, since an identical uptime on every hit is its own
tell.

Master switch: `HONEYPOT_OBSERVABILITY_ENABLED` (default on). The surface
needs no API key — it carries no canary — so keyless deployments serve it
in full. `HONEYPOT_OBSERVABILITY_PATHS_CSV` overrides the path set.
