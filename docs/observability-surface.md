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
| GET / HEAD | `/actuator/info` | `200` + build / git / app metadata JSON | `observability-actuator-info` |
| GET / HEAD | `/actuator/metrics` | `200` + JSON meter-name index (**not** the Prometheus text) | `observability-actuator-metrics` |
| GET / HEAD | `/actuator/metrics/{name}` | `200` + that meter's measurements; unknown names get Spring's own 404-shaped JSON | `observability-actuator-metric` |
| GET / HEAD | `/actuator/beans` | `200` + application-context bean list | `observability-actuator-beans` |
| GET / HEAD | `/actuator/loggers` | `200` + configured / effective log levels | `observability-actuator-loggers` |
| GET / HEAD | `/actuator/auditevents` | `200` + recent authentication events (principal names) | `observability-actuator-auditevents` |
| GET / HEAD | `/actuator/sessions` | `200` + Spring Session entries; session ids are per-hit random | `observability-actuator-sessions` |
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
answers a set of endpoints beneath `/actuator`, but the index that Spring
Boot serves at the base path was a 404 — so a client that *discovers*
rather than guesses reached none of them. Restoring the index reconnects a
broken chain into a trap that was already there, and the index advertises
exactly the endpoints flux really answers: an advertised link that then
404s is the cheapest possible tell that the document is canned, so a test
asserts the two sets match, following each advertised `href` (and the
concrete form of each template) rather than rebuilding it from the link
name.

The endpoints served from this file rather than the canary table are the
ones with no credential slot worth minting a canary for. `info` is the
one that had to be here: Spring Boot exposes `health` and `info` by
default and nothing else, so answering `health` while 404ing `info` was a
shape no real configuration produces — and it was the same shape on every
host running this code, which makes it a fleet fingerprint rather than
just a gap. `beans`, `loggers`, `auditevents`, `sessions` and `metrics`
are all in the wide-open `exposure.include=*` set that the rest of the
advertised index implies, and all of them get probed.

Two of those bodies disclose account names. That is the same chain the
WordPress user-enumeration trap runs: names read off a public surface are
the input to a credential-stuffing run against the login surface, and the
login surface is where the capture happens. Account names authenticate
nothing, so they are fixed filler; the session id on `/actuator/sessions`
is the one credential-shaped field on this surface and is per-hit random.

`/actuator/metrics` is a JSON meter-name index, not the Prometheus text
exposition — that is `/actuator/prometheus`. Conflating them is itself a
tell. The name index is also the surface's one templated lead: a client
that reads it and comes back for a single named meter is following a
lead rather than sweeping, and `obsMeterName` / `obsMeterKnown` record
which.

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
