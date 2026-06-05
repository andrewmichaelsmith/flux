# Spring Boot Actuator surface canary traps

Flux serves plausible Spring Boot Actuator responses on seven endpoints
beyond `/actuator/env`: `heapdump`, `configprops`, `health`, `mappings`,
`threaddump`, `logfile`, and `trace` (plus the 2.x `httptrace` rename).
Each embeds a Tracebit AWS canary in a place a credential harvester
would grep raw bytes for.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/actuator/heapdump`     | `GET`, `HEAD`, `POST` | HPROF-shaped binary, canary AWS creds inline as Java string constants |
| `/actuator/configprops`  | `GET`, `HEAD`, `POST` | `@ConfigurationProperties` JSON; canary AWS creds in `cloud.aws.credentials.accessKey` / `secretKey`, per-hit DB password in `spring.datasource.password` |
| `/actuator/health`       | `GET`, `HEAD`, `POST` | `show-details=always` JSON; per-hit DB password embedded in `components.db.details.url` (user-info-bearing JDBC URL form) |
| `/actuator/mappings`     | `GET`, `HEAD`, `POST` | `dispatcherServlets` JSON; canary access-key id embedded in a `/api/v1/webhook/<key>/event` request mapping pattern |
| `/actuator/threaddump`   | `GET`, `HEAD`, `POST` | thread state JSON; canary access-key id embedded in worker thread names (`s3-transfer-manager-worker-<key>-prod`) |
| `/actuator/logfile`      | `GET`, `HEAD`, `POST` | Spring Boot startup log; canary AWS creds inline as `AmazonAwsCredentialsProviderChain` lines + JDBC URL with per-hit DB password in HikariCP startup line |
| `/actuator/trace` (+ 2.x `/actuator/httptrace`) | `GET`, `HEAD`, `POST` | recent HTTP exchanges JSON; canary access-key id inside an AWS SigV4 `Authorization` header on one trace + as a query parameter on an outbound webhook URL |

Each path is also routed at the `/manage`, `/management`,
`/api/actuator`, `/app/actuator`, and `/backend/actuator`
reverse-proxy aliases that already serve `/actuator/env` — for example
`/manage/heapdump`, `/api/actuator/configprops`, `/app/actuator/logfile`,
or `/backend/actuator/trace`. The `/app/` and `/backend/` prefixes are
common reverse-proxy mount points for backend services behind an API
gateway; recurring scanner dictionaries walk those prefixes alongside
`/manage` and `/management`.

## Logged fields

Standard request metadata plus:

- `result` = `actuator-heapdump` / `actuator-configprops` /
  `actuator-health` / `actuator-mappings` / `actuator-threaddump` /
  `actuator-logfile` / `actuator-trace`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

Every credential-shaped value is randomized per request:

- AWS access key id, secret access key, and session token come from
  Tracebit's per-issuance canary (`_aws()`).
- The Postgres / Redis passwords embedded in `health` and `configprops`
  are per-hit `_fake_db_password()` values — never a fixed literal.
- The thread-name suffix in `threaddump` carries either the per-hit
  Tracebit access-key id or a per-hit slice of the secret-key, so two
  back-to-back hits never produce the same response body.

The HPROF blob in `heapdump` includes a per-hit DB password in the
embedded `DATABASE_URL` line, so the binary content also varies per
request even when the AWS canary cache happens to return the same
key id within its TTL.

## Tuning

The traps are `CanaryTrap` entries, gated on the global
`CANARY_TRAPS_ENABLED` master switch (default: on) and on the presence
of `TRACEBIT_API_KEY`. There is no per-trap env var; toggle with
`CANARY_TRAPS_ENABLED` if you want to disable the whole canary file
family.

## Why this trap exists

The `/actuator/env` endpoint has been a credential-harvesting target
for years — Spring Boot 1.x exposed it unmasked by default, and 2.x
re-exposes it whenever a deployment sets
`management.endpoint.env.show-values=ALWAYS` or
`management.endpoints.web.exposure.include=*`. The same scanner
populations that hit `/actuator/env` walk the rest of the actuator
surface looking for the same credentials in different shapes. Public
Spring Boot scan dictionaries (and the high-volume cloud-IP fleets
running them) routinely probe at least these five endpoints; without a
trap each one returns 404, gives the scanner a free signal that the
host isn't a Spring Boot target, and the scanner moves on.

Each endpoint leaks credentials in a different idiomatic place on a
real misconfigured app:

- `heapdump` — JVM `String` interns of `getenv()`-loaded credentials
  land in the heap profile and get harvested by raw-bytes greppers.
- `configprops` — `@ConfigurationProperties` beans expose
  `spring.datasource.password` and `cloud.aws.credentials.*` unmasked
  on `show-values=ALWAYS`.
- `health` — `show-details=always` exposes the JDBC URL with embedded
  user info, which is a recurring sloppy-config pattern.
- `mappings` — webhook handler URLs sometimes carry the API key as a
  path segment, which the response surfaces verbatim.
- `threaddump` — SDK-allocated worker thread names sometimes embed the
  authentication context (e.g. `s3-transfer-manager-worker-<key>-prod`).
- `logfile` — Spring's `${ENV_VAR}` placeholder resolution surfaces
  unmasked credential env vars in startup `INFO`/`DEBUG` lines; the
  HikariCP `Added connection ...` log line includes the resolved JDBC
  URL with embedded password.
- `trace` — Spring Boot 1.x `/trace` and 2.x `/httptrace` return
  recent HTTP exchanges verbatim; inbound AWS SigV4 `Authorization`
  headers carry the access-key id in their `Credential=` segment,
  and outbound webhook URLs sometimes pass the API key as a query
  parameter that the trace logs in full.

Returning a plausible body in each shape keeps the scanner's
filter-on-shape branch alive long enough to harvest the canary; the
canary fires on replay.
