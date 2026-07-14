# Fake ASP.NET `Trace.axd` disclosure trap

Simulates the `Trace.axd` per-request detail view that ASP.NET serves
when `<trace enabled="true" localOnly="false"/>` is left on in a
production `Web.config`. Real trace pages dump the recent request
history including Request Headers, Server Variables, Session State,
and Form Collection — a recurring credential-disclosure finding that
scanners fingerprint specifically to grep for `Authorization:` values
and env-var-shape server variables.

| Path | Methods | Response |
| --- | --- | --- |
| `/trace.axd` | `GET`, `HEAD`, `POST` | Application Trace detail-view HTML (see below). `?id=<n>` and `?clear=1` query strings are accepted and produce the same body. |
| `/trace.axd/` | `GET`, `HEAD`, `POST` | Same detail-view HTML (trailing-slash variant). |

Path matching is case-insensitive — scanner dictionaries walk
`/Trace.axd`, `/trace.axd`, `/trace.axd?id=1`, and the trailing-slash
variant, all of which route to the same handler.

All matched paths return `200` with `Content-Type: text/html; charset=utf-8`,
`Cache-Control: no-store`, `Server: Microsoft-IIS/10.0`,
`X-AspNet-Version: 4.0.30319`, and `X-Powered-By: ASP.NET`. Disabled
deployments (no `TRACEBIT_API_KEY`) return `404` for the same paths.

## Canary placement

The Tracebit AWS canary lands in three natural slots within a single
response body — a scraper grepping for `AKIA`-prefixed bytes,
`AWS4-HMAC-SHA256 Credential=`, or `AWS_ACCESS_KEY_ID=` from server env
all catch the same per-hit canary:

- **Server Variables** — the classic env-leak shape:
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_DEFAULT_REGION`.
- **Headers Collection** — `Authorization: AWS4-HMAC-SHA256 Credential=<AKIA…>/…`,
  the shape a real S3 SDK client would send. `X-Amz-Security-Token`
  carries the session token.
- **Session State** — an `AwsProfile` entry containing an INI fragment
  (`aws_access_key_id` / `aws_secret_access_key`).

## Per-hit uniqueness

Nothing credential-shaped is a fixed literal across sensors — replay
detection depends on every hit shipping a distinct fingerprint:

- Session id (`Session Id:` header), `ASP.NET_SessionId` cookie, and
  `.ASPXAUTH` cookie are per-request `uuid4()`-derived values.
- `__VIEWSTATE` and the AWS4 request `Signature` use per-request
  `secrets.token_hex(...)` random material.
- `DbConnectionString` embeds a per-hit `_fake_db_password()` — no
  fixed DB literal is ever shipped.
- AWS keys / secret / session token are per-hit Tracebit canaries.

## Logging

The handler logs the shared `CanaryTrap` fields via the standard
canary dispatch path:

- `result: trace-axd`
- `canaryTypes: ["aws"]`
- `bytes` (response payload length)

Scanners that fingerprint the platform before scraping the body get
`Server: Microsoft-IIS/10.0` + `X-AspNet-Version: 4.0.30319` from the
extra-headers hook, so a shape check on the response headers still
passes and the follow-up body grab hits the canary.
