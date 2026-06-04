# `/@vite/env` canary trap

Flux serves a Vite dev-server-shaped JavaScript module on `/@vite/env`
whose `context.define` flat-key block exposes `VITE_*` environment
variables, with a Tracebit AWS canary embedded in the credential-shaped
slots.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/@vite/env` | `GET`, `HEAD`, `POST` | ES-module body with `context.define = {...}` flat-keys; AWS canary in `VITE_AWS_*` and `VITE_API_KEY` slots |

Content-Type: `application/javascript; charset=utf-8`.

## Logged fields

Standard request metadata plus:

- `result` = `vite-env`
- canary issuance metadata recorded against the source IP via the
  shared `_get_or_issue_canary` per-IP TTL cache

## Per-hit uniqueness

The AWS canary triple (`awsAccessKeyId` / `awsSecretAccessKey` /
`awsSessionToken`) is Tracebit-issued per request. The non-canary
filler is also randomised per render: the Sentry DSN public key, org
id, and project id; the `VITE_S3_BUCKET` suffix; and the `VITE_APP_ID`
hex. Two adjacent renders therefore produce different bodies, so a
scanner that cross-references responses across our sensors can't
fingerprint the fleet on this surface.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
No per-trap env var — toggle the whole canary file family with
`CANARY_TRAPS_ENABLED` if needed.

## Why this trap exists

Vite's dev server serves the `vite/dist/client/env.mjs` module at
`/@vite/env`. The module's `context.define` block is a flat dict of
`import.meta.env.VITE_*` -> value entries built from the project's
`.env` file at dev-server startup, so it carries every `VITE_*`
variable the project defines. When a Vite dev server is left reachable
from the public internet — `server.host: '0.0.0.0'` in
`vite.config.ts`, or a reverse proxy that forwards `/@vite/*` to the
dev port — anyone can `curl /@vite/env` and walk the project's
frontend environment.

`VITE_*` is intended for build-time-public values (an API base URL,
an analytics ID, a Sentry DSN), but in practice frontend developers
routinely smuggle cloud credentials, API keys, and signing secrets
through the `VITE_*` prefix because that's how they reach the
browser bundle. Scanners that fetch this path grep raw bytes for
`VITE_`, `AWS_`, `AKIA`, and `SECRET_` patterns and replay anything
credential-shaped — which is exactly the harvesting behaviour the
trap is built to intercept.

The companion `/@fs/<absolute-path>` arbitrary-file-read endpoints
(`bash-history` / `zsh-history` `CanaryTrap` entries cover
`/@fs/root/.bash_history` and siblings) extend the chain: scanners
that probe `/@vite/env` for env-leakage commonly pivot to `/@fs/...`
for filesystem reads. A scanner that walks both paths in one session
harvests an AWS canary from the env response and a second canary
from the bash-history response, doubling the replay surface and
making attribution to the original probe IP unambiguous.
