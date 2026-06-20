# `vercel.json` canary trap

Flux serves a populated `vercel.json` project-config JSON on `/vercel.json`
and the runtime working-directory variants where misconfigured static-file
routes commonly expose it. The `env`, `build.env`, and per-route `headers[]`
slots each carry a per-request Tracebit AWS canary in the slot a real
misconfigured deploy would leak it from.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/vercel.json` | `GET`, `HEAD`, `POST` | Vercel project-config JSON with AWS canary in `env`, `build.env`, and `headers[].headers[]` |
| `/app/vercel.json` | same | same renderer |
| `/var/task/vercel.json` | same | same renderer (AWS Lambda runtime working dir) |
| `/usr/src/app/vercel.json` | same | same renderer (Node Docker base image working dir) |
| `/srv/app/vercel.json` | same | same renderer |
| `/home/node/app/vercel.json` | same | same renderer |
| `/opt/app/vercel.json` | same | same renderer |
| `/workspace/vercel.json` | same | same renderer |

Content-Type: `application/json; charset=utf-8`.

## Logged fields

Standard request metadata plus:

- `result` = `vercel-json`
- canary issuance metadata recorded against the source IP via the
  shared `_get_or_issue_canary` per-IP TTL cache

## Per-hit uniqueness

The AWS canary triple (`awsAccessKeyId` / `awsSecretAccessKey` /
`awsSessionToken`) is Tracebit-issued per request and embedded in the
top-level `env` block, the `build.env` block, and the
`headers[].headers[]` block under `x-aws-access-key-id` /
`x-aws-secret-access-key` slots — three places different scanner
dictionaries grep raw bytes. Non-AWS credential-shaped slots
(`NEXTAUTH_SECRET`, `DATABASE_URL` password, `REDIS_URL` password,
`SENTRY_AUTH_TOKEN`, `VERCEL_PROJECT_ID`) are per-hit
`secrets.token_urlsafe` / `secrets.token_hex` synthetics — no fixed
literals — so two adjacent renders produce different bodies and a
scanner that cross-references responses across our sensors can't
fingerprint the fleet on this surface.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
No per-trap env var — toggle the whole canary file family with
`CANARY_TRAPS_ENABLED` if needed.

## Why this trap exists

`vercel.json` is the project-config file Vercel deployments commit at
the repo root. The documented top-level `env` block, the `build.env`
block, and the per-route `headers[]` blocks each surface build-time
or request-time configuration — in real projects this is where AWS
credentials, Sentry auth tokens, database URLs, and other secrets
leak when a frontend developer commits a populated config instead of
relying on the Vercel dashboard env-var UI. The misuse is common
enough that off-the-shelf scanner dictionaries walk the file
alongside `.env` and `wp-config.php`.

The webroot-prefix variants (`/app/`, `/var/task/`, `/usr/src/app/`,
`/srv/app/`, `/home/node/app/`, `/opt/app/`, `/workspace/`) cover
the runtime working-directories AWS Lambda containers, the Node
Docker base image, Cloud Run, and common CI runners use. A
misconfigured static-file route that pins `root` at the runtime
working dir exposes the file at the prefixed path, and scanner
dictionaries walk the prefix matrix to catch those deployments.

URL-encoded variants (`/vercel%2ejson`) are handled by
`normalize_path`'s `unquote` step before the canary lookup runs, so
no separate paths are needed for them.
