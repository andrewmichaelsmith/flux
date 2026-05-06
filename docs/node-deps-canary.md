# Node.js dependency-manifest canary set

Flux serves a coherent set of plausible Node.js dependency manifests
— `package.json`, `package-lock.json`, `yarn.lock`, `.yarnrc`,
`.yarnrc.yml` — every URL of which embeds the same
`gitlab-username-password` Tracebit canary in its userinfo / auth-token
component. A scanner harvesting Node.js codebases pulls the whole set
together; collapsing the same canary across all five files means any
one of them is enough to replay the token, and pulling more just gives
the operator more replay opportunities.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/yarn.lock`, `/yarn.lock.bak`, `/yarn.lock.old` | `GET`, `HEAD`, `POST` | yarn v1 lockfile; resolved tarball URLs carry the canary userinfo |
| `/package-lock.json`, `/package-lock.json.bak`, `/package-lock.json.old`, `/var/backups/npm/package-lock.json.old` | `GET`, `HEAD`, `POST` | npm package-lock v3 JSON; same userinfo on every `resolved` URL |
| `/package.json` | `GET`, `HEAD`, `POST` | manifest with internal deps pinned to `git+https://<canary>@npm.internal-tools.lan/...` |
| `/.yarnrc` | `GET`, `HEAD`, `POST` | yarn classic registry + `_authToken` |
| `/.yarnrc.yml` | `GET`, `HEAD`, `POST` | yarn berry `npmRegistryServer` + `npmAuthToken` |

## Logged fields

Standard request metadata plus:

- `result` = `yarn-lock` / `package-lock-json` / `package-json` /
  `yarnrc` / `yarnrc-yml`
- canary issuance metadata (canary id, expiration) recorded against
  the source IP

## Per-hit uniqueness

Two things vary per request to keep the body from turning into a
cross-sensor fingerprint:

- The canary userinfo password is the per-hit Tracebit
  `gitlab-username-password` value. If issuance fails, it falls back
  to `secrets.token_urlsafe(16)` — never a fixed literal.
- Each lockfile entry's `integrity` field is a fresh
  `sha512-<base64>` hash of 32 random bytes, so two adjacent renders
  on different sensors don't share the same lockfile body.

The package names and versions in `dependencies` are fixed
non-credential filler — same plausibility rule as `wp_prod` username
or `db.internal` host name.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
There is no per-trap env var; toggle with `CANARY_TRAPS_ENABLED` if
you want to disable the whole canary file family.

## Why this trap exists

Scanners harvesting deploy credentials probe Node.js codebases for
the full dependency-manifest path family in one sweep — `yarn.lock`
+ `package-lock.json` + `package.json` + `.yarnrc(.yml)` from the
same source IP, often with URL-encoding / extension / null-byte
variants (`/yarn.lock~`, `/yarn.lock.txt`, `/yarn.lock%00`,
`/yarn.lock?v=1`) thrown in for filter-bypass. Without the trap each
of these returns 404 and the harvest yields nothing; with it, every
URL the scanner extracts for token replay carries a live canary.

The high-signal piece is the `resolved` URL on each internal-package
entry: `https://<user>:<canary>@npm.internal-tools.lan/...`.
Scanners that strip URL userinfo for credential replay fire the
`gitlab-username-password` canary on the next attempt against the
gitlab host the canary is bound to.
