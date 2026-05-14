# `.htpasswd` canary trap

Flux serves a plausible Apache `.htpasswd` file (`username:bcrypt-hash`
lines) with a Tracebit `gitlab-username-password` canary embedded as
the *username* of the first row. The hashes are per-hit synthetic
bcrypt-shaped strings, not real bcrypts — scanners can't crack them
back to a plaintext, but they will typically harvest the usernames
and try them against gitlab / generic basic-auth endpoints, which
fires the canary on the issuer side.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/.htpasswd` | `GET`, `HEAD`, `POST` | 3 lines of `username:$2y$10$...` |

## Logged fields

Standard request metadata plus:

- `result` = `htpasswd`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

The bcrypt-shaped hashes (`$2y$10$` + 22-char salt + 31-char digest) are
generated from `secrets.choice` over the bcrypt output alphabet on every
request. A fixed `$2y$10$...` literal shipped across the fleet would
itself become a cross-sensor fingerprint (the same regression that hit
wp-config / phpinfo / `.env.production` in April 2026), so two
consecutive fetches of `/.htpasswd` from the same sensor return
*different* hashes.

The canary value is the *first row's username* (`deploybot42` in the
fixture; whatever Tracebit returns in production). The other two rows
use generic `admin` / `backup` labels so the file shape isn't a
single-user outlier that scanner heuristics would flag.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
There is no per-trap env var; toggle with `CANARY_TRAPS_ENABLED` if you
want to disable the whole canary file family.

## Why this trap exists

Scanner dictionaries enumerate `.htpasswd` alongside `.env`,
`.git/config`, `.aws/credentials`, and other web-root credentials
files. Recent traffic from config-file harvesters and Googlebot-spoofing
recon scanners includes `.htpasswd` in a path-dict of 100+ probes per
hit. Returning a believable bcrypt file keeps those scanners engaged
past the existence-check stage so any follow-on basic-auth retry, login
POST, or credential replay lands in the access log, and the harvested
username trips the Tracebit canary the moment it is replayed against
the issuer's tracking surface.
