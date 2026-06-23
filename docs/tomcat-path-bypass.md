# Tomcat `/..;/env.*` path-normalization bypass + env-file harvest

Catches the specific combination of a Tomcat path-parameter bypass
(`/..;/`) with a frontend-bundle env-file filename
(`env.js`, `env.dev.js`, `env.prod.js`, `env.production.js`,
`env.development.js`). Both halves are interesting on their own; the
combination is the evasion-aware-scanner indicator the trap is
designed to surface.

## Routed paths

| Path shape | Methods | Response |
| --- | --- | --- |
| `/..;/env.js`, `/..;/env.dev.js`, `/..;/env.prod.js`, `/..;/env.production.js`, `/..;/env.development.js` | any | Plausible JS env-config bundle (`window.__APP_ENV__ = {...}`) carrying the per-hit Tracebit AWS canary in the `REACT_APP_AWS_*`, `VITE_AWS_*`, and `NEXT_PUBLIC_AWS_*` slots scrapers grep on, plus per-hit synthetic Sentry / Firebase / Stripe-shaped values |
| `/static/..;/env.js`, `/api/..;/..;/env.prod.js`, … | any | Same response — any path containing the `/..;/` segment AND an `env*.js` filename routes here |

The matcher explicitly excludes `/tmui/` paths so the F5 BIG-IP TMUI
`/..;/` bypass (CVE-2020-5902) family continues to route to the
dedicated F5 handler.

## Result tag

- `tomcat-path-bypass-env` — the env.js body served. Triage on the
  separate `tomcatHasPathNormBypass=true` flag, which fires for every
  hit in this family.

## Logged fields

Standard request metadata plus:

- `tomcatBypassPath`, `tomcatBypassMethod`, `tomcatBypassFilename`
- `tomcatHasPathNormBypass` — always `true` for this handler, so the
  evasion-aware scanner shape is separable from regular env-file
  canary hits at one log field.
- `queryPreview` (first 400 chars)

## Per-hit uniqueness

The body is regenerated per request — no caching:

- AWS access key id / secret / session token come from Tracebit's
  per-issuance canary (`_aws()`). Keyless deployments leave these
  empty but still serve the body shape.
- The Sentry DSN public key, Sentry org/project ids, Firebase app id,
  and Stripe publishable key are per-hit
  `secrets.token_hex` / `randbelow` values. Two consecutive renders
  produce different bundles even when the canary is the same.

## Why

The `/..;/` sequence is a Tomcat path-parameter — anything after the
semicolon is a JSESSIONID-style attribute that Tomcat strips when
resolving the servlet path. Some upstream proxies (or WAFs configured
in path-prefix-only mode) normalize the request before forwarding,
defeating prefix-based auth gates: a `/admin/..;/secret` request can
reach a `/secret` servlet that the proxy was meant to block. The
behavior surfaced publicly around CVE-2020-1938 ("Ghostcat") but
modern scanner populations still walk the family looking for any
fronted Java application that gates on a URL prefix.

The env.js filename family is the credential-leak half — frontend
React / Vue / Vite dev builds emit a runtime-config JS object so the
client can read env vars without a rebuild. When devs commit a
populated env file or misconfigure the static-file route, the bundle
ships cloud creds (`REACT_APP_AWS_*`, `VITE_*`, `NEXT_PUBLIC_*`) in
plaintext. The combination — Tomcat bypass shape AND env-file
filename — is the signature of a scanner population that already
knows about both surfaces and is composing them. Logging the family
separately surfaces evasion-aware actors above the noise of regular
env-file harvesters.
