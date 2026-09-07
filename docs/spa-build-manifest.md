# SPA build manifest

Answers the frontend build manifest that secret-dredging dictionaries walk
alongside `config.js` and `env.js`, and the per-client runtime-config chunk
that the manifest names.

This is the only trap here whose payoff is not in its own body.

## Paths

| Family | Paths | Canary | Result tag |
| --- | --- | --- | --- |
| Vite build manifest | `/.vite/manifest.json`, plus the `dist/`, `build/`, `public/`, `static/` placements and the bare `manifest.json` under `dist/`, `build/`, `static/`, `assets/` | none | `spa-build-manifest` |
| PWA manifest | `/manifest.webmanifest`, `/site.webmanifest`, plus `dist/` and `build/` placements | none | `spa-webmanifest` |
| Referenced config chunk | `/assets/env-config-<hash>.js`, plus `dist/`, `build/`, `public/`, `static/` placements | `aws` | `spa-config-chunk-referenced` |
| Unreferenced config chunk | as above, hash not the one issued to that client | `aws` | `spa-config-chunk-foreign` |

Bare `/manifest.json` at the webroot is deliberately not claimed — it is a PWA
manifest on countless ordinary sites, and answering it would reach well past
the sweep this trap is for. `/assets/env-config.js` without a hash stays with
the `webapp-config-bundle-js` trap, which has a closer-fitting body.

## Response

The build manifest is ordinary Vite 5 output: an `index.html` entry with
`isEntry`, `css` and `imports`, a shared vendor chunk, a CSS asset, and an
`src/env-config.ts` entry whose `file` names `assets/env-config-<hash>.js`.
It carries no credential and requests no canary type — a manifest that held a
secret would not be a manifest.

The hash is an HMAC of the client address under a secret generated at process
start. So it is not in any wordlist, not shared between deployments, not
stable across restarts, and not reachable by enumeration; and it is the same
on both requests of a sweep, which is what lets a client that read the
manifest find the file it names.

The chunk itself renders the same `window.__RUNTIME_CONFIG__` shape and the
same `REACT_APP_AWS_*` / `VITE_AWS_*` / `NEXT_PUBLIC_AWS_*` canary slots as
the `webapp-config-bundle-js` body. A request carrying a well-formed hash that
this process did not issue to that address is served identically but tagged
`spa-config-chunk-foreign`.

The `.webmanifest` is a real PWA manifest and names no chunk. Its app name
goes through the same proxy-substituted-host guard as every vendor portal
title, so a deployment behind a rewriting proxy does not advertise itself as
`127.0.0.1`.

## Why

Every other referenced path this server serves is one a dictionary could have
reached on its own, so following a reference and replaying a wordlist produce
the same requests and cannot be told apart. A per-client hashed filename
breaks that tie: it exists in exactly one response, so a request for it is
evidence the client parsed what it was sent rather than merely receiving it.

That distinction is worth a route because the populations behave differently
once they have a credential, and volume alone does not separate them. It also
gives the `-foreign` tag something to mean — a well-formed hash this process
never issued is the shape a replay across deployments would take.

Both branches return the same body. Rewarding the parsing client differently
would advertise that the fork is being measured.
