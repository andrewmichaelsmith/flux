# Framework build-config files

The repo-root config module a JS framework's build reads —
`next.config.js`, `nuxt.config.ts`, `gatsby-config.js`, `vite.config.ts`
and their siblings. Four renderers, one per framework family.

| Trap | Paths | Canary | Log tag |
| --- | --- | --- | --- |
| Next.js | `next.config.{js,ts,mjs,cjs}` | `aws` | `next-config-js` |
| Nuxt 3 | `nuxt.config.{ts,js,mjs}` | `aws` | `nuxt-config-ts` |
| Gatsby | `gatsby-config.{js,ts}` | `aws` | `gatsby-config-js` |
| Bundlers | `vite`/`svelte`/`astro`/`vue`/`remix`/`webpack`/`rollup` `.config.{js,ts,mjs}` | `aws` | `bundler-config-js` |

Each leaf is served at webroot and under `/app/`, `/src/`, `/frontend/`,
`/web/`, `/client/` — the places a checked-out app actually sits. The
prefix set is deliberately narrower than the runtime-bundle traps': these
files live at repo root, so answering them under `/static/js/` would
describe a layout no real deployment produces, which is its own
fingerprint.

Every body puts the Tracebit AWS canary in the slot that framework uses
for a **server-only** secret, because that is where a real leaked one
lives and it is what separates a collector that understands the framework
from one grepping blindly:

- Next — `serverRuntimeConfig`, which is not serialised into the client
  bundle. `publicRuntimeConfig` and `env` carry only non-secret values.
- Nuxt — top-level `runtimeConfig` keys, never the `public` sub-object.
- Gatsby — plugin options (`gatsby-source-s3`), which is how Gatsby
  actually takes credentials, plus a per-hit bearer token on
  `gatsby-source-graphql`.
- Bundlers — the compile-time `define` block, which is what makes these
  files dangerous: a value there is substituted into the shipped output.

Alongside the credential, each body names
`/assets/env-config-<hash>.js` — the same per-client chunk the
[SPA build manifest](./spa-build-manifest.md) references, injected the
idiomatic way for each framework (`publicRuntimeConfig.runtimeConfigUrl`,
`app.head.script`, `gatsby-plugin-load-script`,
`define['process.env.RUNTIME_CONFIG_URL']`). The hash is an HMAC of the
client address under a per-process secret, so a request for that path can
only come from a client that parsed a body served to it, and it lands on
the existing `spa-config-chunk-referenced` tag.

## Why

These spellings were recurring across all four families, from several
sources and on many separate days, while every one of them fell through
to a 404 — and the population walking them is one that demonstrably
collects what it is offered across a wide set of credential-file traps
rather than merely enumerating.

They are not aliases onto the runtime-config bundle trap, which serves
`window.__APP_ENV__ = {...}`. That is a browser artifact; these are Node
modules. A collector greping a `nuxt.config.ts` for `defineNuxtConfig`
would discard the bundle body, so the wrong shape would lose the very
hit the trap exists to capture.

The reference is the part worth watching. For a credential-collecting
population we already know issuance works; what we do not know is
whether anything *parses* what it takes. A hit on the referenced chunk
would be the first evidence of that, and its absence over a fair window
is a real answer too.

One limitation, stated because it bounds the inference: the chunk path is
shared with the build-manifest trap, so a `referenced` hit proves a body
was parsed but not which of the two it was. Separating them would need a
second chunk route.
