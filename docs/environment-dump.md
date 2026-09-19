# `_environment` route

Answers a route named `_environment` with a `KEY=value` dump of the
process environment.

| Property | Value |
| --- | --- |
| Paths | `/_environment`, `/webroot/index.php/_environment`, `/index.php/_environment`, `/app.php/_environment`, `/public/index.php/_environment` |
| Canary | `aws`, in `AWS_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` / `_SESSION_TOKEN` |
| Other secrets | `DB_PASSWORD`, per-hit random |
| Content type | `text/plain` |
| Log tag | `environment-dump` |

## Why

This belongs to the same class as the dev-mode debug surfaces in
[`framework-debug.md`](./framework-debug.md) — a route that should never be
routable in production and that prints the environment when it is.

The framework behind it is deliberately **not** claimed. The route arrives
both at the webroot and behind a front-controller prefix, from
near-identical source populations, which says one client is testing two
deployment layouts — it does not identify a product. Rather than guess a
vendor and render a body that a client familiar with that product could
falsify, the response is the lowest common denominator every such route
shares: `KEY=value` lines. That is the shape the client is grepping for
whichever framework emitted it, so the weaker attribution costs nothing in
plausibility.

The bare and prefixed spellings are listed as separate entries rather than
matched by pattern, so an unrelated path ending in `_environment` still
404s.
