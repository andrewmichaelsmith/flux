# Laravel Debugbar stored-request browser

Serves the `/_debugbar/*` surface a Laravel app exposes when Debugbar is
left enabled in production — either `APP_DEBUG=true` shipped by mistake,
or the package sitting in `require` instead of `require-dev`. Default-on
via `HONEYPOT_LARAVEL_DEBUGBAR_ENABLED`; dispatch also requires
`TRACEBIT_API_KEY`.

| Path | Response | Canary |
| --- | --- | --- |
| `/_debugbar`, `/_debugbar/` | Stored-request listing (JSON) | no |
| `/_debugbar/open`, `?op=list` | Stored-request listing (JSON) | no |
| `/_debugbar/open?op=get&id=<id>` | One captured request, in full (JSON) | **`aws`** |
| `/_debugbar/assets/javascript` | DebugBar JS stub | no |
| `/_debugbar/assets/stylesheets` | DebugBar CSS stub | no |
| `/_debugbar/clockwork` | `{}` — the unconfigured Clockwork shim | no |
| anything else under `/_debugbar/` | 404 | no |

Trailing slashes are tolerated and matching is case-insensitive.

The listing advertises `LARAVEL_DEBUGBAR_STORED_REQUESTS` (5) entries,
each a `__meta` block: id, datetime, utime, method, uri, ip. Ids are
derived deterministically from the requested host — they are storage
keys, not secrets, so a stable derivation is correct and is what makes
the discriminator below possible. Two different hosts advertise
different ids, and an id minted for one host is not recognised at
another.

The payload step returns a full captured request: `php`, `messages`,
`time`, `memory`, `queries` and `request`. The AWS canary lands in
`request.env` — the slot a real `RequestDataCollector` fills from
`$_ENV` — and is repeated in the bindings of the `update settings …`
statement in the `queries` panel, because a real dump leaks credentials
in both places and one that leaked in only one would read as
hand-made. `APP_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, `MAIL_PASSWORD`,
the CSRF `_token` and the session id are per-hit synthetics. There are
no fixed credential literals.

Logged on every step: `debugbarOp` (which step), `debugbarStoredId` (the
id named, if any) and `debugbarIdKnown`.

## Why

This is a **two-step** surface, and the second step is the whole point.

The listing carries no secret. A scanner walking a path dictionary fires
`/_debugbar/open` because the path is on its list, reads a body with
nothing greppable in it, and moves on — that is the overwhelming
majority of the traffic this path sees. A client that *parses* the
listing and comes back with `op=get&id=<id>` naming an id we just handed
it has implemented the protocol rather than replayed a string, and that
is a far smaller and more interesting population.

`debugbarIdKnown` is what separates the two, and it separates them
cheaply: because ids are host-deterministic, the check is a set
membership test with no server-side session state, and it still holds
across a listing and a fetch arriving on different connections. This is
the same discriminator the instance-metadata trap gets from `imdsRole`,
applied to a framework debug surface instead of a cloud one.

The canary placement also earns something the `.env` trap cannot. A
credential harvested from a debug dump arrives with context attached —
an app name, a route, a database schema — so a later replay is
attributable to *this* surface rather than to the generic secret-file
sweep that hits every host on the internet.
