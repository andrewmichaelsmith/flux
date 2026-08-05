# Vite `/@fs/` arbitrary file read

Vite's dev server serves files outside the project root through a
`/@fs/<absolute path>` prefix. Several disclosed `server.fs.deny` bypasses
turned that into an unauthenticated arbitrary-read primitive against any
dev server left reachable from the internet, and scanners now walk it.

| Request | Response |
| --- | --- |
| `GET /@fs/<absolute path>` resolving to a file we serve | `200` with that file's normal trap body, including a per-hit canary |
| `GET /@fs/<absolute path>` resolving to anything else | `404 not found` |
| Any non-`/@fs/` path | Not claimed — falls through to the trap that owns it |

## Why this isn't a path list

Every other trap here matches webroot-relative URLs a scanner picked out
of a dictionary, so a list of literals is a workable way to cover them.
`/@fs/` takes an **absolute filesystem path**, which the client composes
freely — enumerating literals is unwinnable, and the handful of
`/@fs/...history` entries that predated this trap only ever matched a
fraction of what arrives.

So instead of matching the request, the handler resolves it. It strips the
prefix, collapses `.` / `..` / empty segments, then walks leading
directory segments off the resulting absolute path one at a time and looks
each suffix up in the existing exact-path trap table, longest first:

```
/@fs/usr/src/app/.env  ->  /usr/src/app/.env   (miss)
                       ->  /src/app/.env       (miss)
                       ->  /app/.env           (miss)
                       ->  /.env               (hit — serve the .env body)
```

A prefix nobody has ever catalogued therefore still lands on the renderer
for the file the scanner actually asked for, and every trap added to the
table in future is reachable through `/@fs/` for free. The walk is bounded
by `HONEYPOT_VITE_FS_MAX_SUFFIX_WALK` (default 12) so a deeply nested
request can't turn into an unbounded lookup.

Unresolvable paths get a `404`, which is what a real dev server returns
for a file that isn't there. Answering everything would be an obvious
tell, and the miss is still logged — the paths we decline to furnish are
as descriptive of the tooling as the ones we serve.

## What it logs

Result tag is `vite-fs-<trap>` on a hit and `vite-fs-miss` otherwise. The
prefix keeps the filesystem-walk population separable from the webroot
population: the same body served for `/.aws/credentials` and for
`/@fs/root/.aws/credentials` represents two different scanner behaviours
and shouldn't share a bucket.

| Field | Meaning |
| --- | --- |
| `viteFsRequestedPath` | The absolute path the client named, post-collapse |
| `viteFsRawSuffix` | Everything after `/@fs/`, before collapse |
| `viteFsMatchDepth` | Leading directories stripped to find the trap; `0` = exact table hit |

`viteFsRequestedPath` is the reason this trap is worth more than the 404
it replaces. It is the only field flux records that captures an
attacker's *belief about the target's on-disk layout* — no other surface
lets a client name a filesystem path. `/home/node` says they expect a
Docker Node image, `/var/www/html` a classic LAMP box, `/usr/src/app` a
containerised app, `/workspace` a devcontainer. `viteFsMatchDepth` says
whether that layout was one we already knew about.

## Dispatch order

The handler runs **ahead of the generic tarpit**. Most `/@fs/` traffic is
`.env`-suffixed, which `is_tarpit_path` would otherwise claim, and the
tarpit issues no canary — taking it here would trade a replay-detectable
credential for a held connection on the one surface that also reveals the
assumed filesystem layout. With `HONEYPOT_VITE_FS_ENABLED=false` (or no
`TRACEBIT_API_KEY`) the branch falls through and those paths tarpit as
they did before.

Note that traversal climbing *above* the prefix (`/@fs/../../../etc/...`)
is collapsed by `normalize_path` before dispatch, so the `/@fs/` prefix is
gone by the time this trap would see it and the request is logged as a
plain probe for the resolved path. Same body, same canary, different tag —
correctly, since it is no longer an `/@fs/` read.

## Config

| Env var | Default | Effect |
| --- | --- | --- |
| `HONEYPOT_VITE_FS_ENABLED` | `true` | Master switch |
| `HONEYPOT_VITE_FS_MAX_SUFFIX_WALK` | `12` | Max leading directories stripped during resolution |
