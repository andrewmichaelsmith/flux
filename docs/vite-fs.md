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

## World-readable system files

The suffix walk above only ever consults the credential trap table, which
is webroot-relative. An absolute system path has no suffix that appears in
it, so every such read fell out as a miss.

That inverted the exploit. `/etc/passwd` is the file a scanner reads
*first*, to confirm the read primitive actually works, before walking to
anything worth stealing. Serving the credential files while 404ing the
oracle that gates them is backwards twice over: no real `server.fs.deny`
bypass fails on a world-readable file, so the mismatch is a tell, and a
scanner that gates on the oracle leaves before it ever reaches a canary.

So a fixed table of system files is answered statically, checked **after**
the credential walk has missed — it can never shadow a trap that would
have issued a canary — and matched **exactly**, not walked, because a
system file only means anything at the path it really lives at
(`/@fs/var/www/etc/passwd` is still a miss).

| Path | Body |
| --- | --- |
| `/etc/passwd` | The same account list the command-injection trap prints for `cat /etc/passwd`, so a scanner probing both surfaces sees one consistent host |
| `/etc/nginx/nginx.conf` | The unmodified packaged config — no vhost, no upstream, nothing that reflects real deployment shape |

These bodies carry no credential, so no canary is spent and no per-IP
quota applies. Keeping the list fixed is the point: answering every system
path a scanner can name would be its own obvious tell, and the misses stay
worth reading.

## What it logs

Result tag is `vite-fs-<trap>` on a hit, `vite-fs-etc-passwd` /
`vite-fs-etc-nginx-conf` for a system file, and `vite-fs-miss`
otherwise. The
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
| `HONEYPOT_VITE_FS_SYSTEM_FILES_ENABLED` | `true` | Answer the world-readable system-file list |
