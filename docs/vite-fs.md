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

## System files

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
| `php.ini` (every packaged location — `/etc/php/<version>/<sapi>/php.ini`, `/etc/php.ini`, `/usr/local/etc/php/php.ini`, …) | Distro defaults. A client reads it for `allow_url_include` / `allow_url_fopen` / `disable_functions` — the directives that say whether the next step in the chain is available |
| `/etc/shadow` | Hashes minted per hit, over the same account list as `/etc/passwd`. Root-only, so asking for it is a different question: whether the read runs privileged |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` (and the `/run` spelling) | A projected service-account JWT, minted per hit |
| `…/serviceaccount/namespace` | The namespace the token claims, so the volume describes one coherent pod |
| `…/serviceaccount/ca.crt` | The cluster CA bundle — public material, random per hit so it is not a fleet constant |

Most of these bodies carry no credential, so no canary is spent and no
per-IP quota applies. The service-account token is the exception: it is a
bearer, so it follows the same rule the rest of the surface does and is
**unique per hit**. A fixed one would ship the same string from every
deployment — a fleet fingerprint — and no later use of it could ever be
traced back to the read that leaked it.

The projected volume is worth answering because it asks a different
question from the three `/etc` files above: not "does this read work" or
"does it run privileged", but "is this a container, and can I have its
cluster identity". A source that pulls `token` and stops has told us less
than one that also pulls `namespace` and `ca.crt` — the latter is the
shape of a client assembling a working API-server config, and the three
tags separate those populations.

Keeping the list fixed is the point: answering every system path a
scanner can name would be its own obvious tell, and the misses stay
worth reading.

## What it logs

Result tag is `vite-fs-<trap>` on a hit, `vite-fs-etc-passwd` /
`vite-fs-etc-shadow` / `vite-fs-etc-nginx-conf` / `vite-fs-etc-php-ini` /
`vite-fs-k8s-serviceaccount-{token,namespace,ca-cert}` for a system
file, and `vite-fs-miss` otherwise. The
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
