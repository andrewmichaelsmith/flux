# World-readable system files, read by absolute path

The fixed system-file list answered when a request names one of these
files by its own absolute path. It is the same table the Vite `/@fs/`
reader serves — see [vite-fs.md](./vite-fs.md) — reached the other way a
read primitive delivers a path.

| Path | Response |
| --- | --- |
| `/etc/passwd` | Stock account list |
| `/etc/shadow` | Per-hit hashes — see `render_fake_shadow` for why a fixed one would be worse than serving nothing |
| `/etc/nginx/nginx.conf` | Stock distribution config |
| `php.ini` at every packaged location (`/etc/php.ini`, `/etc/php/<7.0–8.4>/{apache2,cgi,cli,fpm}/php.ini`, `/etc/php7/php.ini`, `/etc/php8/php.ini`, `/usr/local/etc/php/php.ini`, `/usr/local/lib/php.ini`) | Stock config |
| `/{var/,}run/secrets/kubernetes.io/serviceaccount/token` | Projected service-account JWT, minted per hit |
| `/{var/,}run/secrets/kubernetes.io/serviceaccount/namespace` | The namespace, no trailing newline, as kubelet writes it |
| `/{var/,}run/secrets/kubernetes.io/serviceaccount/ca.crt` | Cluster CA bundle, per-hit body |
| `/.dockerenv` | `200` with a **zero-byte** body — the real file is empty, and its existence is the whole message |
| `/proc/{self,1}/cgroup` | cgroup v2 `0::` line naming a burstable pod under containerd; pod UID and container ID random per hit |
| `/proc/{self,1}/cmdline` | NUL-separated argv, trailing NUL |

Matching is exact and case-folded. There is deliberately **no layout
walk**: a credential file moves with the project it belongs to, so
`/admin/aws.json` is a name a real deployment could have, but
`/app/etc/passwd` is not. Anything outside the list 404s — this is a
fixed table, not an answer-everything switch, which would be its own
obvious tell.

Each read is logged with the file's own result tag (`etc-passwd`,
`k8s-serviceaccount-token`, `proc-cgroup`, …) and the response length.
A read arriving through `/@fs/` keeps its prefixed tag
(`vite-fs-etc-passwd`), so the two surfaces stay countable against each
other. The `rawPath` field preserves the spelling as sent, which is what
distinguishes a collapsed traversal from a bare request.

Disable with `HONEYPOT_SYSTEM_FILE_READS_ENABLED=false`. None of these
bodies carries a canary, so the surface needs no issuing key and keeps
working on a keyless deployment, where almost nothing else does.

## Why

A scanner that finds an arbitrary-read primitive does not spend it on
credentials first. It reads a file every host is known to have — to
confirm the primitive works at all — and only then walks the dictionary
of files worth taking. Answering the credential files while 404ing the
oracle that gates them inverts the exploit: no real read bypass fails on
a world-readable file, and a client that concludes the primitive is dead
never reaches anything worth issuing a canary for.

That reasoning is why the table exists. It was reachable only behind the
`/@fs/` dev-server prefix, which is one of the two ways the same path
arrives:

- **Collapsed traversal.** Path normalisation repairs the no-slash form
  and collapses the `..` segment, so `/static../etc/passwd`,
  `/js../etc/passwd`, `/assets../etc/passwd` and the percent-encoded
  spellings all reach dispatch as the bare absolute name. The read
  primitive was exercised and the answer was a 404.
- **No traversal at all.** A dictionary that has no bypass to spend just
  asks for `/etc/passwd`, `/.dockerenv`, `/proc/self/cmdline`,
  `/var/run/secrets/kubernetes.io/serviceaccount/token`. Recurring
  volume across many distinct sources, every day.

The precedent was already in the trap table, which has answered bare
`/proc/self/environ` since that trap shipped — and which is also where
the inconsistency showed. The container-recon step reads four files in
one pass: `/.dockerenv` says "a container", `/proc/<pid>/cgroup` names
the orchestrator and the pod under it, `/proc/<pid>/cmdline` names the
process, and `/proc/<pid>/environ` is the environment block. Answering
the environment while insisting the same process has no command line
describes a machine that does not exist, which is a sharper tell than
any of the three bodies could be. The cgroup line and the projected
service-account volume are also the two reads that agree with each
other: a reader that takes the cgroup path, sees a kubelet slice and
then walks to the token is following a chain that holds up.

Identifiers inside these bodies are random per hit — the pod UID, the
container ID, the service-account token's UIDs and signature — for the
same reason no credential-shaped field in this project is ever a fixed
literal: a constant would be one pod, one bearer, shared by every host
running this software, so a single observation would fingerprint the
whole deployment. Non-identifying filler (the argv, `PATH`, `PWD`) stays
fixed, and the command line is deliberately the runtime the environment
block already claims, because the two files are read in one pass.
