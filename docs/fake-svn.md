# Fake Subversion working copy

The `/.svn/` sibling of the [fake `/.git/` tree](../README.md#traps) — a
Subversion working copy left in a webroot, answered in both of the
layouts Subversion has used.

## Routed paths

| Method | Path | Response |
| --- | --- | --- |
| `GET`, `HEAD` | `/.svn`, `/.svn/` | Apache-style autoindex of the working copy's admin directory |
| `GET`, `HEAD` | `/.svn/entries`, `/.svn/format` | pre-1.7 working-copy metadata; `entries` carries the repository URL |
| `GET`, `HEAD` | `/.svn/text-base/<name>.svn-base` | pre-1.7 pristine copy of a tracked root-level file |
| `GET`, `HEAD` | `/.svn/wc.db` | 1.7+ working-copy database — a real SQLite file |
| `GET`, `HEAD` | `/.svn/pristine/<xx>/<sha1>.svn-base` | 1.7+ pristine copy, named by the checksum `wc.db` records |
| `GET`, `HEAD` | `/.svn/auth/svn.simple/<md5(realm)>` | Subversion's saved-credential cache, in its hash-dump format |
| `GET`, `HEAD` | `/.svn/all-wcprops`, `/.svn/dir-prop-base` | per-directory property files |
| `GET`, `HEAD` | `<prefix>/.svn/<child>` | same, for apps deployed at a subpath; the `.svn` segment is case-insensitive |

Log tags `fake-svn` (200, with `svnKey`, `svnRevision`, `svnRepoUuid`,
`svnAuthCached`, `canaryTypes`, `bytes`), `fake-svn-miss` (404, a child
that resolved to the tree but isn't a file in it), and `fake-svn-error`
(canary issuance failed — answers the same `404 not found` body as an
unrouted path, so the failure is invisible to the client).

Enabled by `FAKE_SVN_ENABLED` (default on). Requires `TRACEBIT_API_KEY`
like every canary-backed trap; a keyless deployment 404s it.

## What the handler serves

A four-file working copy — `.env`, `README.md`, `deploy.sh`,
`config/database.yml` — checked out from a repository whose URL embeds
the canary. It is built once per source IP and cached with a TTL, so a
dictionary sweep across the whole `.svn/*` list costs one canary
issuance and sees one internally consistent tree.

Both generations are answered on purpose. The pre-1.7 layout stores
metadata in a plain-text `entries` file and pristine copies under
`text-base/`; the 1.7+ layout stores them in a SQLite `wc.db` and a
content-addressed `pristine/` store. `wc.db` is a genuine database, not
a stub, because a client that understands the modern layout opens it
with SQLite and reads `NODES` for the file list and each file's
`$sha1$…` checksum — and that checksum has to name a pristine file the
trap actually serves, holding bytes that actually hash to it. Both
layouts describe the same four files, and the two spellings of each
pristine copy return identical bytes.

There are three independent places a credential can be picked up:

1. the repository URL in `entries` and in the `wc.db` `REPOSITORY` row,
   carrying the canary as HTTPS Basic userinfo — so a client that reads
   only the metadata file still leaves with a live credential;
2. `.svn/auth/svn.simple/<md5(realm)>`, Subversion's own saved-credential
   cache, holding a username/password canary in the real hash-dump
   serialization;
3. the pristine copy of `.env`, holding the canary in a dotenv body.

Nothing secret-shaped is a fixed literal: the AWS triple and the
username/password pair are per-request Tracebit canaries, and the
database password in `config/database.yml` is a per-hit synthetic.
Non-credential filler — usernames, host names, the ignore list — is
constant, which is what makes the checkout read as real.

## Why

A working copy committed into a webroot is one of the oldest and most
durable source-disclosure exposures, and the tooling to exploit it is
mature: given `entries` or `wc.db`, a dumper reconstructs the tracked
file list and pulls each file's pristine copy, recovering source that
was never meant to be served. That the `.svn/*` dictionary is still
walked heavily — interleaved with `.git/config` in the same sweeps —
long after Subversion stopped being the default VCS is a good measure of
how well it still pays off for the people walking it.

Answering it turns a flat 404 into a graded observation. A client that
takes `entries` and stops is running a dictionary. A client that reads
`wc.db`, extracts a checksum, and comes back for the pristine file it
names has implemented the working-copy format, which is a much smaller
population and a much stronger signal about tooling. And which of the
three credential placements a client picks up says how deep it went —
metadata only, credential cache, or all the way to file contents.

Serving both layouts is what makes that comparison possible: answering
only the modern one would drop every pre-1.7 dumper at its first
request, and answering only the legacy one would drop every modern one,
in each case turning a distinguishable population into an
indistinguishable 404.
