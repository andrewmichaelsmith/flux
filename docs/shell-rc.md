# Shell rc files as a credential surface

`~/.bashrc`, `~/.profile`, `~/.zshrc` and their siblings, walked in the
same sweep as the `.env` / `.aws/credentials` dictionary and answered
with an rc file that exports cloud credentials from it.

## Routed paths

| Method | Path | Response |
| --- | --- | --- |
| `GET`, `HEAD`, `POST` | `/.bashrc`, `/.bash_profile`, `/.bash_login`, `/.profile`, `/.zshrc`, `/.zprofile`, `/.zshenv`, `/.kshrc`, `/.cshrc` | interactive-shell rc with an `export AWS_*` block carrying a Tracebit `aws` canary |
| `GET`, `HEAD`, `POST` | `/root/.bashrc`, `/root/.bash_profile`, `/root/.profile`, `/root/.zshrc`, `/home/ubuntu/.bashrc`, `/home/ubuntu/.profile` | same |
| `GET`, `HEAD`, `POST` | app-layout prefixed variants of `.bashrc` / `.profile` (`/app/…`, `/backend/…`, `/storage/…`, `/www/…`, …) | same |

Log tag `shell-rc`, `Content-Type: text/plain; charset=utf-8`.

Because the trap table is also what the `/@fs/<absolute path>` read
primitive resolves through, the home-dir spellings mean a filesystem
walk that asks for `/@fs/root/.bashrc` lands on the same renderer as a
webroot probe for `/.bashrc`.

## What the handler serves

An ordinary interactive-shell rc — history settings, `shopt`, the usual
`ls`/`grep` colour aliases, `EDITOR`, a `PATH` prepend — wrapped around
a short block of exported credentials with a comment explaining why
someone put them there. The AWS access-key / secret / session-token
triple is the per-request Tracebit canary; a registry token in the same
block is a per-hit synthetic. Nothing secret-shaped is a fixed literal.
Non-credential filler (aliases, paths, region, registry hostname) is
constant, which is what makes the file read as lived-in rather than
generated.

## Why

An `export AWS_ACCESS_KEY_ID=` line in a shell rc is the standard
workaround for a tool that cannot see `~/.aws/credentials`, and unlike a
`.env` beside an application it is attached to the *operator* rather
than the deployment — so it tends to hold longer-lived, more broadly
scoped credentials, and it survives the application being redeployed.
Harvester dictionaries know this, which is why the rc names arrive
interleaved with the credential-file names rather than in a separate
pass.

Serving it costs one canary and converts a request that produced nothing
into a monitored credential on the surface most likely to carry real
ones. The rc file also states, in its own contents, what the operator
was doing — the comment and the surrounding exports are the plausible
context that makes a harvester treat the keys as live rather than as
sample data.

Requires `TRACEBIT_API_KEY` like every canary-backed trap; a keyless
deployment 404s it.
