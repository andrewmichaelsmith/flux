# Non-Node dependency manifests

Composer (PHP), Bundler (Ruby) and pip (Python) manifests, answered in each
ecosystem's native format with the private-registry credential supplied as a
canary.

| Path | Method | Response | Log tag |
| --- | --- | --- | --- |
| `/composer.json` (+ `.bak` / `.old` / `.save`) | GET | Composer manifest JSON; canary in the `config.http-basic` block | `composer-json` |
| `/composer.lock` (+ `.bak` / `.old`) | GET | Composer lockfile JSON; canary in each package's `source` / `dist` URL userinfo, per-hit commit `reference` | `composer-lock` |
| `/Gemfile` (+ `.bak` / `.old`) | GET | Bundler manifest; canary in the scoped `source` URL userinfo | `gemfile` |
| `/Gemfile.lock` (+ `.bak` / `.old`) | GET | Bundler lockfile with `GEM` / `PLATFORMS` / `DEPENDENCIES` / `CHECKSUMS` / `BUNDLED WITH` sections; canary in `remote:`, per-hit sha256 per gem | `gemfile-lock` |
| `/requirements.txt` (+ `.bak` / `.old`), `/requirements-dev.txt`, `/requirements/base.txt` | GET | pip requirements with `--extra-index-url` carrying the canary, per-hit `--hash=sha256:` pins | `requirements-txt` |
| `/Pipfile` (+ `.bak`) | GET | Pipfile TOML with a public and an internal `[[source]]`; canary in the internal index URL | `pipfile` |

Path matching is exact against the canary-trap table, which folds case — which
does real work here, because the mixed-case spellings (`Gemfile`, `Pipfile`)
are the canonical ones. `Pipfile.lock` is deliberately **not** claimed: it is
JSON, and answering a JSON filename with the TOML `Pipfile` body is a worse
tell than the 404 it would replace.

Each format carries private-registry credentials in the file itself, so the
canary placement is the same idea in each ecosystem's own spelling rather than
a generic blob: Composer's `http-basic` block, Bundler's `source` URL userinfo,
pip's `--extra-index-url`. Whichever single file a client takes, it walks away
with the same replayable credential. Inside a URL the password is
percent-encoded, which is what keeps it recoverable rather than a parse error
at the other end.

Everything secret-shaped is per-hit: the credential is the issued canary, and
falls back to a per-hit synthetic if issuance fails. The integrity material —
Composer commit `reference`s, Bundler `CHECKSUMS`, pip `--hash` pins — is
per-hit random, so two hosts running this software never serve byte-identical
lockfiles. The package names and versions are fixed filler, which is fine
because they are not credentials.

## Why

The Node set (`package.json`, `package-lock.json`, `yarn.lock`, `.yarnrc*`)
was already answered and every other ecosystem's equivalent returned 404.
Harvesters walking a config/secret dictionary ask for all of them in the same
pass, so two things were wrong with that. The reads were simply lost. And a
server that hands over a Node lockfile while insisting it has no
`composer.lock` describes a stack that does not exist — a tell available to
anyone who bothers to ask for both, which the dictionaries do by default.

Dependency manifests are also the fingerprinting step that precedes a targeted
exploit attempt: the question they answer is "which package, at which
version". Naming a small internal-looking dependency set at pinned versions is
what makes a follow-up request, if one comes, worth reading — a client that
returns asking about something it could only have learned here has told us
what it does with the answer.

The editor-backup spellings (`.bak` / `.old` / `.save`) are included for the
same structural reason the phpinfo and env families carry them: the webshell
sweep gate only claims names ending in `.php`, so a backup suffix puts the
name permanently out of its reach. No amount of sweep width opens those — only
an entry does.
