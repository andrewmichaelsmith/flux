# flux

A small async HTTP honeypot intended to run behind nginx on a public sensor.
Python 3.11+; one runtime dep — [aiohttp](https://docs.aiohttp.org/).

Async so the tarpit and fake-git drip paths can hold thousands of concurrent
slow-drip connections at ~8 KB each instead of one OS thread each.

> **Heads up: this is a pure vibe-coded app.** Every line was written by an
> LLM working off natural-language prompts from a human operator, then smoke-
> tested against a live sensor. It has not been audited by a human who read
> every line. If you're planning to deploy it anywhere that matters, please
> read [`flux/server.py`](./flux/server.py) end-to-end first, run the test
> suite, and think about what `HONEYPOT_WEBSHELL_PATHS_CSV` or `FAKE_GIT_*`
> hitting a real webroot would do. No warranties.

Six trap families, each independently toggleable via env var:

1. **Fake `/.env` canary issuer** — mints a per-request Tracebit Community
   canary and returns it as a `.env`-style payload. Requires `TRACEBIT_API_KEY`.
2. **Fake `/.git/` repository** — serves a loose-object git tree whose
   `config/secrets.yml` embeds a canary. Per-IP cached so `git-dumper`-style
   scanners see a consistent tree across their fan-out. Requires `TRACEBIT_API_KEY`.
3. **Canary file traps** — 19 plausible paths (`/.aws/credentials`,
   `/wp-config.php`, `/backup.sql`, `/id_rsa`, `/api/v4/user`,
   `/users/sign_in`, …) each render a canary in the file format a scanner
   expects. See [the table below](#canary-file-trap-table). Requires
   `TRACEBIT_API_KEY`.
4. **Fake webshell** — matches known webshell probe paths
   (`/wp-content/plugins/hellopress/wp_filemanager.php`, `/shell.php`,
   short-named `*.php` shells) and returns a plausible File Manager page
   that invites follow-up commands. Simulates `id` / `whoami` / `uname -a` /
   `cat /etc/passwd`. No Tracebit key required.
5. **Modular tarpit + fingerprinting** — streams a slow-drip response
   with a chain of fingerprinting modules (cookie, ETag, redirect chain,
   variable drip, Content-Length mismatch, DNS callback — all default-on).
   Triggered on `.env` variants (`.env.bak`, `*/.env.prod`) or on a
   configurable set of first-contact paths (default: `/`, `/index.html`,
   `/index.php`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`). No
   Tracebit key required.
6. **Fake LLM-API endpoint** — serves plausible Ollama / OpenAI /
   Anthropic-proxy responses on common AI-probe paths (`/v1/models`,
   `/anthropic/v1/models`, `/api/version`, `/api/chat`, `/v1/chat/completions`,
   …). Logs the model requested, any `Authorization: Bearer` or `x-api-key`
   header, and a prefix of the POSTed prompt body. No Tracebit key required.
   See [below](#fake-llm-api-endpoint) for why this exists.

All traps log one JSON line per event to the configured log path. See
[`LOGS.md`](./LOGS.md) for the schema.

## Install

```bash
pip install .
```

Or in place (needs `aiohttp` on the path):

```bash
pip install aiohttp
python -m flux
```

## Run

Flux listens on `127.0.0.1:18081` by default. The expected deployment puts
nginx in front and proxies a set of trap paths (e.g. `/.env`, `/.git/*`,
`/shell.php`, etc.) to it; nginx handles TLS, `X-Forwarded-*` headers, and
all non-trap routing.

```bash
export TRACEBIT_API_KEY=...  # optional — enables canary-backed traps (/.env, /.git/*, etc)
python -m flux
```

Docs: [`CONFIG.md`](./CONFIG.md) (env vars) ·
[`LOGS.md`](./LOGS.md) (JSONL schema + `result` tags) ·
[`BENCH.md`](./BENCH.md) (throughput + tarpit saturation numbers).

## Canary file trap table

All gated on `TRACEBIT_API_KEY`, with per-IP TTL caching to protect quota.
Toggle the whole category with `CANARY_TRAPS_ENABLED`. Paths are
case-insensitive exact matches.

| Trap | Paths | Canary type | Log tag |
| --- | --- | --- | --- |
| AWS credentials file (INI) | `/.aws/credentials` | `aws` | `aws-credentials-file` |
| WordPress config | `/wp-config.php` (+`.bak`/`.old`/`.txt`) | `aws` | `wp-config` |
| SQL dump | `/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`, `/backup/db.sql`, `/sql/backup.sql` | `aws` | `sql-dump` |
| Generic JSON config | `/config.json`, `/settings.json`, `/credentials.json`, `/secrets.json` | `aws` | `config-json` |
| Firebase / GCP SA | `/firebase.json`, `/google-services.json`, `/serviceaccount.json`, `/service-account.json` | `aws` | `firebase-json` |
| Docker client | `/.docker/config.json`, `/docker/config.json` | `aws` | `docker-config` |
| Docker Compose | `/docker-compose.yml`, `/docker-compose.yaml`, `/compose.yml`, `/compose.yaml` | `aws` | `docker-compose` |
| Spring properties | `/application.properties` | `aws` | `application-properties` |
| Spring YAML | `/application.yml`, `/application.yaml` | `aws` | `application-yml` |
| Production .env | `/.env.production`, `/.env.prod`, `/.env.live` | `aws` | `env-production` |
| phpinfo() | `/phpinfo.php`, `/info.php`, `/php.php`, `/test.php` | `aws` | `phpinfo` |
| SSH private key | `/id_rsa`, `/.ssh/id_rsa`, `/ssh/id_rsa`, `/ssh/id_rsa.key`, `/keys/id_rsa`, `/private.key`, `/deploy_key`, `/deploy.key` | `ssh` | `ssh-private-key` |
| SSH public key | `/id_rsa.pub`, `/.ssh/id_rsa.pub` | `ssh` | `ssh-public-key` |
| authorized_keys | `/authorized_keys`, `/.ssh/authorized_keys` | `ssh` | `authorized-keys` |
| .netrc | `/.netrc`, `/_netrc` | `gitlab-username-password` | `netrc` |
| .npmrc | `/.npmrc` | `gitlab-username-password` | `npmrc` |
| .pypirc | `/.pypirc` | `gitlab-username-password` | `pypirc` |
| GitLab API user | `/api/v4/user` | `gitlab-username-password` | `gitlab-api-user` |
| GitLab sign-in | `/users/sign_in` | `gitlab-cookie` | `gitlab-sign-in` |

`/users/sign_in` returns the cookie canary as `Set-Cookie:
_gitlab_session=<value>`. `/api/v4/user` embeds the username/password
canary as a plausible GitLab API user response.

The four canary types (`aws`, `ssh`, `gitlab-username-password`,
`gitlab-cookie`) are everything Tracebit Community currently exposes via
[`/openapi.json`](https://community.tracebit.com/openapi.json). Email
and LLM canaries are hinted at in Tracebit marketing but not yet in the
API; new trap surfaces for those will land when the API does.

## Tests

```bash
pip install -e '.[dev]'
python -m pytest
```

Two test files:

- `tests/test_server.py` — pure-function tests (renderers, path matchers,
  parsers) + dispatch tests via aiohttp's in-process `TestClient`.
- `tests/test_integration.py` — binds flux to a random port on 127.0.0.1
  and hits it with a real HTTP client over the kernel loopback. Catches
  anything that only breaks on a real socket.

## Fake LLM-API endpoint

Scanners started hunting for exposed AI inference servers in April 2026.
The trap matches these paths (exact, case-insensitive; configurable via
`HONEYPOT_LLM_ENDPOINT_PATHS_CSV`):

| Family | Paths | Response |
| --- | --- | --- |
| Ollama | `/v1/models`, `/api/tags`, `/api/version`, `/api/ps`, `/api/show`, `/api/chat`, `/api/generate` | Ollama-native JSON with a fixed list of plausible model IDs |
| OpenAI | `/v1/models`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` | OpenAI-compatible JSON |
| Anthropic | `/v1/messages`, `/anthropic/v1/models`, `/anthropic/v1/messages` | Anthropic Messages-API JSON |

On any POST the trap parses `model` and a prompt-ish field out of the JSON
body (handles OpenAI/Ollama/Anthropic content shapes), then logs them along
with the scanner's auth header, UA, and IP. Chat responses are a
deterministic canned reply — bland enough to look boring, not real enough
to be abusable.

### Why this exists

The 2026-04-20 weekly-novelty run caught a new scanner — `scanner/1.0`
from `203.0.113.10` — sending 26 requests to `/anthropic/v1/models` in
one day. Three other IPs (`203.0.113.11`, `203.0.113.12`,
`203.0.113.13`) hit `/v1/models`. Earlier, on Apr 18, the lab sensor
saw the Ollama signature (`/v1/models` + `/api/version` from
`203.0.113.14`).

These scanners are looking for:

- **Exposed self-hosted Ollama / llama.cpp servers** — unauthenticated by
  default, so a `200 OK` on `/api/tags` with a real model list is an
  immediate prompt-execution primitive.
- **Internal AI-proxy gateways** (`/anthropic/v1/models`) — corporate
  relays that hold an upstream API key, which a scanner can then use from
  the proxy without needing the key itself.
- **Harvested API keys in the wild** — the scanner already has a
  `Bearer sk-...` or `x-api-key` from a credential dump and is probing
  who'll honor it.

The intel we want: the model a scanner targets, the prompt they send on
their first successful POST, the auth header they present, and the
follow-up sequence when they believe the endpoint is live. None of that
is visible from a bare 404.

See `LOGS.md` for the `llm-endpoint-*` result tags and the `llmModel` /
`llmPromptPreview` / `llmHasAuth` fields.

## Why a fake webshell on a sensor that never had a real shell?

Because post-compromise scanners — e.g. the Azure WP Webshell Checker family
observed probing our sensors in April 2026 — walk a list of PHP shell paths
looking for "is my planted shell still here". They don't care whether your
site ever ran WordPress. A plausible response makes them send their *next*
command, which is the actual intel we want: the argument they pass, their
cookie jar, their user-agent rotation, whether they escalate.

The simulated command outputs are deliberately boring (`www-data`, a stock
`/etc/passwd`, a Linux 5.15 `uname`) and the form reflects whatever the
scanner submits. Unknown commands return empty output — the same thing a
real shell would produce for `cd foo` or a variable assignment — rather
than a canned "command not found" that outs the trap on the first probe.

## License

MIT. See [LICENSE](./LICENSE).
