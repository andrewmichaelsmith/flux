# flux

An evolving HTTP honeypot, actively maintained by an LLM working off
observations from a live honeypot sensor network. Fresh scanner
behaviour in the corpus drives new traps; existing traps get tuned or
retired as the logs show what's eliciting follow-up and what's being
ignored. New trap families land in days, not quarters — the table
below has a release date per family, and it's usually recent.

Small async Python behind nginx. Python 3.11+; one runtime dep —
[aiohttp](https://docs.aiohttp.org/). Async so the tarpit and
fake-git drip paths can hold thousands of concurrent slow-drip
connections at ~8 KB each instead of one OS thread each.

> **Experimental — no guarantees about safety or value.** Every line
> was written by an LLM from natural-language prompts, smoke-tested
> against a live sensor, and continuously reshaped by the same loop.
> It has not been audited line-by-line by a human. The author makes
> no claim that flux is safe to run, produces useful intel, or won't
> do something surprising under load. Before deploying anywhere that
> matters, read [`flux/server.py`](./flux/server.py) end-to-end, run
> the test suite, and think hard about what
> `HONEYPOT_WEBSHELL_PATHS_CSV` or `FAKE_GIT_*` hitting a real webroot
> would do. No warranties.

## Traps

Each family is independently toggleable via env var; all default to
on (see [`CONFIG.md`](./CONFIG.md)). Keyless deployments still 404
the canary-backed rows — dispatch requires `TRACEBIT_API_KEY` on top
of the master switch. We use [Tracebit Community](https://community.tracebit.com)
for the canaries: free tier, sign up and drop the key in the env var.

| Trap | What it does | Released | Key |
| --- | --- | --- | --- |
| Fake `/.env` canary issuer | Mints a per-request Tracebit Community canary and returns it as a `.env`-style payload | 2026-04-20 | yes |
| Fake `/.git/` repository | Serves a loose-object git tree whose `config/secrets.yml` embeds a canary; per-IP cached so `git-dumper`-style fan-out sees a consistent tree | 2026-04-20 | yes |
| Canary file traps (19 paths) | Plausible file-format responses for `/wp-config.php`, `/backup.sql`, `/id_rsa`, `/.aws/credentials`, `/api/v4/user`, `/users/sign_in`, … — full table [below](#canary-file-trap-table) | 2026-04-20 | yes |
| AI-credential-file canaries | `/.openai/config.json`, `/.anthropic/config.json`, `/.cursor/mcp.json` — listed in the same table; broken out in the footnote because Tracebit has no LLM canary type yet | 2026-04-20 | yes |
| Fake webshell | Plausible File Manager on known `*.php` shell probe paths; simulates `id` / `whoami` / `uname -a` / `cat /etc/passwd` on follow-up commands — [docs](./docs/fake-webshell.md) | 2026-04-20 | no |
| Modular tarpit + fingerprinting | Slow-drip response plus six fingerprinting modules (cookie, ETag, redirect chain, variable drip, Content-Length mismatch, DNS callback); fires on `.env` variants and on configurable first-contact paths (`/`, `/index.html`, `/robots.txt`, …) | 2026-04-20 | no |
| Fake LLM-API endpoint | Ollama / OpenAI / Anthropic-proxy JSON on `/v1/models`, `/v1/chat/completions`, `/anthropic/v1/messages`, `/api/chat`, … ; logs model + auth header + prompt prefix — [docs](./docs/fake-llm-api.md) | 2026-04-20 | no |
| Fake SonicWall SSL VPN | SonicOS 7 JSON responses on the three paths in the CVE-2024-53704 auth-bypass chain; logs submitted username, body sha + preview, and replayed session cookies — [docs](./docs/fake-sonicwall.md) | 2026-04-21 | no |

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
| OpenAI config file | `/.openai/config.json` | `aws` (†) | `openai-config` |
| Anthropic config file | `/.anthropic/config.json` | `aws` (†) | `anthropic-config` |
| Cursor MCP config | `/.cursor/mcp.json` | `aws` (†) | `cursor-mcp` |

`/users/sign_in` returns the cookie canary as `Set-Cookie:
_gitlab_session=<value>`. `/api/v4/user` embeds the username/password
canary as a plausible GitLab API user response.

† **The three AI-credential-file traps probably don't make sense yet.**
Tracebit Community doesn't expose an OpenAI / Anthropic / LLM canary
type, so these traps dress an `aws` canary in OpenAI / Anthropic /
Cursor-shaped JSON. A scanner that filters by key-format prefix
(`sk-...`, `sk-ant-...`) will correctly decide the key is fake and
drop it; a scanner that harvests by field name (`api_key`, `auth_token`,
`GITHUB_PERSONAL_ACCESS_TOKEN`) will still serialize the value and ship
it, and *that* side-channel trips the AWS canary if it's ever used as
AWS credentials. Shipped anyway because the probe itself is what we
want to log. Swap the renderers to real LLM canaries when Tracebit
ships them.

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

## Per-trap docs

Response shape, parsed fields, and rationale for the novel traps live
under [`docs/`](./docs/):

- [Fake LLM-API endpoint](./docs/fake-llm-api.md)
- [Fake SonicWall SSL VPN endpoint](./docs/fake-sonicwall.md)
- [Fake webshell](./docs/fake-webshell.md)

The other traps (`.env`, `/.git/`, canary file traps, tarpit +
fingerprinting) are documented in [`CONFIG.md`](./CONFIG.md) and the
canary table above.

## License

MIT. See [LICENSE](./LICENSE).
