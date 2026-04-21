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
of the master switch.

| Trap | What it does | Released | Key |
| --- | --- | --- | --- |
| Fake `/.env` canary issuer | Mints a per-request Tracebit Community canary and returns it as a `.env`-style payload | 2026-04-20 | yes |
| Fake `/.git/` repository | Serves a loose-object git tree whose `config/secrets.yml` embeds a canary; per-IP cached so `git-dumper`-style fan-out sees a consistent tree | 2026-04-20 | yes |
| Canary file traps (19 paths) | Plausible file-format responses for `/wp-config.php`, `/backup.sql`, `/id_rsa`, `/.aws/credentials`, `/api/v4/user`, `/users/sign_in`, … — full table [below](#canary-file-trap-table) | 2026-04-20 | yes |
| AI-credential-file canaries | `/.openai/config.json`, `/.anthropic/config.json`, `/.cursor/mcp.json` — listed in the same table; broken out in the footnote because Tracebit has no LLM canary type yet | 2026-04-20 | yes |
| Fake webshell | Plausible File Manager on known `*.php` shell probe paths; simulates `id` / `whoami` / `uname -a` / `cat /etc/passwd` on follow-up commands | 2026-04-20 | no |
| Modular tarpit + fingerprinting | Slow-drip response plus six fingerprinting modules (cookie, ETag, redirect chain, variable drip, Content-Length mismatch, DNS callback); fires on `.env` variants and on configurable first-contact paths (`/`, `/index.html`, `/robots.txt`, …) | 2026-04-20 | no |
| Fake LLM-API endpoint | Ollama / OpenAI / Anthropic-proxy JSON on `/v1/models`, `/v1/chat/completions`, `/anthropic/v1/messages`, `/api/chat`, … ; logs model + auth header + prompt prefix — see [below](#fake-llm-api-endpoint) | 2026-04-20 | no |
| Fake SonicWall SSL VPN | SonicOS 7 JSON responses on the three paths in the CVE-2024-53704 auth-bypass chain; logs submitted username, body sha + preview, and replayed session cookies — see [below](#fake-sonicwall-ssl-vpn-endpoint) | 2026-04-21 | no |

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

Multiple distinct scanner fleets started probing exposed AI-inference
endpoints on our sensors in April 2026 — Ollama-native paths
(`/v1/models` + `/api/version` + `/api/tags`), OpenAI-compatible paths
(`/v1/chat/completions`), and corporate AI-proxy paths
(`/anthropic/v1/models`). The trap shipped the day after the
behaviour was confirmed across more than one source, spread across
several ASNs with non-overlapping HTTP-client fingerprints.

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

## Fake SonicWall SSL VPN endpoint

Scanners started hammering SonicWall SSL VPN auth-bypass paths in mid-April
2026. The trap matches three paths (exact, case-insensitive; configurable
via `HONEYPOT_SONICWALL_PATHS_CSV`):

| Path | Method | Response |
| --- | --- | --- |
| `/api/sonicos/is-sslvpn-enabled` | GET | `{"is_ssl_vpn_enabled": true, "status": {...}}` |
| `/api/sonicos/auth` | POST | SonicOS auth-success envelope with a per-request `session_id` and `tfa_required: true` |
| `/api/sonicos/tfa` | POST | SonicOS TFA-accepted envelope (same session_id shape, `tfa_required: false`) |

On each POST the trap extracts `user` / `username` / `login` from the JSON
or form body and logs it along with the full body sha + a preview. The
`Cookie` header is sniffed for `swap_session=` / `SonicOS-Session=` —
presence of either is surfaced via `sonicwallHasAuth: true`, which is a
stronger-than-baseline signal that the scanner already has a harvested
session token.

### Why this exists

Two overlapping behaviour patterns appeared on our sensors in
mid-April 2026:

- A dedicated SonicWall-precondition fleet hitting
  `/api/sonicos/is-sslvpn-enabled` on its own — the CVE-2024-53704
  precondition check, stopping at the first 404.
- A broader enterprise-appliance probe that added
  `/api/sonicos/tfa` + `/api/sonicos/auth` to its dictionary and
  runs the full three-step sequence
  (`is-sslvpn-enabled` → `auth` → `tfa`) on every target.

These paths are SonicWall-specific — no legitimate client hits them.
The intel a bare 404 yields is zero; a plausible 200 gets the scanner
to send its next payload, which is the actual exploit try. That
payload is what `bodyPreview` + `bodySha256` capture on each hit,
and what future analysis of CVE-2024-53704 variants will read from
the log.

## Why a fake webshell on a sensor that never had a real shell?

Because post-compromise scanners walk a list of PHP shell paths
looking for "is my planted shell still here". They don't care whether
your site ever ran WordPress. A plausible response makes them send
their *next* command, which is the actual intel we want: the argument
they pass, their cookie jar, their user-agent rotation, whether they
escalate.

The simulated command outputs are deliberately boring (`www-data`, a stock
`/etc/passwd`, a Linux 5.15 `uname`) and the form reflects whatever the
scanner submits. Unknown commands return empty output — the same thing a
real shell would produce for `cd foo` or a variable assignment — rather
than a canned "command not found" that outs the trap on the first probe.

## License

MIT. See [LICENSE](./LICENSE).
