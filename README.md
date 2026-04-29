# flux

[![tests](https://github.com/andrewmichaelsmith/flux/actions/workflows/tests.yml/badge.svg)](https://github.com/andrewmichaelsmith/flux/actions/workflows/tests.yml)

An evolving HTTP honeypot, actively maintained by an LLM working off
observations from a live honeypot sensor network. Fresh scanner
behaviour in the corpus drives new traps; existing traps get tuned or
retired as the logs show what's eliciting follow-up and what's being
ignored. The table below has a last-updated date per family (initial
release or latest substantive change, whichever's more recent).

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

| Trap | What it does | Updated | Key |
| --- | --- | --- | --- |
| Fake `/.env` canary issuer | Mints a per-request Tracebit Community canary and returns it as a `.env`-style payload | 2026-04-22 | yes |
| Fake `/.git/` repository | Serves a loose-object git tree whose `config/secrets.yml` embeds a canary AND whose `.git/config` `[remote "origin"] url` embeds the same canary as HTTP Basic userinfo — so scrapers that only fetch `.git/config` (without cloning) still walk away with a live canary. Matches `<prefix>/.git/*` (apps deployed at subpaths) and is case-insensitive on the `.git` segment; ships a minimal-valid `/.git/index` (DIRC header) so `git-dumper`-style tools don't bail on a missing index. Per-IP cached so fan-out sees a consistent tree | 2026-04-23 | yes |
| Canary file traps | Plausible file-format responses for `/wp-config.php`, `/backup.sql`, `/id_rsa`, `/.aws/credentials`, `/api/v4/user`, `/users/sign_in`, `/actuator/env`, `/.vscode/sftp.json`, GCP service-account JSON variants (`/.config/gcloud/application_default_credentials.json`, `/firebase-adminsdk.json`, …), CI/CD config files, … — full table [below](#canary-file-trap-table) | 2026-04-29 | yes |
| AI-credential-file canaries | AI editor / coding-assistant configs (`/.claude/settings.json`, `/.cline/{settings,mcp_settings}.json`, `/.continue/config.json`, `/.cursor/mcp.json`, `/.aider.conf.yml`, `/.sourcegraph/cody.json`, `/.config/open-interpreter/config.yaml`, …) plus AI infrastructure / proxy configs (`/litellm_config.yaml`, `/langsmith.env`, `/.huggingface/token`, `/.streamlit/secrets.toml`, `/baseten.yaml`, generic MCP configs, `/.bito/`, `/.codeium/`, `/.roost/`, `/cohere_config.json`, …) — listed in the same table; broken out in the footnote because Tracebit has no LLM canary type yet | 2026-04-28 | yes |
| Fake webshell | Plausible File Manager on known `*.php` shell probe paths plus shell-jacking regex families (`/.well-known/<name>.php`, `/.trash<N>/*`, `/.tmb/`, `/.dj/`, `/.alf/`, …); simulates `id` / `whoami` / `uname -a` / `cat /etc/passwd` on follow-up commands — [docs](./docs/fake-webshell.md) | 2026-04-22 | no |
| Modular tarpit + fingerprinting | Slow-drip response plus six fingerprinting modules (cookie, ETag, redirect chain, variable drip, Content-Length mismatch, DNS callback); fires on `.env` variants and on configurable first-contact paths (`/`, `/index.html`, `/robots.txt`, …) | 2026-04-20 | no |
| Fake LLM-API endpoint | Ollama / OpenAI / Anthropic-proxy JSON on `/v1/models`, `/v1/chat/completions`, `/anthropic/v1/messages`, `/api/chat`, … ; logs model + auth header + prompt prefix — [docs](./docs/fake-llm-api.md) | 2026-04-20 | no |
| Fake SonicWall SSL VPN | SonicOS 7 JSON responses on the three paths in the CVE-2024-53704 auth-bypass chain; logs submitted username, body sha + preview, and replayed session cookies — [docs](./docs/fake-sonicwall.md) | 2026-04-21 | no |
| Fake Cisco WebVPN endpoint | Cisco SSL VPN landing page + launcher assets on `/+CSCOE+/...` and `/+CSCOL+/...`; also recognizes AnyConnect `config-auth` XML POSTs to `/` and logs submitted usernames without storing passwords — [docs](./docs/fake-cisco-webvpn.md) | 2026-04-26 | no |
| Fake Ivanti Connect Secure / Pulse Secure VPN | Ivanti SSL VPN welcome + login POST + HostChecker installer assets on `/dana-na/...` and `/dana-cached/hc/...`; mints a per-request `DSID` cookie, logs username + has-password, and flips `ivantiHasCmdInjection` on shell-meta payloads aimed at `/dana-ws/namedusers` (CVE-2023-46805 / CVE-2024-21887 / CVE-2025-22457 chain bait) — [docs](./docs/fake-ivanti-vpn.md) | 2026-04-27 | no |
| Fake IBM Aspera Faspex portal | Aspera Faspex login/logout/relay surfaces on `/aspera/faspex/...`; emits plausible HTML/JSON, logs follow-on payload previews on logout/relay endpoints, and keeps scanner chains alive past initial fingerprinting (CVE-2022-47986 bait) — [docs](./docs/fake-aspera-faspex.md) | 2026-04-27 | no |
| Fake Hikvision IP camera | Hikvision ISAPI surface (`/SDK/webLanguage`, `/ISAPI/Security/userCheck`, `/ISAPI/System/deviceInfo`); returns plausible XML with `Server: App-webs/` and a CVE-2021-36260-window firmware banner, flips `hikvisionHasCmdInjection` on shell-meta indicators in body/query so language-parameter command-injection payloads are easy to triage — [docs](./docs/fake-hikvision.md) | 2026-04-29 | no |
| Fake GeoServer admin / OGC | GeoServer 2.x admin shell + About page + OGC `*_Capabilities` on `/geoserver/...`; flags OGNL/expression-language indicators in query string + body so CVE-2024-36401 payloads are easy to triage — [docs](./docs/fake-geoserver.md) | 2026-04-25 | no |
| Fake ColdFusion admin / component browser | ColdFusion public `.cfm` anchors plus `/CFIDE/componentutils/`, Administrator, and AdminAPI surfaces; logs method, auth/session hints, and exploit payload indicators — [docs](./docs/fake-coldfusion.md) | 2026-04-25 | no |
| Cmd-injection / printenv responder | `/admin/config?cmd=…` and `/admin/config.php?cmd=…` (admin-shell exploit shape) plus `/printenv`, `/cgi-bin/printenv`, `/cgi-bin/test-cgi`; classifies the cmd value, returns a plausible `cat /etc/passwd` / `id` / `uname` body, and mints a per-request Tracebit AWS canary when the cmd asks for `~/.aws/credentials` or env vars — [docs](./docs/cmd-injection.md) | 2026-04-26 | yes |
| PHP/body-RCE responders | Body-driven exploit responders for PHPUnit `eval-stdin.php`, PHP-CGI `auto_prepend_file=php://input`, and Apache CGI path-traversal `/bin/sh`; logs request-body payloads and decoded base64 command hints — [docs](./docs/cmd-injection.md) | 2026-04-26 | no |

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

### Design principle: every credential is per-hit unique

A trap renderer that ships a **fixed literal** credential (hardcoded
DB password, hardcoded API key) provides no detection value — a
replay triggers nothing — and ships the same string across every
sensor in the fleet, which becomes a cross-sensor fingerprint. Every
secret-shaped field in a rendered response must therefore be per-hit
unique. We back it with Tracebit when that adds detection value
(replay against AWS STS, the Tracebit-hosted gitlab URL, the Tracebit
sshIp); when there's no matching canary type we fall back to a
per-hit random synthetic. Concretely, every secret-shaped field is
either:

1. **A per-request Tracebit canary** — `_aws(r)` or
   `_gitlab_creds(r, ...)`. Fires when replayed against the matching
   target (AWS STS globally, the Tracebit-hosted gitlab URL for u/p
   and cookie, the Tracebit sshIp for ssh).
2. **A per-hit random synthetic** — `_fake_db_password()` or similar.
   Does *not* fire (no Tracebit path exists for the cred type, e.g.
   MySQL/Postgres), but is unique per rendering so the rendered body
   can't be fingerprinted across the fleet.

Hardcoded literals in the "plausible filler" around the canary are
fine when the value isn't credential-shaped — usernames like
`wp_prod`, host names like `db.internal`, bucket names, comments.
What must never be fixed is anything that looks like a password,
token, or key.

When the canary type doesn't exist in Tracebit Community yet (LLM
API keys, Google service accounts), the trap must either (a) dress
an AWS canary in plausible shape so a field-name-keyed harvester
still exfils a live canary value (see the AI-credential traps below)
or (b) emit a per-hit random synthetic so the response isn't
fingerprintable — never a fixed literal.

### Trap table

All gated on `TRACEBIT_API_KEY`, with per-IP TTL caching to protect quota.
Toggle the whole category with `CANARY_TRAPS_ENABLED`. Paths are
case-insensitive exact matches.

| Trap | Paths | Canary type | Log tag |
| --- | --- | --- | --- |
| AWS credentials file (INI) | `/.aws/credentials` | `aws` | `aws-credentials-file` |
| AWS SDK config (INI) | `/.aws/config` | `aws` | `aws-config-file` |
| Postgres pgpass | `/.pgpass` | `gitlab-username-password` | `pgpass` |
| WordPress config | `/wp-config.php` plus editor-leftover suffix variants (`.bak`, `.save`, `.swp`, `.swo`, `.old`, `.orig`, `.txt`, `~`, `::$DATA`) and short/relocation forms (`/wp-config.bak`, `/wp-config.old`, `/wp-config.txt`, `/wp-config-backup.php`, `/backup/wp-config.php`); also matches the observed double-encoded `.bak` form | `aws` | `wp-config` |
| SQL dump | `/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`, `/backup/db.sql`, `/sql/backup.sql` | `aws` | `sql-dump` |
| Generic JSON config | `/config.json`, `/settings.json`, `/credentials.json`, `/secrets.json` | `aws` | `config-json` |
| SFTP deploy config | `/.vscode/sftp.json`, `/sftp-config.json`, `/sftp.json`, `/.ftpconfig` | `gitlab-username-password` | `sftp-config` |
| Firebase / GCP SA | `/firebase.json`, `/google-services.json`, `/serviceaccount.json`, `/service-account.json`, `/firebase-adminsdk.json`, `/gcp-service-account.json`, `/.config/gcloud/application_default_credentials.json` | `aws` | `firebase-json` |
| Docker client | `/.docker/config.json`, `/docker/config.json` | `aws` | `docker-config` |
| Docker Compose | `/docker-compose.yml`, `/docker-compose.yaml`, `/compose.yml`, `/compose.yaml`, plus `.prod`, `.production`, `.dev`, `.staging`, `.override` variants (both `.yml` and `.yaml`) | `aws` | `docker-compose` |
| GitHub Actions workflows | `/.github/workflows/{deploy,main,ci,build,test,docker,release,cd}.yml` plus `.yaml` variants | `aws` | `github-actions-workflow` |
| GitLab CI config | `/.gitlab-ci.yml`, `/.gitlab-ci.yaml`, `/.gitlab/.gitlab-ci.yml` | `aws` | `gitlab-ci` |
| Jenkins Pipeline | `/Jenkinsfile`, `/Jenkinsfile.bak` | `aws` | `jenkinsfile` |
| Bitbucket Pipelines | `/bitbucket-pipelines.yml`, `/bitbucket-pipelines.yaml` | `aws` | `bitbucket-pipelines` |
| Generic CI deploy config | `/appveyor.yml`, `/.circleci/config.yml`, `/azure-pipelines.yml`, `/deployment.yml`, `/deploy.yml`, `/drone.yml`, `/.drone.yml` plus `.yaml` variants where applicable | `aws` | `generic-ci-config` |
| Spring properties | `/application.properties` | `aws` | `application-properties` |
| Spring YAML | `/application.yml`, `/application.yaml` | `aws` | `application-yml` |
| Spring Boot Actuator `/env` | `/actuator/env`, `/actuator/env.json`, `/env`, `/manage/env`, `/management/env`, `/api/actuator/env` | `aws` | `actuator-env` |
| Production .env | `/.env.production`, `/.env.prod`, `/.env.live` | `aws` | `env-production` |
| phpinfo() | `/phpinfo.php`, `/info.php`, `/php.php`, `/test.php` | `aws` | `phpinfo` |
| SSH private key | `/id_rsa`, `/.ssh/id_rsa`, `/ssh/id_rsa`, `/ssh/id_rsa.key`, `/keys/id_rsa`, `/private.key`, `/deploy_key`, `/deploy.key`, `/.ssh/id_ed25519`, `/.ssh/id_dsa`, `/.ssh/id_ecdsa`, `/id_ed25519`, `/id_dsa`, `/id_ecdsa`, `/root/.ssh/id_rsa`, `/home/.ssh/id_rsa` | `ssh` | `ssh-private-key` |
| SSH public key | `/id_rsa.pub`, `/.ssh/id_rsa.pub` | `ssh` | `ssh-public-key` |
| SSH client config | `/.ssh/config` | `ssh` | `ssh-config` |
| known_hosts | `/.ssh/known_hosts`, `/known_hosts` | `ssh` | `known-hosts` |
| authorized_keys | `/authorized_keys`, `/.ssh/authorized_keys`, `/.ssh/authorized_keys2`, `/static/.ssh/authorized_keys`, `/downloads/.ssh/authorized_keys`, `/blog/.ssh/authorized_keys` | `ssh` | `authorized-keys` |
| .netrc | `/.netrc`, `/_netrc` | `gitlab-username-password` | `netrc` |
| git credential store | `/.git-credentials`; fake-git also serves `/.git/credentials` | `gitlab-username-password` | `git-credentials` / `fake-git` |
| .npmrc | `/.npmrc` | `gitlab-username-password` | `npmrc` |
| .pypirc | `/.pypirc` | `gitlab-username-password` | `pypirc` |
| GitLab API user | `/api/v4/user` | `gitlab-username-password` | `gitlab-api-user` |
| GitLab sign-in | `/users/sign_in` | `gitlab-cookie` | `gitlab-sign-in` |
| OpenAI config file | `/.openai/config.json` | `aws` (†) | `openai-config` |
| Anthropic config file | `/.anthropic/config.json` | `aws` (†) | `anthropic-config` |
| Cursor MCP config | `/.cursor/mcp.json` | `aws` (†) | `cursor-mcp` |
| Claude Code credentials | `/.claude/.credentials.json` | `aws` (†) | `claude-credentials` |
| Claude Desktop settings | `/.claude/settings.json` | `aws` (†) | `claude-settings` |
| Cline settings | `/.cline/settings.json` | `aws` (†) | `cline-settings` |
| Generic MCP server configs | `/.cline/mcp_settings.json`, `/mcp_settings.json`, `/mcp.json`, `/.mcp/mcp.json` | `aws` (†) | `mcp-config` |
| Continue.dev config | `/.continue/config.json` | `aws` (†) | `continue-config` |
| Sourcegraph Cody config | `/.sourcegraph/cody.json` | `aws` (†) | `cody-config` |
| Aider config | `/.aider.conf.yml` | `aws` (†) | `aider-conf` |
| Open-Interpreter config | `/.config/open-interpreter/config.yaml` | `aws` (†) | `open-interpreter-config` |
| LiteLLM proxy config | `/litellm_config.yaml`, `/litellm/config.yaml`, `/proxy_config.yaml` | `aws` (†) | `litellm-config` |
| LangSmith env | `/langsmith.env` | `aws` (†) | `langsmith-env` |
| HuggingFace token | `/.huggingface/token`, `/.cache/huggingface/token` | `aws` (†) | `huggingface-token` |
| Streamlit secrets | `/.streamlit/secrets.toml` | `aws` (†) | `streamlit-secrets` |
| OpenAI flat config | `/openai.json` | `aws` (†) | `openai-config-flat` |
| Anthropic flat config | `/anthropic.json` | `aws` (†) | `anthropic-config-flat` |
| Generic AI provider config | `/cohere_config.json`, `/tabnine_config.json`, `/.bito/config.json`, `/.codeium/config.json`, `/.roost/config.json`, `/pinecone_config.json`, `/.lobechat/config.json`, `/chatgpt-next-web.json` | `aws` (†) | `ai-provider-config` |
| Baseten model deploy config | `/baseten.yaml` | `aws` (†) | `baseten-config` |

`/users/sign_in` returns the cookie canary as `Set-Cookie:
_gitlab_session=<value>`. `/api/v4/user` embeds the username/password
canary as a plausible GitLab API user response.

The `ssh` canary fires only when the stolen key is replayed against
Tracebit's ``sshIp`` (returned alongside the keypair). That's why
``ssh-config`` and ``known-hosts`` exist — without a target-host hint,
a harvested ``/id_rsa`` points at nothing, so an attacker runs
``ssh -i id_rsa <arbitrary-host>`` and the canary never fires. The
three traps together (``id_rsa`` → ``config`` → ``known_hosts``) give
a scanner walking an exposed ``.ssh/`` the full key + `Host bastion
HostName <sshIp>` mapping, which resolves to an ``ssh bastion`` replay
the canary can catch.

† **The AI-credential-file traps probably don't make sense yet.**
Tracebit Community doesn't expose an OpenAI / Anthropic / LLM canary
type, so these traps dress an `aws` canary in OpenAI / Anthropic /
Cursor / Claude-shaped JSON. A scanner that filters by key-format prefix
(`sk-...`, `sk-ant-...`) will correctly decide the key is fake and
drop it; a scanner that harvests by field name (`api_key`, `auth_token`,
`accessToken`, `GITHUB_PERSONAL_ACCESS_TOKEN`) will still serialize the
value and ship it, and *that* side-channel trips the AWS canary if it's
ever used as AWS credentials. Shipped anyway because the probe itself
is what we want to log. Swap the renderers to real LLM canaries when
Tracebit ships them.

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
- [Fake Cisco WebVPN endpoint](./docs/fake-cisco-webvpn.md)
- [Fake Ivanti Connect Secure / Pulse Secure VPN endpoint](./docs/fake-ivanti-vpn.md)
- [Fake IBM Aspera Faspex trap](./docs/fake-aspera-faspex.md)
- [Fake Hikvision IP camera trap](./docs/fake-hikvision.md)
- [Fake GeoServer admin / OGC](./docs/fake-geoserver.md)
- [Fake ColdFusion admin / component browser](./docs/fake-coldfusion.md)
- [Cmd-injection / printenv responder](./docs/cmd-injection.md)
- [CI/CD config canaries](./docs/ci-cd-config.md)
- [Fake webshell](./docs/fake-webshell.md)

The other traps (`.env`, `/.git/`, canary file traps, tarpit +
fingerprinting) are documented in [`CONFIG.md`](./CONFIG.md) and the
canary table above.

## License

MIT. See [LICENSE](./LICENSE).
