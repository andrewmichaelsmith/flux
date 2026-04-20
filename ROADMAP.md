# Roadmap: more canary deployment surfaces

flux currently deploys Tracebit Community canaries on exactly two trap
paths: `/.env` (canary-in-dotenv) and `/.git/*` (canary-in-secrets.yml
inside a synthetic repo). The Tracebit Community API supports several
more canary types than we currently use, and even for the ones we do
use there are more believable places on disk for a scanner to find them.

This doc is a design register of deployment surfaces we could add. Each
entry is a fresh trap route on the same flux server, reusing the existing
`issue_credentials()` path with a different rendered payload.

## Tracebit Community API canary types (as of April 2026)

Confirmed from the Tracebit OpenAPI spec at
`https://community.tracebit.com/openapi.json`:

| `type` | Response fields | Notes |
| --- | --- | --- |
| `aws` | `awsAccessKeyId`, `awsSecretAccessKey`, `awsSessionToken`, `awsExpiration`, `awsConfirmationId` | Session tokens; STS format. |
| `ssh` | `sshIp`, `sshPrivateKey`, `sshPublicKey`, `sshExpiration`, `sshConfirmationId` | Key pair + a destination IP that triggers on connect. |
| `gitlab-cookie` | `credentials`, `hostNames`, `expiresAt`, `browserDeploymentId`, `confirmationId` | Session cookie for a decoy GitLab UI. |
| `gitlab-username-password` | `credentials`, `hostNames`, `expiresAt`, `browserDeploymentId`, `confirmationId` | Username/password for the same decoy GitLab. |

Flux today only serves `aws` and `ssh` (inside `/.env` and `/.git/*`).
`gitlab-cookie` and `gitlab-username-password` are unused.

## Implemented trap surfaces

The table below is the live set of file traps. All gated on `ALLOWED_HOSTS`
+ `TRACEBIT_API_KEY`, with per-IP TTL caching to protect quota. Toggle with
`CANARY_TRAPS_ENABLED`. Paths are case-insensitive exact matches.

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

The GitLab sign-in trap returns the cookie canary as `Set-Cookie:
_gitlab_session=<value>`; scanners that harvest cookies pick it up there.
The API-user trap embeds the gitlab-username-password canary as a
plausible `/api/v4/user` JSON response.

## Still to do

### Wait for API additions

Tracebit marketing materials mention email canaries and LLM canaries
as part of the Community Edition, but the OpenAPI spec doesn't expose
them yet. When / if they're added to `issue-credentials`:

- **email** (intentionally excluded from this repo for now).
- **llm** → embed in a `/.cursor/mcp.json`, `/.continue/config.json`,
  or a fake `/api/chat/completions` endpoint.

## Common design rules for any new trap

Whatever we ship next should:

1. **Require `TRACEBIT_API_KEY`**; 404 when unset.
2. **Gate on `ALLOWED_HOSTS` being non-empty** (trap sensors only). We
   intentionally do **not** gate on per-request Host matching, because
   scanners routinely spoof Host and we still want to catch them. See
   `test_dispatch_trap_serves_even_with_spoofed_host`.
3. **Mint one canary per cache-miss**, not per request — reuse the
   same per-IP TTL cache we already have for `/.git/*`.
4. **Log a distinct `result` tag** (`aws-credentials-file`, `gitlab-login-page`,
   etc.) so the downstream analysis can tell which trap fired.
5. **Stream behind `TARPIT_SEMAPHORE`** when the response is slow-dripped,
   to protect against a scanner opening many connections.

## Non-goals

- Writing a stateful session system for the gitlab-* canaries that
  actually logs the scanner in. Let Tracebit's own browser deployment
  handle the follow-up; flux just issues the credential and walks away.
- Embedding canaries into a file the trap host doesn't plausibly own
  (e.g. a canary in `/var/runtime/index.mjs` on a trap that doesn't
  present as a Node app).
