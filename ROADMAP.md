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

## Proposed new trap surfaces

Each trap below is cheap (one function + a dispatch block, optionally a
small path pattern). Priority ordering roughly reflects "ratio of
observed scanner traffic to implementation cost."

### P0 — cheap, high-traffic

These paths are hit constantly across our sensor fleet. Standing up a
trap on each is a handful of lines.

1. **`/.aws/credentials`** (aws) — emit an `~/.aws/credentials` INI
   payload. Scanners who grepped `/.env` almost always try `.aws/`
   next. The file has a very stable format (`[default]`, `aws_access_key_id`,
   `aws_secret_access_key`, `aws_session_token`), so this is a one-liner
   beyond what `format_env_payload()` already does.

2. **`/wp-config.php`** (aws) — mock WordPress config in PHP with
   `define('AWS_ACCESS_KEY_ID', '...');` lines. The file name is among
   the top-20 paths in our scanner logs.

3. **`/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`** (aws) — a
   short SQL dump that embeds AWS creds in a comment header or an
   `INSERT INTO settings` row. Scanners mass-exfil these.

4. **`/config.json`, `/settings.json`, `/credentials.json`** (aws) — a
   minimal JSON object `{"aws": {"access_key_id": "...", ...}}`.

### P1 — opens up a canary type we don't yet use

5. **`/users/sign_in` + `/api/v4/user`** (gitlab-username-password /
   gitlab-cookie) — serve a small HTML page that looks like a GitLab
   sign-in and, on `POST`, responds with 302 + `Set-Cookie: _gitlab_session=<canary>`.
   Or: serve `/api/v4/user` returning JSON `{"username": "...", "email": "..."}`
   that leaks a canary username paired with a weak password in a
   sibling `/robots.txt` hint. Requires the Tracebit browser deployment
   workflow — read the `browserDeploymentId` field carefully.

6. **SSH key files** (ssh) — `/id_rsa`, `/.ssh/id_rsa`, `/ssh/id_rsa.key`,
   `/keys/id_rsa`, `/private.key`. Serve the `sshPrivateKey` body (PEM).
   Also serve `/authorized_keys` with the `sshPublicKey` attached to a
   fake user. Scanners who find a real `id_rsa` on an exposed webroot
   try to `ssh -i` with it, and our `sshIp` logs that attempt.

### P2 — plausible but lower-priority

7. **`/phpinfo.php`, `/info.php`** (aws) — a synthetic `phpinfo()` HTML
   page with `AWS_ACCESS_KEY_ID` and friends showing in the `$_ENV`
   section.

8. **`/.docker/config.json`, `/docker-compose.yml`** (aws) — container
   config referencing ECR/S3 with embedded creds.

9. **`/application.properties`, `/application.yml`, `/.env.production`**
   (aws) — Spring / framework-flavored payloads.

10. **`/.npmrc`, `/.pypirc`, `/.netrc`** (gitlab-username-password or
    aws) — package-manager creds; `/.netrc` is especially good because
    it encodes `machine login password` on one line.

11. **`/firebase.json`, `/google-services.json`, `/serviceAccount.json`**
    (aws — reuse the format with different keys; Tracebit Community
    doesn't ship a GCP canary type yet). Lower value because the creds
    "look" AWS rather than GCP, which might tip off a careful operator.

### P3 — wait for API additions

Tracebit marketing materials mention email canaries and LLM canaries
as part of the Community Edition, but the OpenAPI spec doesn't expose
them yet. When / if they're added to `issue-credentials`:

- **email** → embed a canary address in a `/.htpasswd`, a fake `/admin`
  user listing, or a mock `/users/profile` page.
- **llm** → embed in a `/.cursor/mcp.json`, `/.continue/config.json`,
  or a fake `/api/chat/completions` endpoint.

## Common design rules for any new trap

Whatever we ship next should:

1. **Require `TRACEBIT_API_KEY`** like `/.env` and `/.git/*` do; 404 when
   unset.
2. **Respect `host_allowed`** (trap sensors only, never control sensors).
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
