# Log format

flux writes one JSON object per line to `TRACEBIT_ENV_LOG_PATH`
(default `/var/log/honeypot/tracebit/env-canary.jsonl`). Pipe it into
your log shipper of choice; one line per event.

## Common fields

Every line includes these — they're built in `_handle()` before dispatch.

| Field | Type | Notes |
| --- | --- | --- |
| `timestamp` | string | UTC, ISO 8601, `Z` suffix. |
| `requestId` | string | UUID4 minted on each request. |
| `method` | string | `GET` / `HEAD` / `POST`. |
| `host` | string | `X-Forwarded-Host` or `Host`, lowercased, port stripped. |
| `hostAllowReason` | string | `configured-host` / `local-ip` / `localhost` / `not-allowed`. |
| `path` | string | Percent-decoded, duplicate-slash collapsed. |
| `rawPath` | string | Pre-decode path from the request line. |
| `rawTarget` | string | Full request target (path + query). |
| `query` | string | Query string, no leading `?`. |
| `clientIp` | string | First comma-split value of `X-Forwarded-For`. |
| `userAgent` | string | From `User-Agent` header. |
| `protocol` | string | From `X-Forwarded-Proto`, default `http`. |
| `headers` | object | Subset: `Host`, all `X-Forwarded-*`, `True-Client-Ip`, `X-Real-Ip`, `X-Client-Ip`, `X-Azure-Clientip`, `X-Azure-Socketip`, `X-Originating-Ip`, `X-Host`, `Cf-Connecting-Ip`, `Content-Type`, `Content-Length`. Values truncated to 512 chars. |
| `bodyBytesRead` | int | 0 unless the request read a body (webshell `POST`). |
| `bodySha256` | string | SHA256 hex of the body, or `""`. |

## Result tags

Every line has a `result` identifying what the handler did, and a
`status` (the HTTP status returned to the client). Grouped by trap.

### Router / fallback

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `not-handled` | 404 | — | Path didn't match any trap; fell through to 404. |

### `/.env` canary (existing)

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `issued` | 200 | `types: [..]` | `.env` canary issued and served. |
| `tracebit-http-error` | 502 | `tracebitStatus: int`, `error: str<=400` | Tracebit API returned a non-2xx. |
| `tracebit-error` | 502 | `error: str<=400` | URLError / TimeoutError / ValueError from Tracebit. |

### Fake `/.git/*` tree

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `fake-git` | 200 | `commitSha`, `rootTreeSha`, `secretsBlobSha`, `canaryTypes`, `fakeGitBytes`, `fakeGitDripBytes`, `fakeGitDripIntervalMs` | Object served from the synthetic repo. |
| `fake-git-miss` | 404 | `commitSha` | Path resolved to the repo but wasn't a file in it. |
| `fake-git-error` | 502 | — | Canary issuance failed. |
| `fake-git-disconnect` | 200 | `fakeGitBytesSent`, `commitSha` | Scanner hung up mid-drip. |
| `fake-git-capacity` | 503 | — | Tarpit semaphore full. |

### Tarpit + fingerprint modules

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `tarpit` | 200 | `tarpitChunkBytes`, `tarpitIntervalMs`, `tarpitSeconds`, `modules?: {<name>: {..}}` | Started streaming the tarpit. `modules` appears when any augmenting module (cookie / etag / content-length-mismatch) ran. |
| `tarpit-disconnect` | 200 | `tarpitChunksSent: int` | Scanner hung up mid-drip. |
| `tarpit-capacity` | 503 | — | Semaphore full. |
| `tarpit-module` | 302 | `module: str`, + per-module fields | A terminal module (dns-callback, redirect-chain) took the response. |

Per-module extras on `tarpit-module`:

| `module` | Extras |
| --- | --- |
| `dns-callback` | `callbackId`, `location` |
| `redirect-chain` | `chainId`, `hop` |

Augmenting-module extras inside `tarpit.modules`:

| key | Extras |
| --- | --- |
| `cookie-tracking` | `cookieId`, `cookieReturned?` |
| `etag-probe` | `etag`, `conditionalRequest?`, `ifNoneMatch?`, `ifModifiedSince?` |
| `content-length-mismatch` | `claimedBytes` |

### Webshell

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `webshell-probe` | 200 | webshell fields | Hit matching a webshell path without an extractable command. |
| `webshell-command` | 200 | webshell fields + `command`, `commandSource`, `commandKey`, `simulatedOutputBytes` | Hit with a command we extracted. |

Webshell extras (both variants):

| Field | Type | Notes |
| --- | --- | --- |
| `webshellPath` | string | |
| `commandSource` | string | `query` / `form` / `cookie` / `header` / `""`. |
| `commandKey` | string | The param / cookie / header name the command came from. |
| `command` | string | Extracted command, or `""`. |
| `simulatedOutputBytes` | int | Bytes of fake output returned. |
| `cookieNames` | list[str] | Sorted cookie names sent by the client. |
| `queryParamNames` | list[str] | Sorted query-string keys. |
| `formParamNames` | list[str] | Sorted form keys (for `application/x-www-form-urlencoded` bodies). |
| `contentType` | string | First 120 chars of `Content-Type`. |
| `bodyPreview` | string | Up to `HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT` chars; omitted if empty. |

### Canary-backed file traps

One log line per hit. All entries share the same shape:

| `result` | `status` | Extras |
| --- | --- | --- |
| `<trap-name>` | 200 | `canaryTypes: [..]`, `bytes: int` |
| `<trap-name>-error` | 502 | — (upstream canary issuance failed) |
| `<trap-name>-render-error` | 502 | `error: str<=400` (renderer raised) |

Where `<trap-name>` is one of:

| Tag | Paths | Canary type |
| --- | --- | --- |
| `aws-credentials-file` | `/.aws/credentials` | `aws` |
| `wp-config` | `/wp-config.php` (+`.bak`/`.old`/`.txt`) | `aws` |
| `sql-dump` | `/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`, `/backup/db.sql`, `/sql/backup.sql` | `aws` |
| `config-json` | `/config.json`, `/settings.json`, `/credentials.json`, `/secrets.json` | `aws` |
| `firebase-json` | `/firebase.json`, `/google-services.json`, `/serviceaccount.json`, `/service-account.json` | `aws` |
| `docker-config` | `/.docker/config.json`, `/docker/config.json` | `aws` |
| `docker-compose` | `/docker-compose.yml`, `/docker-compose.yaml`, `/compose.yml`, `/compose.yaml` | `aws` |
| `application-properties` | `/application.properties` | `aws` |
| `application-yml` | `/application.yml`, `/application.yaml` | `aws` |
| `env-production` | `/.env.production`, `/.env.prod`, `/.env.live` | `aws` |
| `phpinfo` | `/phpinfo.php`, `/info.php`, `/php.php`, `/test.php` | `aws` |
| `ssh-private-key` | `/id_rsa`, `/.ssh/id_rsa`, `/ssh/id_rsa`, `/ssh/id_rsa.key`, `/keys/id_rsa`, `/private.key`, `/deploy_key`, `/deploy.key` | `ssh` |
| `ssh-public-key` | `/id_rsa.pub`, `/.ssh/id_rsa.pub` | `ssh` |
| `authorized-keys` | `/authorized_keys`, `/.ssh/authorized_keys` | `ssh` |
| `netrc` | `/.netrc`, `/_netrc` | `gitlab-username-password` |
| `npmrc` | `/.npmrc` | `gitlab-username-password` |
| `pypirc` | `/.pypirc` | `gitlab-username-password` |
| `gitlab-api-user` | `/api/v4/user` | `gitlab-username-password` |
| `gitlab-sign-in` | `/users/sign_in` | `gitlab-cookie` |

## Caveats

- Lines are not fsync'd; a hard reboot can drop the last few entries.
- `append_log` opens the file per call without locking. POSIX `write()` is
  atomic for blocks under `PIPE_BUF` (4096 on Linux) — most flux log lines
  are well under that, but a webshell line with a large `bodyPreview` could
  theoretically tear under heavy concurrent writers. Swap in a log shipper
  if you care about this.
- No rotation is built in. Wire up logrotate or equivalent.
