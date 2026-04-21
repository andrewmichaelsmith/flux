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
| `host` | string | `X-Forwarded-Host` or `Host`, lowercased, port stripped. Logged as-is; flux never gates on it. |
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

### Fake LLM-API endpoint

One log line per hit. `result` identifies which family was served.

| `result` | `status` | Meaning |
| --- | --- | --- |
| `llm-endpoint-models-list` | 200 | `GET /v1/models` (OpenAI-compatible list) |
| `llm-endpoint-anthropic-models-list` | 200 | `GET /anthropic/v1/models` (the `scanner/1.0` target) |
| `llm-endpoint-ollama-tags` | 200 | `GET /api/tags` |
| `llm-endpoint-ollama-version` | 200 | `GET /api/version` |
| `llm-endpoint-ollama-ps` | 200 | `GET /api/ps` |
| `llm-endpoint-ollama-show` | 200 | `POST /api/show` |
| `llm-endpoint-ollama-chat` | 200 | `POST /api/chat` |
| `llm-endpoint-ollama-generate` | 200 | `POST /api/generate` |
| `llm-endpoint-openai-chat` | 200 | `POST /v1/chat/completions` |
| `llm-endpoint-openai-completion` | 200 | `POST /v1/completions` |
| `llm-endpoint-openai-embedding` | 200 | `POST /v1/embeddings` |
| `llm-endpoint-anthropic-message` | 200 | `POST /v1/messages` or `POST /anthropic/v1/messages` |
| `llm-endpoint-miss` | 404 | Matched the path set but no renderer (shouldn't occur; defensive) |

Extras on every `llm-endpoint-*` line:

| Field | Type | Notes |
| --- | --- | --- |
| `llmPath` | string | The path that matched. |
| `llmAction` | string | One of `models-list`, `version`, `running-models`, `show-model`, `chat`, `completion`, `embedding`. Filled from the JSON body when present, otherwise inferred from the path. |
| `llmModel` | string | `model` field pulled from a JSON body; `""` on GETs or malformed bodies. Truncated to 120 chars. |
| `llmHasAuth` | bool | `true` if `Authorization` or `x-api-key` header was present — the strongest signal that the scanner already has a harvested key. |
| `llmAuthScheme` | string | Lowercased first token of `Authorization` (`bearer`, `basic`, …); `""` otherwise. |
| `llmMethod` | string | Request method (`GET` / `POST` / `HEAD`). |
| `bytes` | int | Size of the JSON body returned. |
| `llmPromptPreview` | string | Prefix of the extracted prompt, truncated to `HONEYPOT_LLM_BODY_DECODE_LIMIT`. Omitted if empty. |

### Fake SonicWall SSL VPN

One log line per hit.

| `result` | `status` | Meaning |
| --- | --- | --- |
| `sonicwall-is-sslvpn-enabled` | 200 | `GET /api/sonicos/is-sslvpn-enabled` (CVE-2024-53704 step 1) |
| `sonicwall-auth` | 200 | `POST /api/sonicos/auth` (CVE-2024-53704 step 2) |
| `sonicwall-tfa` | 200 | `POST /api/sonicos/tfa` (CVE-2024-53704 step 3) |
| `sonicwall-miss` | 404 | Matched the path set but no renderer (shouldn't occur; defensive) |

Extras on every `sonicwall-*` line:

| Field | Type | Notes |
| --- | --- | --- |
| `sonicwallPath` | string | The path that matched. |
| `sonicwallMethod` | string | `GET` / `POST` / `HEAD`. |
| `sonicwallUsername` | string | `user` / `username` / `login` pulled from a JSON or form body; `""` on GETs or missing field. Truncated to 120 chars. |
| `sonicwallHasAuth` | bool | `true` if `Authorization` header OR a `swap_session=` / `sonicos-session=` cookie was present — stronger signal that the scanner is replaying a harvested session. |
| `sonicwallSessionId` | string | Per-request hex UUID minted for the fake response. Lets you correlate a scanner's follow-on replays back to the exact response they got from us. |
| `contentType` | string | First 120 chars of `Content-Type`. |
| `bytes` | int | Size of the JSON body returned. |
| `bodyPreview` | string | Up to `HONEYPOT_WEBSHELL_BODY_DECODE_LIMIT` chars of the request body; omitted on GETs / empty bodies. |

### Canary-backed file traps

One log line per hit. All entries share the same shape:

| `result` | `status` | Extras |
| --- | --- | --- |
| `<trap-name>` | 200 | `canaryTypes: [..]`, `bytes: int` |
| `<trap-name>-error` | 502 | — (upstream canary issuance failed) |
| `<trap-name>-render-error` | 502 | `error: str<=400` (renderer raised) |

See the [canary file trap table in the README](./README.md#canary-file-trap-table)
for the full list of `<trap-name>` values and the paths each one matches.

## Caveats

- Lines are not fsync'd; a hard reboot can drop the last few entries.
- `append_log` opens the file per call without locking. POSIX `write()` is
  atomic for blocks under `PIPE_BUF` (4096 on Linux) — most flux log lines
  are well under that, but a webshell line with a large `bodyPreview` could
  theoretically tear under heavy concurrent writers. Swap in a log shipper
  if you care about this.
- No rotation is built in. Wire up logrotate or equivalent.
