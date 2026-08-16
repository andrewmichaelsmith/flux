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
| `bodyBytesRead` | int | 0 unless the request read a capped body (`GET`/`POST` payloads). |
| `bodySha256` | string | SHA256 hex when body bytes were present, or `""`. |
| `trapWalkDepth` | int | Present only when an exact-path canary trap was reached after dropping leading app-layout directory segments (`/admin/aws.json` -> depth 1). Absent means the path arrived at the location the trap table lists. |

## Result tags

Every line has a `result` identifying what the handler did, and a
`status` (the HTTP status returned to the client). Grouped by trap.

### Router / fallback

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `not-handled` | 404 | — | Path didn't match any trap; fell through to 404. |

**Canary-issuance and renderer failures also answer `404 not found\n`** —
byte-identical to `not-handled` above. They previously answered
`502 upstream credential issue failed` (and `502 render error`), which no
ordinary web server emits, so one upstream blip made every canary-backed
trap on every sensor announce itself at once with a fleet-wide-unique
fingerprint. The client can no longer tell an issuance failure from a path
that was never there; the `result` tag and `error` field below keep the
failure fully diagnosable in the log.

### `/.env` canary

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `issued` | 200 | `types: [..]` | `.env` canary issued and served. |
| `tracebit-http-error` | 404 | `tracebitStatus: int`, `error: str<=400` | Tracebit API returned a non-2xx. |
| `tracebit-error` | 404 | `error: str<=400` | Connection error / timeout / malformed response from Tracebit. `error` is `"<ExceptionClass>"` or `"<ExceptionClass>: <message>"` — the class name is always present, because several of these exceptions (`TimeoutError` in particular) carry no message and previously logged an empty string. |

### Deploy-sync config

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `deploy-sync-config` | 200 | `bytes` | Editor-plugin deploy config served. Carries a per-hit SSH credential minted by the renderer, not a Tracebit canary, so `canaryTypes` is empty and no upstream call is made. The username served is `deploy_<first 8 hex of sha256(requestId)>` — recompute it from this line's `requestId` to tie an SSH authentication attempt back to this request. |

### Fake `/.git/*` tree

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `fake-git` | 200 | `commitSha`, `rootTreeSha`, `secretsBlobSha`, `canaryTypes`, `fakeGitBytes`, `fakeGitDripBytes`, `fakeGitDripIntervalMs` | Object served from the synthetic repo. Includes `/.git/credentials`, which returns a Git credential-store line with a GitLab username/password canary. |
| `fake-git-miss` | 404 | `commitSha`, `gitKey` | Path resolved to the repo but wasn't a file in it. `gitKey` is the canonical `/.git/...` lookup key (lowercased, prefix-stripped) — so `/login/.GiT/FOO` logs `path=/login/.GiT/FOO`, `gitKey=/.git/foo`. |
| `fake-git-error` | 404 | — | Canary issuance failed. |
| `fake-git-disconnect` | 200 | `fakeGitBytesSent`, `commitSha` | Scanner hung up mid-drip. |
| `fake-git-capacity` | 503 | — | Tarpit semaphore full. Only reachable for responses that actually drip — a repo *file* larger than one drip chunk. `HEAD`, single-chunk bodies, and directory autoindexes are served immediately and never charge a slot, so a `/.git/` directory sweep cannot exhaust the semaphore. |

### Fake `/.svn/*` working copy

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `fake-svn` | 200 | `svnKey`, `svnRevision`, `svnRepoUuid`, `svnAuthCached`, `canaryTypes`, `bytes` | File served from the synthetic working copy. `svnKey` is the canonical `/.svn/...` lookup key (lowercased, prefix-stripped), so it records which layout the client asked for — `entries` / `text-base/` is a pre-1.7 dumper, `wc.db` / `pristine/` is 1.7+, and a `pristine/` fetch following a `wc.db` fetch means the client parsed the database and resolved a checksum out of it. |
| `fake-svn-redirect` | 301 | `svnKey`, `svnRevision`, `location` | A directory asked for without its trailing slash (`/.svn/auth/svn.simple`), answered the way Apache `DirectorySlash On` and nginx do. `location` is built from the request path, so a prefixed probe is redirected within its own prefix. Whether the client comes back for the slash-terminated form is itself a signal — most bare-socket dictionary scanners do not follow redirects. |
| `fake-svn-miss` | 404 | `svnKey`, `svnRevision` | Path resolved to the working copy but wasn't a file in it. |
| `fake-svn-error` | 404 | — | Canary issuance failed. |

A path carrying both segments (`/.git/config/.svn/entries` — a scanner
appending the svn dictionary to every git path it tried) is dispatched to
fake-git and logs `fake-git-miss`, not `fake-svn`.

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
| `llm-endpoint-anthropic-models-list` | 200 | `GET /anthropic/v1/models` (corporate AI-proxy probe target) |
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
| `llm-endpoint-<route>-disconnect` | 200 | Streaming response: scanner closed the socket mid-stream (e.g. `llm-endpoint-openai-chat-disconnect`). |
| `llm-endpoint-<route>-prepare-disconnect` | 200 | Streaming response: scanner closed before the headers went out. |
| `llm-endpoint-miss` | 404 | Matched the path set but no renderer (shouldn't occur; defensive) |

Extras on every `llm-endpoint-*` line:

| Field | Type | Notes |
| --- | --- | --- |
| `llmPath` | string | The path that matched. |
| `llmAction` | string | One of `models-list`, `version`, `running-models`, `show-model`, `chat`, `completion`, `embedding`. Filled from the JSON body when present, otherwise inferred from the path. |
| `llmModel` | string | `model` field pulled from a JSON body; `""` on GETs or malformed bodies. Truncated to 120 chars. |
| `llmHasAuth` | bool | `true` if `Authorization` or `x-api-key` header was present — the strongest signal that the scanner already has a harvested key. |
| `llmAuthScheme` | string | Lowercased first token of `Authorization` (`bearer`, `basic`, …); `""` otherwise. |
| `llmAuthTokenSha256` | string | sha256 of the raw bearer / x-api-key token. Same token across many IPs = same actor / fleet. Omitted when no auth was sent. |
| `llmAuthTokenPreview` | string | First 12 + last 4 chars of the token with a `...` elision — preserves the leak-source prefix (`sk-proj-`, `sk-ant-…`) for grouping. Omitted when no auth was sent. |
| `llmMethod` | string | Request method (`GET` / `POST` / `HEAD`). |
| `llmStreamRequested` | bool | `true` if the JSON body set `"stream": true`. Streaming routes branch into SSE / NDJSON wire format. |
| `llmStreamChunks` | int | Number of chunks written when streaming. Present only on streaming responses. |
| `llmStreamBytesSent` | int | Bytes written before the scanner disconnected. Present only on `-disconnect` / `-prepare-disconnect` lines. |
| `bytes` | int | Size of the response body returned (sum across streaming chunks). |
| `llmPromptPreview` | string | Prefix of the extracted prompt, truncated to `HONEYPOT_LLM_BODY_DECODE_LIMIT`. Omitted if empty. |

### Fake MCP (Model Context Protocol) server endpoint

One log line per hit. Covers the runtime dispatch surface (`/mcp`,
`/mcp/`, `/mcp/messages`) and the SSE handshake (`/sse`). The on-disk
MCP config files (`/mcp.json`, `/.cursor/mcp.json`, …) are the
`mcp-config` CanaryTrap and log under a different `result` tag.

| `result` | `status` | Meaning |
| --- | --- | --- |
| `mcp-server-sse-handshake` | 200 | `GET /sse` — SSE handshake, sends one `event: endpoint` frame pointing at `/mcp/messages`. |
| `mcp-server-sse-method-not-allowed` | 405 | Non-GET on `/sse`. |
| `mcp-server-method-not-allowed` | 405 | Non-POST on a JSON-RPC endpoint. |
| `mcp-server-parse-error` | 200 | Body wasn't valid JSON. JSON-RPC `-32700`. |
| `mcp-server-invalid-request` | 200 | JSON body wasn't a JSON-RPC object or was missing `method`. JSON-RPC `-32600`. |
| `mcp-server-initialize` | 200 | `initialize` — returns fake `serverInfo` + capabilities. |
| `mcp-server-tools-list` | 200 | `tools/list` — returns the five-tool catalog. |
| `mcp-server-tools-call-issued` | 200 | `tools/call` on a secret-fetch tool name — Tracebit AWS canary was minted and returned in `content[0].text`. |
| `mcp-server-tools-call-other` | 200 | `tools/call` on a non-secret tool (e.g. `shell_exec`) or on any tool when no `TRACEBIT_API_KEY`. Returns `isError: true`. |
| `mcp-server-tools-call-tracebit-error` | 200 | `tools/call` matched the secret path but the canary issuance failed / timed out. |
| `mcp-server-resources-list` | 200 | `resources/list` — returns the resource catalog. |
| `mcp-server-resources-read-issued` | 200 | `resources/read` on `env://AWS_*` / `.env` / MCP-credentials URI — Tracebit AWS canary embedded in `contents[0].text`. |
| `mcp-server-resources-read-other` | 200 | `resources/read` on any other URI. JSON-RPC `-32602`. |
| `mcp-server-resources-read-tracebit-error` | 200 | Secret URI matched but canary issuance failed. |
| `mcp-server-prompts-list` | 200 | `prompts/list` — returns `{"prompts": []}`. |
| `mcp-server-ping` | 200 | `ping` — heartbeat. |
| `mcp-server-other` | 200 | Any other JSON-RPC method (`notifications/*`, `logging/*`, …). Returns `{}`. |

Extras on every `mcp-server-*` line:

| Field | Type | Notes |
| --- | --- | --- |
| `mcpMethod` | string | Request method (`GET` / `POST` / `HEAD`). |
| `mcpJsonrpcMethod` | string | The `method` field from the JSON-RPC body (`initialize`, `tools/call`, `resources/read`, …). `""` on the SSE handshake or malformed bodies. |
| `mcpHasAuth` | bool | `true` if `Authorization` or `x-api-key` header was present. Stolen MCP access tokens replayed from many IPs are direct intel. |
| `mcpAuthScheme` | string | Lowercased first token of `Authorization` (`bearer`, `basic`, …); `""` otherwise. |
| `mcpAuthTokenSha256` | string | sha256 of the raw bearer / x-api-key token. Omitted when no auth was sent. |
| `mcpAuthTokenPreview` | string | First 12 + last 4 chars of the token with a `...` elision. Omitted when no auth was sent. |
| `mcpClientName` | string | `params.clientInfo.name` from an `initialize` call (`cursor`, `claude-code`, `cline`, …). Truncated to 120 chars. |
| `mcpClientVersion` | string | `params.clientInfo.version` from an `initialize` call. Truncated to 60 chars. |
| `mcpToolName` | string | `params.name` from a `tools/call`. |
| `mcpToolArgsPreview` | string | JSON-serialised `params.arguments` from a `tools/call`, truncated to `HONEYPOT_MCP_SERVER_BODY_DECODE_LIMIT`. Recovers `shell_exec` / `database_query` payloads without inflating the log line. |
| `mcpResourceUri` | string | `params.uri` from a `resources/read`, truncated to 400 chars. |
| `types` | list | `["aws"]` on `mcp-server-tools-call-issued` / `mcp-server-resources-read-issued`. |

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

### Fake Cisco WebVPN / AnyConnect

One log line per hit.

| `result` | `status` | Meaning |
| --- | --- | --- |
| `cisco-anyconnect-config-auth` | 200 | `POST /` with AnyConnect `config-auth` XML body |
| `cisco-webvpn-logon` | 200 | `/+CSCOE+/logon.html` or `/+CSCOE+/portal.html` |
| `cisco-webvpn-logon-forms-js` | 200 | `/+CSCOE+/logon_forms.js` |
| `cisco-webvpn-java-jar` | 200 | `/+CSCOL+/Java.jar` |
| `cisco-webvpn-a1-jar` | 200 | `/+CSCOL+/a1.jar` |
| `cisco-webvpn-miss` | 404 | Matched the path family but no renderer |

Extras include `ciscoWebvpnPath`, `ciscoWebvpnMethod`, `bytes`,
`ciscoWebvpnUsername`, `ciscoWebvpnHasPassword`, and
`ciscoAnyconnectVersion` when those values are present.

### Fake ColdFusion admin / component browser

One log line per hit.

| `result` | `status` | Meaning |
| --- | --- | --- |
| `coldfusion-public-cfm` | 200 | `/indice.cfm`, `/menu.cfm`, or `/base.cfm` public ColdFusion anchor |
| `coldfusion-componentutils` | 200 | `/CFIDE/componentutils/` component browser surface |
| `coldfusion-admin-login` | 200 | Administrator login page |
| `coldfusion-admin-post` | 200 | POST to Administrator, with body/auth hints logged |
| `coldfusion-adminapi` | 200 | `/CFIDE/adminapi/...` WDDX-shaped API response |
| `coldfusion-miss` | 404 | Matched the path family but no renderer (shouldn't occur; defensive) |

Extras on every `coldfusion-*` line:

| Field | Type | Notes |
| --- | --- | --- |
| `coldfusionPath` | string | The path that matched. |
| `coldfusionMethod` | string | `GET` / `POST` / `HEAD`. |
| `coldfusionHasAuth` | bool | `true` if `Authorization` or `Cookie` was present. |
| `coldfusionHasExploit` | bool | Query/path/body contained ColdFusion exploit indicators such as AdminAPI, WDDX, Java runtime, traversal, or admin-password parameters. |
| `coldfusionAction` | string | Query-string `method` value, when present. |
| `contentType` | string | First 120 chars of `Content-Type`. |
| `bytes` | int | Size of the response body returned. |
| `bodyPreview` | string | First 512 chars of request body; omitted on GETs / empty bodies. |
| `coldfusionPayloadPreview` | string | Up to 400 chars of `query | body-preview`; only present when `coldfusionHasExploit` is true. |

### Cmd-Injection / Body-RCE

| `result` | `status` | Meaning |
| --- | --- | --- |
| `cmd-injection-probe` | 200 | Admin-config path with no command |
| `cmd-injection-command` | 200 | Admin-config command with static simulated output or empty shell output |
| `cmd-injection-creds-leak` | 200 | Command asked for AWS credentials/config and got a Tracebit AWS canary |
| `cmd-injection-printenv` | 200 | `/printenv`-shape route returned an env block with Tracebit AWS values |
| `cmd-injection-php-cgi-rce` | 200 | PHP-CGI `auto_prepend_file=php://input` body payload |
| `cmd-injection-apache-cgi-shell` | 200 | Apache CGI path-traversal `/bin/sh` body payload |
| `phpunit-eval-stdin` | 200 | PHPUnit `eval-stdin.php` body probe |

Common extras include `cmdInjectionPath`, `cmdSource`, `cmdKey`, `cmd`,
`cmdFamily`, `outputBytes`, `bodyPreview`, and `decodedCommand` for decoded
PHP-CGI `base64_decode(...)` payloads.

### Cloud instance / container role-credential service

Every line carries `imdsKind` (which protocol step) and `imdsRole` (the
role segment **as the client sent it**, `""` for the listing steps). A
`cloud-imds-role-list` followed by a `cloud-imds-role-credentials` from
the same source, naming the role the listing returned, is the two-step
chain — that pair is the signal this trap exists to produce. See
[docs](./docs/cloud-imds.md).

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `cloud-imds-index` | 200 | `bytes: int` | Metadata-root key listing. No canary issued. |
| `cloud-imds-iam-index` | 200 | `bytes: int` | `iam/` subtree listing. No canary issued. |
| `cloud-imds-role-list` | 200 | `bytes: int` | Role **name** only, no secret. No canary issued. |
| `cloud-imds-role-credentials` | 200 | `canaryTypes: [..]`, `bytes: int` | Instance-metadata credential envelope. |
| `cloud-imds-ecs-credentials` | 200 | `canaryTypes: [..]`, `bytes: int` | Container credential-provider envelope. |
| `cloud-imds-<kind>-error` | 404 | — | Canary issuance failed. Only the credential kinds can produce this. |

### SSRF relay onto the metadata tree

The same documents, reached through a URL-taking parameter on a
fetch-style entry path instead of directly. Every line adds `ssrfParam`
(the parameter spelling the client guessed), `ssrfTarget` (the URL as
sent, ≤512 chars), `ssrfHost`, `ssrfTargetPath` and `ssrfCloud`
(`aws`/`gcp`). The AWS branch also carries the full `imdsKind` /
`imdsRole` pair, because it is the same handler — so the two-step chain
above is reconstructable through the relay too. See
[docs](./docs/ssrf-metadata-relay.md).

| `result` | `status` | Extras | Meaning |
| --- | --- | --- | --- |
| `ssrf-relay-aws-<kind>` | 200 | as `cloud-imds-<kind>` | EC2-layout metadata step served through the relay. Canary only on the credential kinds. |
| `ssrf-relay-aws-<kind>-error` | 404 | — | Canary issuance failed on a relayed credential step. |
| `ssrf-relay-gcp-index` | 200 | `bytes: int` | GCP metadata tree listing. No canary issued. |
| `ssrf-relay-gcp-sa-index` | 200 | `bytes: int` | Service-account key listing. No canary issued. |
| `ssrf-relay-gcp-email` | 200 | `bytes: int` | Service-account address (non-secret filler). No canary issued. |
| `ssrf-relay-gcp-token` | 200 | `syntheticToken: true`, `bytes: int` | Per-hit synthetic bearer token — **not** a monitored canary; Tracebit issues no GCP-shaped credential. The token itself is never logged. |
| `ssrf-relay-unmatched` | 404 | — | Metadata host we serve, document we do not emulate. Logged for the target, which names what the tooling wants next. |

A request to an entry path whose parameters name no metadata host is not
claimed by this trap at all — it falls through to `not-handled`, and
flux never makes an outbound request on any branch.

### Canary-backed file traps

One log line per hit. All entries share the same shape:

| `result` | `status` | Extras |
| --- | --- | --- |
| `<trap-name>` | 200 | `canaryTypes: [..]`, `bytes: int` |
| `<trap-name>-error` | 404 | — (upstream canary issuance failed) |
| `<trap-name>-render-error` | 404 | `error: str<=400` (renderer raised) |

See the [canary file trap table in the README](./README.md#canary-file-trap-table)
for the full list of `<trap-name>` values and the paths each one matches.

## Caveats

- Lines are not fsync'd; a hard reboot can drop the last few entries.
- `append_log` opens the file per call without locking, but each record is
  serialised up front and handed to a single `os.write()` on an `O_APPEND`
  descriptor, which is atomic against other appenders on a regular file.
  This used to be a buffered text-mode write, which could split one record
  across several syscalls; with two writers live at once (a service restart
  overlap is enough) those splits spliced into lines that were not valid
  JSON, and every reader dropped them silently — so the loss, including
  canary-issuance records, was invisible. If you add a writer here, keep
  the one-record-one-`write()` property; the tests assert it.
- No rotation is built in. Wire up logrotate or equivalent.
