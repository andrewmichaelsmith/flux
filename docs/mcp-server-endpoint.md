# Fake MCP (Model Context Protocol) server endpoint

Matches these paths (exact, case-insensitive; configurable via
`HONEYPOT_MCP_SERVER_PATHS_CSV`):

| Method | Path | Response |
| --- | --- | --- |
| GET  | `/sse` | `text/event-stream` handshake — one `event: endpoint` frame pointing at `/mcp/messages` |
| POST | `/mcp`, `/mcp/`, `/mcp/messages` | JSON-RPC 2.0 dispatch (see below) |
| GET / HEAD / other | `/mcp`, `/mcp/`, `/mcp/messages` | `405` + JSON-RPC error envelope |

`/mcp.json`, `/.cursor/mcp.json`, `/.mcp/config.json`, and the other
on-disk MCP config filenames are covered by the `mcp-config` CanaryTrap
(they render a fake `mcp.json` with the Tracebit AWS canary in the
`mcpServers[*].env` block). This trap covers the runtime **wire**
endpoints instead — the JSON-RPC dispatch surface a real MCP server
exposes, and the SSE handshake older MCP clients open before the
JSON-RPC POST.

## JSON-RPC dispatch

| Method | Response |
| --- | --- |
| `initialize` | `serverInfo` + `capabilities` (tools / resources / prompts / logging). `params.clientInfo.{name,version}` logged. |
| `tools/list` | A five-tool catalog (`fetch_secret`, `filesystem_read`, `list_workspace_files`, `database_query`, `shell_exec`). Each tool ships a plausible `inputSchema`. |
| `tools/call` on `fetch_secret` / `filesystem_read` / `list_workspace_files` / `database_query` / `read_env` / `get_aws_credentials` | Mints a per-request Tracebit AWS canary via `_get_or_issue_canary(("aws",), …)`; returns it as the tool-call `content[0].text` in `.env` shape (`AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_SESSION_TOKEN=…`). |
| `tools/call` on any other tool (including `shell_exec`) | Returns `isError: true` with `permission denied`; we don't imitate real code execution. |
| `resources/list` | Four resources: `env://AWS_ACCESS_KEY_ID`, `env://AWS_SECRET_ACCESS_KEY`, `file:///workspace/.env`, `file:///etc/mcp/credentials.json`. |
| `resources/read` on `env://AWS_*` / `file:///workspace/.env` / `.../credentials.json` / `.../.aws/credentials` | Mints the same canary; returns it as `contents[0].text` in the format the URI implies (bare value for `env://`, `.env` shape for `.env`, JSON for `credentials.json`). |
| `resources/read` on any other URI | Returns JSON-RPC `-32602 Invalid params: resource not found`. |
| `prompts/list` | `{"prompts": []}` — the empty-catalog shape a fresh server returns. |
| `ping` | `{}` — MCP heartbeat. |
| Anything else | `{}` — keeps `notifications/*` scanners walking. |

The tool argument (`params.arguments`) is JSON-serialised and truncated
to `HONEYPOT_MCP_SERVER_BODY_DECODE_LIMIT` (default 2048) chars, logged
as `mcpToolArgsPreview` so `shell_exec` / `database_query` payloads are
recoverable for triage without inflating the log line.

## Auth-token capture

Both `Authorization: Bearer <tok>` and `x-api-key: <tok>` are parsed
(reuses `capture_llm_auth_token`); the trap logs:

- `mcpAuthScheme` — lowercased scheme (`bearer`, `basic`, …) or empty.
- `mcpAuthTokenSha256` — sha256 of the raw token, for grouping the
  same stolen key across replays from many IPs.
- `mcpAuthTokenPreview` — first 12 + last 4 characters with a
  `...` elision. Preserves a leak-source prefix without storing the
  middle entropy in plaintext alongside the hash.

## Why

Scanners started probing MCP server-runtime endpoints alongside the
config files after the protocol landed in production coding assistants.
The `/mcp` + `/sse` pair is the runtime dispatch surface — a real MCP
server exposes tools (arbitrary functions the LLM can call, e.g.
`filesystem_read`, `database_query`, or `shell_exec`) and resources
(env vars / files / API responses the LLM can read). Scanners walking
these endpoints are looking for:

- **Exposed self-hosted MCP servers** — unauthenticated by default in
  many implementations, so a `200 OK` on `initialize` + a plausible
  `tools/list` gets the scanner to send `tools/call` next.
- **Servers hosting secret-fetch or filesystem tools** — the harvest
  target is the response text, which for `fetch_secret` / `read_env` /
  `filesystem_read` a real server would populate with actual
  credentials. `AKIA…`-shaped grep loops walking `content[].text`
  pick up the canary.
- **Servers hosting arbitrary command execution** — `shell_exec` is
  a common tool name. We return `isError: true` for those; the log
  captures the attempted command in `mcpToolArgsPreview` for triage.

A bare 404 yields nothing. A plausible JSON-RPC dispatch gets the
scanner to walk `initialize` → `tools/list` → `tools/call`, which is
where the intel lives — the tool names / URIs probed, the auth header
presented, and the follow-up sequence. Bearer tokens against MCP are
themselves credential intel: the same stolen token replayed from many
IPs identifies one actor operating a fleet.

See [`../LOGS.md`](../LOGS.md) for the `mcp-server-*` result tags and
the `mcpJsonrpcMethod` / `mcpToolName` / `mcpResourceUri` /
`mcpToolArgsPreview` / `mcpHasAuth` / `mcpAuthTokenSha256` /
`mcpAuthTokenPreview` / `mcpClientName` / `mcpClientVersion` fields.
