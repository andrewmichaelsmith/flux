# MCP config files, and the chain out of them

On-disk Model Context Protocol config files, plus the two provider-scoped
dotenv fragments that travel in the same scanner dictionaries.

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/.mcp.json`, `/mcp.json`, `/.mcp/mcp.json`, `/.mcp/config.json`, `/.mcp/settings.json`, `/mcp_settings.json`, `/.cline/mcp_settings.json`, `/.cursor/mcp.json`, `/.cursor/mcp_config.json`, `/claude_desktop_config.json` | `200 application/json` — an `mcpServers` document |
| `GET` | `/.env.anthropic` | `200 text/plain` — dotenv fragment, canary in `ANTHROPIC_API_KEY` |
| `GET` | `/.env.openai` | `200 text/plain` — dotenv fragment, canary in `OPENAI_API_KEY` |

The `mcpServers` document carries three entries. Two are *stdio* servers
(`command` + `args` + an `env` block holding the canary as
`GITHUB_PERSONAL_ACCESS_TOKEN`, `API_KEY`, `SESSION_TOKEN`). The third,
`internal-gateway`, is an **HTTP-transport** entry whose `url` is this
same server's `/mcp` JSON-RPC endpoint and whose `Authorization` header
is a `Bearer` of the per-hit canary session token.

## Why

Two of these paths are not dot-prefixed or not bare `.env`, and both
shapes were being missed for structural reasons rather than by choice:

- `/claude_desktop_config.json` is the only name in the MCP-config family
  without a leading dot, so it fell outside a dotfile-shaped matcher
  while every dotted sibling in the same sweep answered.
- `/.env.anthropic` and `/.env.openai` were worse than a 404. The generic
  `.env` tarpit claims every `.env`-prefixed leaf except bare `/.env`,
  exempting only paths that carry a trap entry — so these two were
  answered with a redirect chain, and the canary that yields replay-side
  telemetry was never issued. Adding the trap entries is what routes them
  to a canary; the tarpit exemption then follows automatically. A
  regression that drops those entries reintroduces the redirect silently,
  with no 404 to notice, which is why there is a test asserting
  `is_tarpit_path` is False for both.

The `internal-gateway` entry exists because reading a config was
otherwise a dead end. A stdio entry names a binary to spawn on the
reader's own machine; nothing in it is followable across the network. So
the walk ended at the file, and the interesting question — does anyone
who harvests an MCP config actually *use* it? — was unmeasurable. The
runtime JSON-RPC endpoint was already implemented (see
[`mcp-server-endpoint.md`](./mcp-server-endpoint.md)) and already mints
canaries on `tools/call`; the two halves simply were not wired together.

Because the advertised bearer is the per-hit canary session token, the
`mcpAuthTokenSha256` logged on any follow-up connection joins that
connection back to the exact config read that issued it. That is the
measurement: not "a config was fetched" and separately "an endpoint was
probed", but one actor doing both, with the link provable from the logs.

Two constraints on the advertised URL, both learned the hard way
elsewhere in this codebase (the OIDC issuer and the appliance page
titles): it must not publish a loopback literal — behind a proxy that
rewrites `Host`, the requested host arrives as `127.0.0.1`, which would
advertise the reader's own machine and would be the identical string from
every host running this software, i.e. a fleet fingerprint. And the path
is derived from the live endpoint set rather than written out a second
time, so renaming the endpoint via `HONEYPOT_MCP_SERVER_PATHS_CSV` moves
the advertised URL with it instead of leaving the config pointing at a
path this server no longer answers.

The dotenv fragments carry non-secret shape (base URL, model, timeout)
alongside the canary. A file holding one key and nothing else reads as
bait.

Same caveat as the other AI-credential traps: the canary is an AWS
credential wearing an LLM field name, so a consumer that format-checks
the value drops it as obviously wrong. One that harvests on field name
(`API_KEY`, `_TOKEN`, `ANTHROPIC_API_KEY`) still serialises and ships it,
tripping the AWS canary on replay.
