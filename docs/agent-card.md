# Agent / MCP service-discovery cards (`/.well-known/`)

Three discovery documents in the `/.well-known/` namespace, each of
which names a surface this same server already answers.

| Method | Paths | Response |
| --- | --- | --- |
| GET / HEAD | `/.well-known/agent-card.json`, `/.well-known/agent.json`, `/.well-known/agents.json` | A2A agent card. `url` + `preferredTransport: JSONRPC` name the MCP JSON-RPC endpoint; `skills[]` restate the endpoint's tool catalog in A2A vocabulary. |
| GET / HEAD | `/.well-known/mcp`, `/.well-known/mcp.json`, `/.well-known/mcp/server-card[.json]`, `/.well-known/webmcp[.json]` | MCP server card. Advertises both served transports (Streamable HTTP on the JSON-RPC endpoint, SSE on `/sse`) plus the tool and resource catalogs. |
| GET / HEAD | `/.well-known/ai-plugin.json` | OpenAI plugin manifest. `api.url` points at `/openapi.json`, which the openapi-swagger trap serves. |
| any other method | all of the above | `405` + `Allow: GET, HEAD` — what a static JSON document returns. |

Path sets are exact and case-insensitive, tolerate a trailing slash and
a query string, and are overridable via
`HONEYPOT_AGENT_CARD_A2A_PATHS_CSV`,
`HONEYPOT_AGENT_CARD_MCP_PATHS_CSV` and
`HONEYPOT_AGENT_CARD_PLUGIN_PATHS_CSV`. Master switch:
`HONEYPOT_AGENT_CARD_ENABLED` (default on).

The handler logs `agentCardKind` (`a2a-agent-card` /
`mcp-server-card` / `ai-plugin-manifest`), `agentCardPath`,
`agentCardMethod`, and `agentCardEndpoint` — the URL the served card
advertised. That last field is what the trap is for: a later
`mcp-server-*` line from the same source against the endpoint named
here is a client that read a discovery document and acted on it.

The cards carry **no credential of any kind**, fixed or per-hit. A
public discovery document that ships a secret is implausible on its
face, and the credential slot in this chain is one hop further on —
`tools/call` on the JSON-RPC endpoint already mints a per-request
canary. `securitySchemes` / `authentication` declare that a bearer is
*required*, which is a statement about the endpoint, not a token.

Tool names, resource URIs and transport URLs are all read from the
same `_mcp_tool_catalog()` / `_mcp_resource_catalog()` /
`MCP_SELF_ENDPOINT_PATH` the endpoint itself uses, so the card and
`tools/list` cannot drift apart. A client that fetches both sees one
server describing itself consistently; a disagreement between them
would be the cheapest tell on offer.

## Why

Two traps already cover MCP. The `mcp-config` CanaryTrap —
[docs](./mcp-config.md) — answers the on-disk config *files* a
harvester reads off a filesystem. The `mcp-server-endpoint` trap —
[docs](./mcp-server-endpoint.md) — answers the JSON-RPC *wire*
endpoint. Both are reachable only by a client that already knows where
to look: one reads a file, the other guesses a path.

Neither is reachable by the population that now arrives here. Agent
and MCP discovery crawlers do not read files and do not guess
endpoints. They ask the `/.well-known/` namespace what agent-callable
surface a host publishes — an agent card, an MCP server card, sometimes
the older plugin manifest — a handful of GETs, one per name, and then
they stop. Answering 404 ends that walk at the first request, which is
why the population had produced no behavioural signal at all: there was
no way to distinguish a crawler that only indexes discovery documents
from one that connects and calls tools, because nothing served had ever
given it somewhere to connect to.

A card is a *descriptor*, and the useful property of a descriptor is
that it can name an endpoint the client had no way to guess. That makes
the follow-up request self-selecting: only a client that parsed the
response can make it. The same reasoning is why the SPA build manifest
names a chunk — [docs](./spa-build-manifest.md) — and why the MCP
config advertises an HTTP transport rather than only stdio entries.

The namespace has also stopped being a benign-traffic marker. Alongside
the discovery crawlers, credential-dredging dictionaries have begun
speculatively probing `/.well-known/` for secrets — the AWS credentials
envelope at `/.well-known/credentials.json` is already answered by the
`aws-credentials-json` trap for exactly that reason. So requests here
now come from at least two populations with opposite intent, and the
result tag plus the endpoint follow-up is what separates them.

`/.well-known/openid-configuration`, its OAuth sibling and
`/.well-known/credentials.json` belong to other traps and are
explicitly not claimed here. Neither is `/.well-known/acme-challenge/`,
which is served by the webroot in front of this process — answering it
would break certificate issuance.

## Endpoint spellings the readers fall back to

`/api/mcp/v1`, `/api/v1/mcp` and `/api/mcp/mcp` were added to the MCP
endpoint path set at the same time. They are the versioned and doubled
spellings of the `/api/mcp` gateway mount, walked in the same burst as
the bare name, and they are also where a client that fetched a card but
could not parse it falls back to guessing.

See [`../LOGS.md`](../LOGS.md) for the `agent-card-*` result tags and
the `agentCardKind` / `agentCardPath` / `agentCardMethod` /
`agentCardEndpoint` fields.
