# codex-config-toml

Fake OpenAI Codex CLI `~/.codex/config.toml` — the persistent model /
provider / MCP-server settings file, distinct from `~/.codex/auth.json`
(covered by the `codex-auth` trap).

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/.codex/config.toml`, `/root/.codex/config.toml` | `200 application/toml` — plausible TOML doc |

The rendered TOML documents two `[mcp_servers.*]` entries with `env`
blocks (`GITHUB_PERSONAL_ACCESS_TOKEN`, `API_KEY`, `SESSION_TOKEN`) and
two `[model_providers.*]` entries pointing at the OpenAI + Anthropic
endpoints. Each render mints a fresh Tracebit AWS canary and embeds
the access-key-id, secret-access-key, and session-token as the three
MCP-env-slot values, so a scanner grepping for `api_key` / `_TOKEN`
under an `env` heading walks away with a replay-fireable set.

The `[history]` block is filler shape only — no canary material,
but real Codex configs carry it, so its absence would fingerprint
the response.

## Why

`~/.codex/config.toml` is one of the paths a mid-July 2026 scanner
cohort added to its AI-tooling credential dictionary. The `auth.json`
sibling was already trapped; the config.toml is what a Codex user
pastes MCP-server API keys into (Codex spawns each MCP server as a
child process with the `env` block on its command line). Missing
this variant meant flux 404'd a walk that was fetching everything
else in the same dictionary. Same AWS-canary-in-LLM-shape caveat as
the other AI-cred traps: a key-format-prefix filter drops the value
as obviously-fake; a field-name harvester (`API_KEY`, `_TOKEN`) still
serialises and ships it, tripping the AWS canary on replay.
