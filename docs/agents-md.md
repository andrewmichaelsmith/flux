# Agent instruction files

Serves the instruction files coding agents read on startup, with a
per-hit AWS canary and a follow-up link that only a client reading the
prose would fetch.

| Path | Method | Response | Result tag |
| --- | --- | --- | --- |
| `/AGENTS.md`, `/CLAUDE.md`, `/.claude/CLAUDE.md`, `/root/.claude/CLAUDE.md` | any | 200 `text/markdown`, titled after the file asked for | `agents-md` |
| `/internal/agent/sessions/<id>/context` (any trailing leaf, or none) | any | 200 JSON session handout carrying the canary | `agent-session-context-referenced` / `agent-session-context-foreign` |

The instruction file has a "Before you start" section telling the reader
to `GET /internal/agent/sessions/<id>/context` first. `<id>` is the
issuing hit's `requestId`. The link is root-relative, so it resolves
against whatever host the client fetched. `/.claude/history.jsonl` names
the same link in one of its prior prompts.

A follow-up logs `agentBreadcrumbId`, which joins to the issuing row's
`requestId`. While the process still remembers issuing that id (the
registry is bounded, and process memory only), it also logs
`agentBreadcrumbKnown`, `agentBreadcrumbSameIp`,
`agentBreadcrumbAgeSeconds` and `agentBreadcrumbIssuedPath`. An id the
process did not issue is tagged `-foreign`. Both outcomes get the same
body, so the response does not reveal which one it was.

`HONEYPOT_AGENT_BREADCRUMB_ENABLED` (default on) controls the link and
the route. The route also needs `TRACEBIT_API_KEY`, because it mints a
canary.

## Why

A key grepper and a reader look the same when they fetch the file. They
look different when they fetch the link. Credential harvesters now go
after AI-assistant config and history. Some of them are driven by an LLM
agent that reads and acts on what it finds. An instruction file is written
to be followed, so it is the natural place to tell those clients apart.
The link also gives the canary a second, later point where it can be
handed out. That timing separates a reader who acts on the prose from an
offline batch replay.
