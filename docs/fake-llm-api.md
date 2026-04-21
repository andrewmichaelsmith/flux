# Fake LLM-API endpoint

Matches these paths (exact, case-insensitive; configurable via
`HONEYPOT_LLM_ENDPOINT_PATHS_CSV`):

| Family | Paths | Response |
| --- | --- | --- |
| Ollama | `/v1/models`, `/api/tags`, `/api/version`, `/api/ps`, `/api/show`, `/api/chat`, `/api/generate` | Ollama-native JSON with a fixed list of plausible model IDs |
| OpenAI | `/v1/models`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` | OpenAI-compatible JSON |
| Anthropic | `/v1/messages`, `/anthropic/v1/models`, `/anthropic/v1/messages` | Anthropic Messages-API JSON |

On POST the trap extracts `model` and a prompt-ish field from the
JSON body (handles OpenAI / Ollama / Anthropic content shapes) and
logs them alongside the scanner's auth header, UA, and IP. Chat
responses are a canned bland reply — boring enough to pass, not
useful enough to abuse.

## Why

Multiple scanner fleets started probing exposed AI-inference
endpoints in April 2026 — Ollama-native paths, OpenAI-compatible
paths, and corporate AI-proxy paths (`/anthropic/v1/models`), with
non-overlapping HTTP-client fingerprints. They're looking for:

- **Exposed self-hosted Ollama / llama.cpp servers** — unauthenticated
  by default, so a `200 OK` on `/api/tags` with a real model list is
  an immediate prompt-execution primitive.
- **Internal AI-proxy gateways** — corporate relays that hold an
  upstream API key the scanner can use without needing the key.
- **Harvested API keys** — scanner already has a `Bearer sk-...` or
  `x-api-key` from a credential dump and is probing who'll honor it.

A bare 404 yields nothing. A plausible 200 gets the scanner to send
its first real prompt — the model targeted, the auth header presented,
the follow-up sequence.

See [`../LOGS.md`](../LOGS.md) for the `llm-endpoint-*` result tags
and the `llmModel` / `llmPromptPreview` / `llmHasAuth` fields.
