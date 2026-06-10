# Fake LLM-API endpoint

Matches these paths (exact, case-insensitive; configurable via
`HONEYPOT_LLM_ENDPOINT_PATHS_CSV`):

| Family | Paths | Response |
| --- | --- | --- |
| Ollama | `/v1/models`, `/api/tags`, `/api/version`, `/api/ps`, `/api/show`, `/api/chat`, `/api/generate` | Ollama-native JSON with a fixed list of plausible model IDs |
| OpenAI | `/v1/models`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` | OpenAI-compatible JSON |
| Anthropic | `/v1/messages`, `/anthropic/v1/models`, `/anthropic/v1/messages` | Anthropic Messages-API JSON |

On POST the trap extracts `model`, a prompt-ish field, and the
`"stream"` flag from the JSON body (handles OpenAI / Ollama /
Anthropic content shapes) and logs them alongside the scanner's
auth header, UA, and IP. Non-streaming chat responses are a canned
bland reply — boring enough to pass, not useful enough to abuse.

## Streaming responses

When the request body sets `"stream": true`, chat / completion /
message routes return the SDK's native streaming wire format
instead of a single JSON blob:

| Path | Streaming wire format | Content-Type |
| --- | --- | --- |
| `/v1/chat/completions` | OpenAI SSE — `data: {...chunk...}\n\n` deltas + `data: [DONE]` | `text/event-stream` |
| `/v1/completions` | OpenAI SSE (legacy `text_completion` envelope) | `text/event-stream` |
| `/v1/messages`, `/anthropic/v1/messages` | Anthropic SSE — `event: <name>\ndata: {...}\n\n` | `text/event-stream` |
| `/api/chat`, `/api/generate` | Ollama NDJSON — one JSON object per line | `application/x-ndjson` |

A small per-chunk delay paces the deltas so a well-behaved SDK
client (OpenAI / Anthropic / `ollama` python client) reads the
stream through to completion rather than bailing on a
single-blob protocol mismatch.

## Auth-token capture

Both `Authorization: Bearer <tok>` and `x-api-key: <tok>` are
parsed; the trap logs:

- `llmAuthScheme` — lowercased scheme (`bearer`, `basic`, …) or empty.
- `llmAuthTokenSha256` — sha256 of the raw token, for grouping the
  same stolen key across replays from many IPs.
- `llmAuthTokenPreview` — first 12 + last 4 characters with a
  `...` elision. Preserves the leak-source prefix (`sk-proj-`,
  `sk-ant-`, `pk-live-`, …) for fleet grouping without storing
  the middle entropy in plaintext alongside the hash.

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
  `x-api-key` from a credential dump and is probing who'll honor it
  (textbook LLMjacking).

A bare 404 yields nothing. A plausible 200 gets the scanner to send
its first real prompt — the model targeted, the auth header presented,
the follow-up sequence. Streaming-shaped responses extend that to
SDK-based clients (which open the socket expecting an event-stream
and bail on a single-JSON-blob protocol error); the dwell time on
those streams is itself a mild discriminator for scripted-loop vs
SDK clients.

The bearer tokens scanners present are themselves credential intel:
the same stolen key replayed from many IPs identifies one actor
operating a fleet, and a known leak-source prefix (`sk-proj-`,
`sk-ant-…`, AWS-like) hints at where the credential originated.

See [`../LOGS.md`](../LOGS.md) for the `llm-endpoint-*` result tags
and the `llmModel` / `llmPromptPreview` / `llmHasAuth` /
`llmAuthTokenSha256` / `llmAuthTokenPreview` /
`llmStreamRequested` / `llmStreamChunks` fields.
