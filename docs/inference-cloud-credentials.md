# Inference / GPU-cloud credential canary traps

The credential files that sit on a box running a self-hosted LLM stack:
the GPU and serverless-compute providers that stack rents capacity from,
the chat front-end that holds the upstream provider keys, and the
edge-runtime secrets file a deployed inference proxy keeps beside its
config.

## Routed paths

| Trap name | Paths | Format |
| --- | --- | --- |
| `runpod-config` | `/.runpod/config.toml` | TOML — RunPod CLI, canary as `api_key` |
| `modal-config` | `/.modal.toml` | TOML — Modal token pair, canary as `token_id` + `token_secret` |
| `lambda-cloud-keys` | `/.lambda_cloud/lambda_keys` | Text — Lambda Labs, bare `api_key` line, no section header |
| `paperspace-config` | `/.paperspace/config.json` | JSON — Paperspace / Gradient CLI, canary as `apiKey` |
| `librechat-config` | `/librechat.yaml`, `/librechat.yml` | YAML — LibreChat server config, canary as a custom endpoint's `apiKey` |
| `cloudflare-dev-vars` | `/.dev.vars` | Dotenv — Cloudflare Workers local secrets |

Every member also answers its editor/backup sibling set (`.bak`, `.old`,
`.save`, `~`, …) on the same rule as the rest of the credential-file
tables — a credentials file is exactly the file an operator copies aside
before rotating it.

## What the handler does

Each renderer emits the file in its real on-disk format with the
Tracebit AWS canary occupying the field a credential extractor reads, so
replay is visible at the provider regardless of which vendor the reader
believed the token belonged to.

`librechat-config` is the one member that sets up a second step. Its
`custom` endpoint block names **this host's own OpenAI-compatible base
URL** (`/v1`, which Flux already serves) and carries the per-hit canary
session token as that endpoint's `apiKey`. A reader that parses the
config rather than grepping it is therefore steered into the inference
trap, and the bearer presented there joins that request back to this
exact config read. The host is resolved with the same test and fallback
order as the MCP self-endpoint, so a loopback literal arriving from a
reverse proxy is never published.

## Per-hit uniqueness

Every credential-shaped field is either a Tracebit canary or a per-hit
random synthetic — the `.dev.vars` database password uses
`_fake_db_password()`. Nothing is a fixed literal. A hardcoded
credential gives zero detection on replay and ships the same string from
every host, which collapses a fleet into a single fingerprint. The
`test_no_member_ships_a_fixed_credential_literal` test pins this by
rendering under two different issuances and requiring every
credential-shaped field to change.

Non-credential filler (profile names like `prod` / `default`, account
ids, model names, size limits) is fixed, which is correct — only
secret-shaped values must vary.

## Why

A credential sweep that used to stop at `/.aws/credentials` now carries a
tail of AI-infrastructure paths, and the distinction that makes them
worth answering is what each buys a thief. An IDE or provider API key
yields inference — metered per token, revocable, visible on a bill. A
**GPU-cloud credential yields the ability to start instances**, billed by
the GPU-hour, which is the same economics that makes compute-focused
credential abuse attractive in the first place.

Observed demand is multi-source rather than one tool's quirk: the GPU and
serverless-compute members are walked by self-identifying scanners whose
dictionaries also carry current IaC and cloud-CLI paths, several sources
per pass, and `.dev.vars` has been asked for steadily for months by
unrelated senders. Before this table Flux returned 404 to all of it,
which is the one response that tells a scanner nothing is there.

The LibreChat member is the highest-yield read in such a sweep for the
same reason the AI-gateway admin API is: a self-hosted deployment
collects *several* upstream provider keys in one file, so it is where a
harvester expects one read to pay for the whole pass.
