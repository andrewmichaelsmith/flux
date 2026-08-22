# Fake AI-gateway proxy admin API

The control plane beside the [inference trap](./fake-llm-api.md): the
routes an OpenAI-compatible gateway exposes to whoever holds its master
key.

| Path | Method | Response |
| --- | --- | --- |
| any of the below | any, **no token** | `401` with the proxy's own `auth_error` envelope |
| `/model/info`, `/v1/model/info` | GET | `200` — model registry; the managed-cloud entry's `litellm_params` carry a per-request Tracebit AWS canary as `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token` |
| `/key/info`, `/v1/key/info` | GET | `200` — key metadata: alias, spend, budget, model allow-list, rate limits. Key material is a hash, which is what the real route returns |
| `/key/generate`, `/v1/key/generate` | POST | `200` — mints a per-hit `sk-…` virtual key and echoes the requested model list |
| `/key/generate`, `/v1/key/generate` | GET / other | `405 {"detail":"Method Not Allowed"}` — the route is POST-only upstream, and sweeps GET it anyway |
| `/global/spend/logs` | GET | `200` — recent spend rows: model, token counts, cost, caller alias |

Matching is exact and case-insensitive with a trailing slash tolerated
(`HONEYPOT_LITELLM_ADMIN_PATHS_CSV` overrides the set). Every response
logs `litellmPath`, `litellmMethod`, `litellmAction`, `litellmHasAuth`,
`litellmAuthScheme` and — when a token is presented —
`litellmAuthTokenSha256` plus `litellmAuthTokenPreview` (first 12 + last
4 characters). A key-mint request additionally logs
`litellmRequestedModels` / `litellmRequestedBudget` /
`litellmRequestedDuration` / `litellmRequestedAlias`.

Canary-backed, so dispatch requires `TRACEBIT_API_KEY` on top of
`HONEYPOT_LITELLM_ADMIN_ENABLED`; a keyless deployment 404s the family
rather than serving a registry with empty credential slots. Issuance is
per-IP cached like every other canary trap, so a sweep across all seven
paths spends one canary, not seven.

## Nothing fixed

Only the registry's managed-cloud credential is a canary. Every other
credential-shaped field — the other providers' API keys, the minted
virtual key, the stored key hashes, the spend rows' key hashes — is
per-hit random, and a test asserts two renders share none of them. A
fixed literal here would ship the same string from every host and detect
nothing if it came back.

## Why

A client walking the control plane is doing something different from one
probing `/v1/chat/completions`. It is not looking for free inference; it
is looking for a gateway it can mint its own keys on, which is durable
access rather than one borrowed request. The routes get walked as a set
— registry, key routes and spend log in one pass — which is what makes
the set, rather than any single path, the thing worth answering.

Two slots carry the value.

**The master key.** These routes are the ones a deployment guide tells
you to protect with a bearer token, and the widely-copied example value
is a short placeholder that plenty of deployments never change. A 404
records none of that. Accepting any presented token and logging its hash
and prefix records exactly which keys the sweep is guessing, and groups
the same guessed or stolen key across source IPs. A request with no
token gets the proxy's own 401 rather than a 404, because that is the
answer that says "real route, guess again" — and the guess is the point.

**The provider credential.** On a real gateway, a model's registry entry
carries the upstream credential the proxy dials out with. That
credential belongs to the *operator's* cloud account, not to the proxy —
it is the highest-value item on the surface, and the reason a registry
read is worth more to the caller than a key mint. Backing that slot with
a canary means a client that takes it and uses it does so against the
cloud provider, where the use is visible, rather than against us.

The pairing is the measurement: a source that reads the registry and
then appears on the canary's use side has completed the chain from
discovery to monetisation, and the token hash links the two ends of it.
