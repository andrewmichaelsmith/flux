# Self-hosted AI / MLOps control-plane login sinks

Credential sinks for three self-hosted control planes that turn up inside
one credential pass, plus the authenticated surfaces a session opens.

## Paths

| Path | Method | Product | Surface | Unauthenticated | Authenticated |
| --- | --- | --- | --- | --- | --- |
| `/api/v1/session` | POST | GitOps delivery controller | login | 401, vendor error envelope | 200 `{"token": "<JWT>"}` |
| `/api/v1/session/userinfo` | GET | " | userinfo | 200 `{"loggedIn": false}` | 200 with account + issuer |
| `/api/v1/applications` | GET | " | inventory | 401 `no session information` | application list |
| `/api/v1/repositories` | GET | " | repositories | 401 | repository list + connection state |
| `/v1/user/login` | POST | RAG platform | login | 200 with non-zero `code` | 200 `data.access_token`, plus `Authorization` response header |
| `/v1/user/info` | GET | " | userinfo | 401 envelope | account document |
| `/v1/user/tenant_info` | GET | " | inventory | 401 envelope | tenant document incl. model-provider key |
| `/api/user/login` | POST | knowledge-base platform | login | 200 `code: 400` | 200 `code: 200`, `data` = token |
| `/api/user/profile` | GET | " | userinfo | 401 envelope | profile + permission list |

A `GET` on a login endpoint answers 405 and does **not** spend a
conversion-gate attempt: it carried no credential, and charging it would
let a reachability sweep convert the surface without ever guessing.

The analytics surface at `/api/session` is a **different** trap
([metabase-setup-chain](./metabase-setup-chain.md)) and is deliberately
not claimed here.

## What the handler does

Each login body is parsed as JSON, falling back to form encoding —
tooling that posts a form to a JSON endpoint is replaying a recipe
written for another product, which is itself a grouping signal, so the
body is read rather than discarded. The username field is taken from the
first of `username`, `email`, `user`, `account`, `login` present, and
which one it was is logged as `aiplatformUserField`.

The password is never logged. What is logged is `aiplatformPasswordLen`
and `aiplatformCredentialId` — the **shared** credential-pair hash, the
same one the VPN and remote-desktop sinks emit, so one dictionary
reaching several surfaces is a joinable fact rather than an impression.

Login runs the shared conversion gate under a single scope for all three
products: a source accumulates attempts against `(source, host)` and,
after a per-source threshold, exactly one pair is accepted and keeps
working. The band is far lower than the VPN sinks' — a control-plane pass
tries a handful of product defaults per host, so a 40-attempt floor would
mean this surface never converted for the traffic it exists to answer.
Sharing one budget across the three products is deliberate: a pass that
walks all three is one operator working one host, so the surface converts
on the pass rather than on the product.

Session credentials are accepted back as a bearer header, as a bare
`Authorization` value with no scheme, and as the controller's own session
cookie, because which one returns depends on the product and on the
client library. `aiplatformTokenValid` records whether the caller held a
session this server issued, which separates a client following the chain
it was given from one replaying a token harvested somewhere else.

| Result tag | Meaning |
| --- | --- |
| `aiplatform-login` | A guess, refused. |
| `aiplatform-login-accepted` | The gate gave way; this request's pair is now the one that works for this source. |
| `aiplatform-login-replay` | The found pair, sent again. |
| `aiplatform-login-method-not-allowed` | Reachability check, no attempt charged. |
| `aiplatform-userinfo-anonymous` | The controller's own unauthenticated answer. |
| `aiplatform-<surface>-unauthenticated` | Authenticated surface, no valid session. |
| `aiplatform-<surface>` | Authenticated surface, served. |

## Why

Self-hosted AI and MLOps control planes are now a mainstream scanning
target rather than a niche one, and two unrelated tool families have been
observed converging on the same product set in the same week. The value
behind them is different in kind from another web shell: a GitOps
delivery controller holds cluster credentials and repository deploy keys,
and a self-hosted RAG platform holds model-provider API keys plus
whatever corpus was loaded into it. The ask is cluster and model access.

Flux already answered one member of that set and 404'd the rest, which is
the worst arrangement available — the sender learns the host does not run
them and stops, and the one surface that does answer looks anomalous
beside three dead ones.

Answering only the login page would record the dictionary and nothing
else, because authentication would never succeed. The gate is what makes
post-authentication behaviour observable at all: whether a client that
obtains a session goes on to enumerate applications, reads the tenant
document, or spends the model-provider key somewhere we can see it.

Every credential-shaped field here is per-hit unique — session tokens are
derived per source and host from a per-process secret, and the
model-provider key is per-hit random. A fixed literal would ship the same
string from every host running this, which is a fleet-wide fingerprint
and gives a replay nothing to detect.
