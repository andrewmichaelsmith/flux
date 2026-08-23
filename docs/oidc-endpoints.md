# OIDC endpoints — the addresses the discovery document advertises

The [discovery document](./fake-oidc-discovery.md) exists to tell a
client where to send its next request. Until this trap, every address it
published returned 404. A client that read the document and followed
`jwks_uri` — the cheapest and most common second step — learned the
issuer was fake, and the one surface built to invite a follow-up instead
proved there was nothing behind it. Credential-bearing POSTs to the
token, introspection and userinfo endpoints fell through to the generic
404 and were never captured.

`_OIDC_ENDPOINT_KINDS` is the single table both sides read: the
discovery renderer builds the advertised URLs from it and the matcher
accepts the same suffixes, so an advertised endpoint cannot drift away
from a served one.

| Path | Methods | Response |
| --- | --- | --- |
| `…/certs` (`jwks_uri`) | GET | JWKS with three per-hit-random keys (RS256 sig, RSA-OAEP enc, ES256 EC); `oidc-certs` |
| `/.well-known/jwks.json`, `/jwks.json`, `/oauth2/certs`, `/oauth/discovery/keys` | GET | Same JWKS — the spellings a client guesses without reading the document |
| `…/auth` (`authorization_endpoint`) | GET | Keycloak login form for a client id the product ships (`oidc-auth-login-form`); the product's `Invalid parameter: client_id` page, 400, for any other (`oidc-auth-unknown-client`) |
| `…/login-actions/authenticate` | POST | Re-renders the login form; captures `username` + password digest (`oidc-login-credential-post`) |
| `…/token` (`token_endpoint`) | POST | 401 `invalid_client`; captures `client_id`, `grant_type`, `scope`, `code`, and digests of `client_secret` / `refresh_token` |
| `…/token/introspect` (`introspection_endpoint`) | POST | 401 `invalid_client`; captures the presented token digest |
| `…/revoke` (`revocation_endpoint`) | POST | 401 `invalid_client`; captures the token digest |
| `…/userinfo` (`userinfo_endpoint`) | GET | 401 + `WWW-Authenticate: Bearer … error="invalid_token"`; captures the replayed bearer digest |
| `…/clients-registrations/openid-connect` (`registration_endpoint`) | POST | 401 `invalid_token`; captures `client_name` and `redirect_uris` |
| `…/logout` (`end_session_endpoint`) | GET | 400 error page — never a redirect |
| token / introspect / revoke | GET | 405 `invalid_request`, which is what the product returns |

`…` is `/oauth`, `/oauth2`, `/idp`, `/oauth/idp`, or
`/realms/<realm>/protocol/openid-connect` (and the legacy
`/auth/realms/<realm>/…`), matching the prefixes the discovery matcher
already accepts. Bare `/certs`, `/token` and `/userinfo` are deliberately
**not** claimed — too generic to be worth the collisions, and the
advertised address already reaches the handler.

## What it logs

`oidcEndpointKind`, `oidcEndpointRealm` and `oidcEndpointMethod` on every
hit. `oidcEndpointFields` carries the plain OAuth parameters — including
`redirect_uri` and, from dynamic client registration, `redirect_uris`:
the caller's own callback infrastructure, which survives source-IP
rotation the way an out-of-band exploit callback does.

`oidcEndpointSecrets` and `oidcEndpointBearer` carry a sha256 and a
length for each credential-shaped field, never the value. The hash is
what groups the same guessed secret across sources, which is the
measurement; a readable preview is emitted only for values long enough
that a first-8/last-4 fragment stays a fragment. Below that threshold a
preview would be the whole secret, which is how most submitted passwords
would have been recorded in clear.

## Why

Answering `invalid_client` rather than accepting a credential is
deliberate: accepting anything would mean the log could not tell a guess
from a real credential, and the guess distribution is the point. A 401 or
405 also confirms the route is registered, which is what the client is
testing for — a 404 says the opposite.

The authorization endpoint splits on `client_id` because real Keycloak
does: a caller naming a client the product ships gets the login form, a
caller fuzzing client ids gets the error page. That costs no
plausibility and separates the two populations at first contact.

`post_logout_redirect_uri` is logged and never honoured. Issuing it as a
`Location` would hand out a working open redirector pointed wherever the
caller likes — a real capability, for no signal the query string does not
already give us.

Issues no canary. The discovery document that leads here already carries
one, and this surface's signal is the submitted credential and the
caller's callback address rather than a replay. Every crypto-shaped value
it emits — JWKS moduli, key ids, session codes, tab ids — is per-hit
random, because a fixed one would be a stable string in a document
scanners archive and would fingerprint every host serving the trap as the
same deployment.

Gated on the same condition as the document that advertises it, so the
IdP surface appears and disappears as a whole. A deployment with no
issuing key 404s both.
