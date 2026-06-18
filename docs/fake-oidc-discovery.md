# Fake OIDC / OAuth discovery endpoint

Simulates a Keycloak-shaped OpenID Connect / OAuth 2.0 Authorization
Server metadata document on every prefix scanners walk for IdP
discovery. The Tracebit AWS canary lands in non-standard extension
fields that credential harvesters grep for `AKIA…` literals — replay
against AWS fires the canary.

| Path | Methods | Response |
| --- | --- | --- |
| `/.well-known/openid-configuration` | any | RFC-shaped OIDC discovery JSON with embedded canary; `oidc-discovery` |
| `/.well-known/openid_configuration` (underscore typo) | any | Same JSON document |
| `/.well-known/oauth-authorization-server` | any | RFC-8414 OAuth-only metadata (drops `userinfo_endpoint`, `id_token_*`, `claims_supported`); same canary placement |
| `/oauth/.well-known/openid-configuration`, `/oauth2/.well-known/...`, `/oauth/idp/.well-known/...`, `/idp/.well-known/...`, `/auth/.well-known/...` | any | Same JSON; bare issuer reflecting host |
| `/auth/realms/<realm>/.well-known/openid-configuration` (Keycloak ≤ 16) | any | Same JSON; issuer + endpoints reflect the realm name |
| `/realms/<realm>/.well-known/openid-configuration` (Keycloak ≥ 17) | any | Same JSON; issuer + endpoints reflect the realm name |
| URL-encoded leading slash (`/%2F.well-known/...`, `/%2f.well-known/...`, `/%252F.well-known/...`) | any | Normalises to canonical, same dispatch |
| Suffix noise (`%00`, `%20`, `.txt`, `~`, `?v=1`) | any | Stripped, same dispatch |

The version advertised in the `_vendor_version` extension field is
pinned to a build inside the public-disclosure window for Keycloak
CVE-2023-6927 / CVE-2024-1132, so scanner gating on a vulnerable
banner stays satisfied.

## What the handler parses + logs

- `result` tag: `oidc-discovery`
- `oidcDiscoveryPath` — the raw request path (preserves the encoding
  variant scanners shipped)
- `oidcDiscoveryMethod` — `GET` / `HEAD` / `POST` (dynamic-client-
  registration probes use POST)
- `oidcDiscoveryRealm` — the Keycloak realm extracted from
  `/realms/<realm>/` or `/auth/realms/<realm>/` placements; empty for
  bare / `/oauth*` / `/idp/` placements
- `oidcDiscoveryKind` — `openid-configuration` or
  `oauth-authorization-server`
- `canaryTypes` — `["aws"]` when a Tracebit canary was minted for the hit
- `bytes` — response body length

## Canary placement

The OIDC / RFC-8414 schemas don't have a standard "embed a credential"
slot. Real IdPs sometimes ship `_admin_*` / `_signing_*` /
`_vendor_*` extension fields with deployment hints. The Tracebit AWS
canary lands in `_aws_metadata_signing_key_id` /
`_aws_metadata_signing_secret` / `_aws_metadata_session_token` —
non-standard but plausible, and the AKIA prefix is what
credential-harvester grep loops match on regardless of the surrounding
schema.

Every credential-shaped field is per-hit unique (a real Tracebit
canary or, on a keyless deployment, the empty string — never a fixed
literal). On a keyless deployment the trap dispatch is bypassed
entirely so the document is not served at all.

## Why

Scanners walk OIDC discovery for three independent reasons:

1. **Liveness + IdP fingerprint.** The presence of the document, the
   `issuer` value, and the supported-algorithm set are enough to gate
   the follow-on exploit between Keycloak, Auth0, Authentik, ADFS,
   Cognito, and custom builds.
2. **Endpoint discovery before credential / session replay.** The
   document advertises `token_endpoint`, `authorization_endpoint`,
   `introspection_endpoint`, `revocation_endpoint`,
   `end_session_endpoint`, `registration_endpoint`. Multi-target VPN
   credential-replay scanners use the discovery doc as a pre-probe to
   confirm a `/oauth/idp/...` deployment shape before shipping a POST
   against `/p/u/doAuthentication.do` or `/cgi/login`.
3. **Credential harvest.** Cloud-native-secret scanner families grep
   discovery JSON for `AKIA…` access-key prefixes — IdP metadata
   documents sometimes carry SDK-bootstrap hints that leaked AWS keys.
   A canary in the extension slot reaches the harvester pipeline and
   fires on AWS replay.

The path matcher covers every deployment shape (`/.well-known/`
bare, `/oauth*/`, `/oauth/idp/`, `/idp/`, `/auth/`, `/auth/realms/`,
`/realms/`) plus the noise variants scanner dictionaries enumerate
(underscore typo, RFC-8414 OAuth sibling, leading-slash URL-encoding
for WAF bypass, `%00` / `.txt` / `~` / `?v=1` extension-confusion
fuzzing).
