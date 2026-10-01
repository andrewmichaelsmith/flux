# Analytics-dashboard pre-auth setup chain

Imitates the unauthenticated first-run setup surface of a widely deployed
open-source BI dashboard, whose published pre-auth RCE chain
([CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646), CVSS
9.8, CISA KEV) turns one JSON field into remote code execution.

| Path | Method | Response | Result tag |
|---|---|---|---|
| `/api/session/properties` | GET, HEAD | `200` settings JSON with a per-address `setup-token` | `metabase-session-properties` |
| `/api/session/properties` | other | `405` + `Allow: GET, HEAD` | `metabase-session-properties-method-not-allowed` |
| `/api/setup/validate` | POST | `400` rejected-connection JSON | `metabase-setup-validate` / `-foreign` / `-untokened` |
| `/api/setup` | POST | `400` invalid-token JSON | `metabase-setup-admin` / `-foreign` / `-untokened` |
| `/api/session` | POST | `401` bad-password JSON | `metabase-session-login` |
| any of the above | non-POST | `405` + `Allow: POST` | `metabase-setup-method-not-allowed` |

The chain is two steps, and the second is the one worth having. Step one
returns a `setup-token` alongside `has-user-setup: false`; a client that
reads a null token concludes the host is already provisioned and moves on,
so answering with a token is what elects this server into the rest of the
exchange. Step two posts that token back wrapped around an H2 JDBC URL
whose `INIT=RUNSCRIPT FROM '<url>'` clause makes the server fetch and
execute SQL from an address the caller chooses.

The handler parses both the nested (`details.details.db`) and flat body
shapes, and logs `metabaseInitScriptUrl` (the URL inside the `RUNSCRIPT`
clause), `metabaseJdbcDb`, `metabaseEngine` and `metabaseJdbcMode`. On the
setup-completion route it logs the administrator a caller tries to plant —
`metabaseAdminEmail`, `metabaseAdminSiteName`, `metabaseAdminHasPassword`
and a `metabaseAdminCredentialId` hash of the pair. Passwords are never
logged, only whether one was sent and the hash.

Token provenance is split into separate result tags rather than a boolean
suffix on one. The token is an HMAC of the calling address under a
per-process secret, so `metabase-setup-validate` means the caller read the
document from this address, `-foreign` means it brought a token this
process minted for somebody else, and `-untokened` means it posted none.
A `-foreign` row is the interesting one: it says the read and the write
came from different hosts.

Responses mirror what the real server returns for a rejected token — a
`400` naming the field. That is not a courtesy. A caller that gets an
unexpected success stops, and the next thing worth having from this
population is the retry with a different payload host.

Nothing credential-shaped is fixed: the setup token is derived per calling
address from a secret minted at process start, so it is unique per sensor,
per address and per restart.

## Why

The properties address draws sustained, long-running probe volume, and the
setup routes behind it are probed too — so the second step of the chain is
being attempted against hosts that answer the first. Before this trap both
addresses `404`ed, which ends the exchange before any body is read: the
request that carries the operator's own payload-hosting URL was the one
thing not being recorded.

The population asking for it is not a research scanner. Alongside these
reads it redeems credentials from the canary file table and drives
command-injection, container-exec and PHP eval-stdin chains, which is the
inverse of the self-identifying crawlers whose path families were
deliberately left unanswered. A share of it carries a browser user-agent
with the platform token stripped out — a forged string, not a real client.
