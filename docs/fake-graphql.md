# Fake GraphQL endpoint

Simulates the canonical GraphQL surface — GraphiQL on `GET`, an
introspection responder on `POST { __schema ... }`, a credential-bait
data responder on `POST { currentUser { apiToken ... } }`, and an
auth-mutation credential-capture path on `POST mutation login(...)`.

| Path | Methods | Response |
| --- | --- | --- |
| `/graphql` | `GET`, `HEAD` | GraphiQL bootstrap HTML pointing at the requesting endpoint |
| `/graphql/` | `GET`, `HEAD` | Same |
| `/api/graphql`, `/api/graphql/`, `/graphql/api`, `/api/gql`, `/gql`, `/v1/graphql`, `/api/v1/graphql`, `/query`, `/api/query` | `GET`, `HEAD` | Same |
| any of the above | `POST` (introspection: `__schema` / `__type` / `IntrospectionQuery`) | Plausible schema JSON listing `Query`, `Mutation`, `User`, `AuthPayload`, `CreateUserInput`. `User` exposes `apiToken`, `accessToken`, `refreshToken`, `awsAccessKeyId`, `awsSecretAccessKey`, `secretKey`, `webhookSecret`. No canary issued here. |
| any of the above | `POST` (data query referencing `apiToken` / `awsAccessKeyId` / `secretKey` / `refreshToken` / `webhookSecret` / similar credential-shaped fields) | Data response with a per-hit Tracebit AWS canary in `apiToken` / `accessToken` / `awsAccessKeyId` / `awsSecretAccessKey` / `secretKey`. `refreshToken` and `webhookSecret` are per-hit synthetics — never fixed literals. |
| any of the above | `POST` (auth mutation: `login` / `signIn` / `signUp` / `register` / `createUser` / `authenticate` / `tokenAuth` / `resetPassword`) | `AuthPayload` with the canary AWS access key as `token`, captures username (string literal or `variables.username` / `email` / `login`), logs `graphqlHasPassword` without storing the value. Without `TRACEBIT_API_KEY`, returns an `Invalid credentials` error envelope and still captures the username. |
| any of the above | `POST` (other mutation) | `permission denied` error envelope |
| any of the above | `POST` (other query) | `Cannot query field on type 'Query'` error envelope |
| any of the above | `POST` (empty / unparseable) | `Syntax Error: Unexpected Name` error envelope |

All responses are `200` with `Cache-Control: no-store`. GET returns
`text/html`; POST returns `application/json`. Disabled deployments
return `404`.

Path matching is case-insensitive. Body extraction accepts
`application/json`, `application/graphql`, and `?query=` query strings.
Batched requests (a JSON array of operation envelopes) are concatenated
before classification so introspection or credential indicators in any
sub-operation are visible.

The handler logs:

- `result` tags — `graphql-playground`, `graphql-introspection`,
  `graphql-credential-canary`, `graphql-auth-canary`,
  `graphql-auth-error`, `graphql-mutation-denied`,
  `graphql-query-unknown`, `graphql-syntax-error`
- `graphqlPath` — exact request path
- `graphqlMethod` — HTTP verb
- `graphqlClassification` — `introspection` / `credential-field` /
  `auth-mutation` / `mutation` / `query` / `empty`
- `graphqlOperationName` — the JSON-body `operationName` field, when
  present
- `graphqlQueryPreview` — first 400 chars of the extracted query,
  with inline `password:"..."` literals replaced by `[REDACTED]`
- `graphqlUsername` — extracted from auth-mutation bodies; checked
  string literals (`username:"..."`, `email:"..."`, `login:"..."`)
  and the `variables` JSON object
- `graphqlHasPassword` — `True` whenever the request includes a
  `password`-shaped field; the value itself is never logged
- `canaryStatus` — `issued` / `issue-failed`
- `canaryTypes` — list of Tracebit canary types embedded in the
  response (e.g. `["aws"]` on credential-field / auth-mutation hits)
- `bytes` — response payload length

## Why

GraphQL is a modern API surface that's underrepresented in the
default honeypot trap set. Three populations gate exploit delivery
on whether the host "looks like" a GraphQL endpoint:

1. **Introspection enumerators.** A `POST { query: "query
   IntrospectionQuery { __schema { types { ... } } } }"` is the
   standard schema-discovery probe every GraphQL pentest tool
   (`graphw00f`, `inql`, `clairvoyance`) emits first. A bare 404
   leaks "no graphql here"; returning a plausible schema invites
   follow-up probes against the named types.
2. **Credential / secret scrapers.** Tools that walked an
   introspection schema then query the credential-shaped fields they
   found (`apiToken`, `awsAccessKeyId`, `secretKey`). The
   credential-field branch returns the Tracebit AWS canary as the
   field value — a replay against AWS fires Tracebit regardless of
   which field name the scraper actually scraped from.
3. **Auth-mutation brute.** The same credential-stuffing fleets that
   POST against `/RDWeb/Pages/`, `/owa/auth/logon.aspx`, and
   `/global-protect/login.esp` also walk `mutation { login(...) }`
   against any GraphQL endpoint they find. The auth-mutation branch
   captures the submitted username and a has-password flag,
   mirroring the RDWeb / OWA log shape so the broader brute-force
   triage works across surfaces.

Canary issuance only fires on the credential-field and auth-mutation
branches — introspection alone returns the schema with no canary, on
the theory that a scraper which walks the schema but never queries
the credential fields is doing pure reconnaissance and wouldn't
replay a key it never retrieved. The per-IP canary cache is shared
with every other AWS-canary-bearing trap, so a scanner fanning out
across `/graphql` + `/api/graphql` + `/v1/graphql` mints one canary,
not several.

The `refreshToken` and `webhookSecret` values are per-hit synthetic
(`secrets.token_urlsafe`) rather than fixed literals — same rule as
every other credential-shaped slot in the flux trap surface. A
hardcoded literal across the sensor fleet would fingerprint the
honeypot uniformly; per-hit randomness keeps the response identical
in shape but distinct in detail.
