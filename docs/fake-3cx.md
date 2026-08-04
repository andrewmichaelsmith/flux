# Fake 3CX web client API trap

Serves the 3CX software-PBX browser client and its JSON authentication
API, capturing the credential pair scripted clients POST to the token
endpoint and then leaving a post-authentication surface open so the
calls they make next become observable.

| Path | Methods | Response |
| --- | --- | --- |
| `/webclient`, `/webclient/`, `/webclient/index.html`, `/webclient/login`, `/webclient/login/` | `GET`, `HEAD` | 3CX web client single-page shell carrying the build label in a `<meta name="version">` tag and the `X-3CX-Version` header |
| `/webclient/api/Login/GetAccessToken`, `/webclient/api/Login`, `/webclient/api/Login/LoginUser`, `/webclient/api/Login/GetTokenAuth`, `/webclient/api/Login/RefreshToken` | `POST` | `200` with an OAuth-shaped token envelope (`Status: AuthSuccess`, `Token.access_token`, `RefreshToken`). Captures the submitted username, password length, second-factor code and remember-me flag |
| Same login paths | `GET`, `HEAD` | `405` with `Allow: POST` and an empty body — what the real API returns for a bare probe |
| `/webclient/api/Login/GetSystemStatus`, `/webclient/api/Login/Ping`, `/webclient/api/Login/Logout`, `/webclient/api/SystemStatus`, `/webclient/api/Users`, `/webclient/api/Users/current`, `/webclient/api/Settings`, `/webclient/api/MyDevices`, `/webclient/api/Contacts`, `/webclient/api/Recordings`, `/webclient/api/Voicemails` | `GET`, `HEAD`, `POST` | `200` with a minimal `{"Status":"OK"}` JSON envelope; records whether the caller presented a bearer token |

Path matching is case-insensitive, tolerates a trailing slash, and
strips the query string before comparing. Disabled deployments and
unmatched paths return `404`.

The handler logs:

- `result` tags (`3cx-webclient-shell`, `3cx-credential-post`,
  `3cx-login-probe`, `3cx-api-probe`)
- `threecxPath`, `threecxMethod`
- `threecxUsername` — the submitted account (frequently a bare
  extension number rather than a name, which is itself a
  PBX-targeting tell)
- `threecxHasPwd` and `threecxPwdLen` — password value is never
  stored, only presence and length, so dictionary versus
  random-blob strategies stay separable
- `threecxSecurityCode` — the second-factor field. A client that
  populates it is working from harvested per-extension detail
  rather than a plain credential-stuffing list
- `threecxRememberMe`
- `threecxBodyEncoding` — `json` or `form`. The real API speaks
  JSON, so a form-encoded body identifies a client replaying a
  generic form-post template rather than one written against this
  API
- `threecxBearerPresent` — on the post-authentication surface,
  whether the caller carried a token
- `bodyPreview` (first 4096 bytes, decoded best-effort) and `bytes`

## Why

Two properties make this worth a dedicated handler rather than a path
alias on the generic web-app form trap.

The endpoint speaks JSON. Credential fields arrive as
`{"Username": …, "Password": …}` rather than form-encoded pairs, so a
form-body parser reads nothing off them and the credential material is
lost even when the request is otherwise logged. The extractor here
tries JSON first and falls back to form parsing, and records which
encoding arrived — a distinguishing signal in its own right.

A PBX credential is also a different asset class from a CMS login. It
carries outbound dial capability, which is directly monetisable through
toll fraud, so the population walking this endpoint is worth keeping
separable from generic brute traffic rather than merging into it.

The endpoint is one of a small number of unauthenticated surfaces on a
product with a well-known supply-chain compromise history, so scanner
kits carry it as a standing dictionary entry. Recurring
credential-submission volume against the token endpoint is spread
across a broad, distributed source population rather than concentrated
in a handful of hosts, which is the shape of a maintained kit rather
than one operator's sweep.

Critically, these clients POST their credential payload whether or not
the endpoint exists. A `404` therefore discards the credential material
at the exact moment it is on the wire, and guarantees the client stops
before revealing anything about its post-authentication behaviour.
Answering with a plausible token envelope captures the pair and lets
the kit proceed, which is the only way to observe what it does with a
PBX it believes it has just entered.

The bare `/api/login` sibling is deliberately **not** claimed by this
trap — it is already owned by the generic web-app form handler, and
relabelling that established population as PBX-targeting would corrupt
it.

## Canary placement

None. The token envelope's credential-shaped fields (`access_token`,
`refresh_token`, `RefreshToken`, and the JWT subject) are per-hit
synthetics minted from `secrets`, never fixed literals — a constant
token would be worthless on replay and would fingerprint every host
serving this trap with one shared string. They are not Tracebit-backed
canaries because a bearer token replayed against a PBX API has no
hosted endpoint that could fire an alert; their value is local, as the
link between an issuance event and any later request that presents the
same token.

The primary success signal for this trap is the captured username plus
`threecxBodyEncoding`, and secondarily whether any client returns with
`threecxBearerPresent` set — the first evidence that a kit parses the
envelope and continues rather than firing a fixed request list.

## Config

- `HONEYPOT_3CX_ENABLED` — master switch, defaults on.
- `HONEYPOT_3CX_VERSION` — build label in the client shell and the
  `X-3CX-Version` header, defaults to `20.0.5.2118`.
- `HONEYPOT_3CX_LOGIN_PATHS_CSV` — comma-separated exact-match set
  for the credential-bearing endpoints.
- `HONEYPOT_3CX_API_PATHS_CSV` — comma-separated exact-match set
  for the post-authentication surface.
- `HONEYPOT_3CX_BODY_DECODE_LIMIT` — bytes of a POST body decoded
  into `bodyPreview`, defaults to 4096.
