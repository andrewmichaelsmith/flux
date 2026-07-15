# Fake Microsoft RDWeb (RD Web Access) trap

Simulates the Microsoft Remote Desktop Web Access landing page, the
credential POST sink, and the post-auth resource list so password-spraying
scanners that bundle `/RDWeb/Pages/` next to other VPN / remote-access
login probes ship the credential body and any session-replay attempts
to the trap log.

| Path | Methods | Response |
| --- | --- | --- |
| `/RDWeb` | `GET`, `HEAD` | RDWeb logon HTML (same scaffold as `/RDWeb/Pages/en-US/login.aspx`) |
| `/RDWeb` | `POST` | Treated as credential POST: post-auth resource list HTML + `Set-Cookie: TSWAAuthHttpOnlyCookie=<per-request hex>; Path=/RDWeb; Secure; HttpOnly` |
| `/RDWeb/` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/` | `POST` | Treated as credential POST (same response + cookie as above) |
| `/RDWeb/Pages` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/Pages` | `POST` | Treated as credential POST (same response + cookie as above) |
| `/RDWeb/Pages/` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/Pages/` | `POST` | Treated as credential POST (same response + cookie as above) |
| `/RDWeb/Pages/en-US/login.aspx` | `GET`, `HEAD` | Logon HTML with a per-request `__VIEWSTATE` placeholder; form posts back to the same path |
| `/RDWeb/Pages/en-US/login.aspx` | `POST` | Post-auth resource list HTML; `Set-Cookie: TSWAAuthHttpOnlyCookie=<per-request hex>; Path=/RDWeb; Secure; HttpOnly` |
| `/RDWeb/Pages/<xx-yy>/login.aspx` | `GET`, `HEAD`, `POST` | Same behaviour as the en-US login form — any two-letter language + two-letter region tag matches (`tr-TR`, `es-ES`, `zh-CN`, `fr-FR`, …), covering the pre-built locale directories Server 2019 / 2022 RDWeb ships |
| `/RDWeb/Pages/en-US/Default.aspx` | `GET`, `HEAD`, `POST` | `RemoteApp and Desktop Connection` panel; with `TRACEBIT_API_KEY` set, advertises one `Cloud Console` tile whose `RDPFileContents` HTML comment embeds a per-hit Tracebit AWS canary (`aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`). Without an API key, falls back to `No resources are currently available.` |
| `/RDWeb/Pages/<xx-yy>/Default.aspx` | `GET`, `HEAD`, `POST` | Same behaviour + canary as the en-US default page for every locale variant |
| `/RDWeb/WebClient`, `/RDWeb/WebClient/`, `/RDWeb/WebClient/index.html` | `GET`, `HEAD`, `POST` | HTML5 Remote Desktop Web Client landing paths (Windows Server 2019 / 2022 ship the webclient alongside the classic ASP.NET login flow) — GET returns the same login HTML; POST is treated as a credential POST with cookie mint |

All matched paths return `200` with `Cache-Control: no-store`,
`Server: Microsoft-IIS/10.0`, and `X-Powered-By: ASP.NET`. Disabled
deployments (or paths outside the configured set) return `404`.

Path matching is case-insensitive — real scanners send mixed-case
variants (`/RDWeb/Pages/en-US/login.aspx`, `/rdweb/pages/en-us/login.aspx`,
…) and all route to the same handler.

The handler logs:

- `result` tags (`rdweb-login`, `rdweb-login-post`, `rdweb-default`)
- `rdwebPath` (exact request path)
- `rdwebMethod` (HTTP verb)
- `rdwebUsername` and `rdwebHasPassword` for any landing-path POST
  (short landings `/RDWeb`, `/RDWeb/`, `/RDWeb/Pages`, `/RDWeb/Pages/`,
  the classic `/RDWeb/Pages/en-US/login.aspx` handler, every locale
  variant `/RDWeb/Pages/<xx-yy>/login.aspx`, and the HTML5 web-client
  landings `/RDWeb/WebClient[/index.html]`). Password value is never
  stored — only presence. Field-name handling accepts both the
  canonical `DomainUserName` + `UserPass` form-field names and the
  lowercased / generic `username` / `password` variants some scanners
  emit.
- `canaryTypes` — list of Tracebit canary types embedded in the
  response (e.g. `["aws"]` on landing-path POSTs and on
  `Default.aspx` GETs/HEADs/POSTs when an API key is configured).
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `__VIEWSTATE` value embedded in the login HTML and the
`TSWAAuthHttpOnlyCookie` minted on landing-path POSTs are per-request
`uuid4().hex` — never a fixed literal across the fleet. The cookie name matches the real RDWeb session cookie name so
any later request replaying a captured cookie is attributable to the
issuance event in the trap log.

## Why

`/RDWeb/Pages/` is a frequent re-pivot for password spraying after
Active-Directory credential dumps and is a persistent target for
multi-IP credential-harvesting fleets even though no single CVE drives
the volume — RDWeb is rarely the initial-access vector but it's a
high-yield post-foothold target. Multi-target VPN scanners pair the
RDWeb login path with `/+CSCOE+/logon.html` (Cisco AnyConnect),
`/remote/login` (FortiGate), `/global-protect/login.esp` (Palo Alto
GlobalProtect), and Citrix Gateway probes; recent fleet telemetry
shows several actor groups bundling all five paths in a single
session.

Returning the RDWeb logon HTML (with `Server: Microsoft-IIS/10.0` so
fingerprint scrapers diff a real Server 2019 RDWeb deployment) plus a
per-request `__VIEWSTATE` and `TSWAAuthHttpOnlyCookie` keeps the probe
chain alive past the credential POST.

After a "successful" POST the resource list ships a single
`Cloud Console` RemoteApp tile whose `RDPFileContents` HTML comment
embeds a per-hit Tracebit AWS canary (access key, secret, session
token). Real RDWeb deployments occasionally leak cloud-console
bookmarks via the `PubName` / `RDPFileContents` slots, so
credential-scraping bots that walk the post-auth resource list
after a credential brute harvest the canary as if it were a careless
admin's stashed cloud key — any later replay against AWS fires
Tracebit. Without a `TRACEBIT_API_KEY` the panel falls back to the
empty `No resources are currently available.` shape so keyless
deployments still emit a plausible response. Per-IP TTL-cached
issuance (`CANARY_TRAP_CACHE_TTL_SECONDS`, default 1h) bounds
Tracebit cost under the credential-stuffing volume this trap absorbs.

The credential POST body, body sha, and form-field name list
(including which credential rotations the scanner submits) are
captured in the trap log regardless of whether a canary was minted.
