# Fake Microsoft RDWeb (RD Web Access) trap

Simulates the Microsoft Remote Desktop Web Access landing page, the
credential POST sink, and the post-auth resource list so password-spraying
scanners that bundle `/RDWeb/Pages/` next to other VPN / remote-access
login probes ship the credential body and any session-replay attempts
to the trap log.

| Path | Methods | Response |
| --- | --- | --- |
| `/RDWeb` | `GET`, `HEAD`, `POST` | RDWeb logon HTML (same scaffold as `/RDWeb/Pages/en-US/login.aspx`) |
| `/RDWeb/` | `GET`, `HEAD`, `POST` | Same logon HTML |
| `/RDWeb/Pages/` | `GET`, `HEAD`, `POST` | Same logon HTML |
| `/RDWeb/Pages/en-US/login.aspx` | `GET`, `HEAD` | Logon HTML with a per-request `__VIEWSTATE` placeholder; form posts back to the same path |
| `/RDWeb/Pages/en-US/login.aspx` | `POST` | Post-auth resource list HTML; `Set-Cookie: TSWAAuthHttpOnlyCookie=<per-request hex>; Path=/RDWeb; Secure; HttpOnly` |
| `/RDWeb/Pages/en-US/Default.aspx` | `GET`, `HEAD`, `POST` | Empty `RemoteApp and Desktop Connection` panel (`No resources are currently available.`) |

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
- `rdwebUsername` and `rdwebHasPassword` for `login.aspx` POSTs
  (password value is never stored — only presence). Field-name handling
  accepts both the canonical `DomainUserName` + `UserPass` form-field
  names and the lowercased / generic `username` / `password` variants
  some scanners emit.
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `__VIEWSTATE` value embedded in the login HTML and the
`TSWAAuthHttpOnlyCookie` minted on `/RDWeb/Pages/en-US/login.aspx`
POSTs are per-request `uuid4().hex` — never a fixed literal across the
fleet. The cookie name matches the real RDWeb session cookie name so
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
chain alive past the credential POST. The post-auth response is an
empty resource list, so nothing useful reaches the scanner — but the
credential POST body, body sha, and form-field name list (including
which credential rotations the scanner submits) are captured in the
trap log.
