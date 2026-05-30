# Fake Microsoft Exchange (OWA / ECP / autodiscover / PSRemoting) trap

Multi-step Exchange Server surface — Outlook Web App login, Exchange
Control Panel login, autodiscover JSON (the ProxyShell SSRF target),
the eDiscovery exporttool ClickOnce manifest, and the PowerShell
remoting endpoint. Designed to keep ProxyShell-shaped exploit chains
(CVE-2021-34473 / CVE-2021-34523 / CVE-2021-31207) alive past each
step so the trap log captures the spoofed-domain SSRF target, the
PowerShell cmdlet payload, and the OWA / ECP credential POSTs.

| Path | Methods | Response |
| --- | --- | --- |
| `/owa/` | `GET`, `HEAD` | OWA landing HTML (meta-refresh to `/owa/auth/logon.aspx`) |
| `/owa/auth/logon.aspx` | `GET`, `HEAD` | OWA login HTML with per-request `canary` hidden input; `Set-Cookie: cadata=<per-request hex>; Path=/; Secure; HttpOnly` |
| `/owa/auth/logon.aspx` | `POST` | Same HTML + cookie; logs `exchangeUsername` + `exchangeHasPassword` |
| `/owa/auth.owa` | `POST` | Treated as credential POST (same response + cookie) |
| `/owa/auth/x.js` | `GET`, `HEAD` | Minimal JS stub stamped with the configured Exchange build (`X-OWA-Version` fingerprint) |
| `/owa/auth/errorFE.aspx?httpCode=NNN` | `GET`, `HEAD` | OWA error page with the requested `httpCode` echoed in the body; code logged |
| `/ecp/` | `GET`, `HEAD`, `POST` | ECP login HTML; `Set-Cookie: msExchEcpCanary=<per-request hex>; Path=/ecp; Secure; HttpOnly` |
| `/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application` | `GET`, `HEAD` | ClickOnce `.application` XML manifest with build version stamped in `<assemblyIdentity version=…>` |
| `/autodiscover/autodiscover.json` | `GET`, `HEAD`, `POST` | Autodiscover JSON with per-request `MailboxGuid` + a per-hit `Bearer <token>` literal in `Token` |
| `/autodiscover/autodiscover.xml` | `GET`, `HEAD`, `POST` | Autodiscover XML error envelope |
| `/powershell` / `/powershell/` | any | `401` + `WWW-Authenticate: Negotiate, Kerberos, NTLM`; logs `X-Rps-CAT` presence/length and a `bodyPreview` |
| `/mapi/`, `/oab/`, `/ews/` | any | Generic XML error envelope (keeps multi-protocol scanners enumerating) |
| `/rpc/rpcproxy.dll` (any depth) | any | Empty `application/rpc` body |

All responses set `Server: Microsoft-IIS/10.0`, `X-Powered-By: ASP.NET`,
`X-AspNet-Version: 4.0.30319`, `X-FEServer: <configured-name>`,
`X-OWA-Version: <configured-build>` plus a fresh per-request `request-id`
UUID. Path matching is case-insensitive. Disabled deployments — or
paths outside the Exchange prefix set — return `404`.

The handler logs:

- `result` tags:
  - `exchange-owa-login`, `exchange-owa-credential-post`,
    `exchange-owa-landing`, `exchange-owa-bootstrap-js`,
    `exchange-owa-error`
  - `exchange-ecp-login`, `exchange-ecp-login-post`
  - `exchange-exporttool-manifest`
  - `exchange-autodiscover-json`, `exchange-autodiscover-xml`,
    `exchange-autodiscover-probe`,
    **`exchange-autodiscover-proxyshell-ssrf`** (literal `?@<spoof>` shape)
  - `exchange-powershell-pre-auth`,
    `exchange-powershell-cmdlet-attempt`
  - `exchange-mapi-probe`, `exchange-oab-probe`, `exchange-ews-probe`,
    `exchange-rpc-proxy-probe`
- `exchangePath` (raw request path)
- `exchangeMethod` (HTTP verb)
- `exchangeBuild` (the build version advertised in headers + manifest)
- `exchangeAutodiscoverSpoofTarget` — everything after the literal
  `?@` in the query string (CVE-2021-34473 attribution slot)
- `exchangeAutodiscoverEmail` — the `Email` query parameter, if any
- `exchangeUsername` and `exchangeHasPassword` for OWA / ECP POSTs.
  Password value is never stored — only presence. Accepts the OWA
  `username` / `password` form fields plus common credential-stuffing
  variants (`UserName`, `j_username`, `email`, `user`, …)
- `exchangeXRpsCatPresent` and `exchangeXRpsCatLen` — whether the
  PowerShell endpoint received an `X-Rps-CAT` header (the Kerberos
  cookie ProxyShell forwards via the autodiscover SSRF) and how long
  it was
- `exchangeHasPowershellCmdlet` — whether the PowerShell endpoint
  body matched ProxyShell-shaped cmdlet indicators
  (`New-MailboxExportRequest`, `Import-Module`, `Invoke-Command`,
  `IEX(`, `DownloadString`, …)
- `exchangeOwaErrorHttpCode` — the `httpCode` query value when
  `/owa/auth/errorFE.aspx` is probed
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The OWA `canary` hidden input, the `cadata` and `msExchEcpCanary`
cookies, the autodiscover `MailboxGuid` + `Bearer <token>` literal,
and the per-response `request-id` header are all per-request
`uuid4().hex` / `secrets.token_urlsafe()` — never a fixed literal
across the fleet. The autodiscover JSON `Token` slot is a
synthetic per-hit bearer (not a Tracebit-backed canary; Tracebit
has no Exchange-token canary type) — its job is to defeat
fleet-wide fingerprinting, not to fire on replay.

## Why

ProxyShell (CVE-2021-34473 / 34523 / 31207, CISA KEV, disclosed
2021-07) remains one of the most-abused on-prem Exchange chains.
The canonical SSRF probe shape — `GET /autodiscover/autodiscover.json?@<spoofed>.com&Email=…`
— still appears across the corpus from multiple unrelated scanner
populations. Each probe carries an attribution slot the trap can
log: the spoofed domain in the query string, the
`Email` parameter that picks the SSRF target, and the
`X-Rps-CAT` Kerberos cookie any follow-on PowerShell call would
carry.

Real Exchange deployments expose a multi-path surface — OWA + ECP +
autodiscover + PSRemoting + the eDiscovery `.application` manifest
— and scanners diff response shapes between paths to confirm the
target is genuine before sending an exploit body. Returning a
plausible response at every step (matching `Server`/`X-OWA-Version`
header triad, real ASP.NET manifest XML, a 401 + `WWW-Authenticate`
on `/PowerShell/`, plausible meta-refresh on `/owa/`) is what keeps
the chain alive long enough to capture the PowerShell cmdlet body
or the OWA credential POST.

The `/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application`
ClickOnce manifest is itself a high-signal fingerprint probe — its
`<assemblyIdentity version=…>` slot tells scanners which CVE branch
to pursue, so embedding a build number inside the ProxyShell
disclosure window invites the follow-on probes. The trap deliberately
advertises a build that is in scope for the documented CVE chains.
