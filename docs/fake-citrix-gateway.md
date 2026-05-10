# Fake Citrix NetScaler / Gateway portal

Simulates the Citrix Gateway / NetScaler ADC SSL VPN landing pages, the
credential POST sinks, and the Citrix XenApp / StoreFront login surface so
banner-grab probes proceed past the fingerprint stage and follow-on
exploit bodies (CitrixBleed cookie replay, Shitrix path traversal,
CVE-2022-27510 auth bypass) land in the access log.

| Path | Methods | Response |
| --- | --- | --- |
| `/vpn/index.html` | `GET`, `HEAD`, `POST` | NetScaler Gateway login HTML scaffold posting to `/cgi/login`; embeds the configured NetScaler version banner in an HTML comment for fingerprint scrapers |
| `/logon/LogonPoint/index.html` | `GET`, `HEAD`, `POST` | StoreFront LogonPoint variant of the same form scaffold (same POST action) |
| `/vpn/js/rdx/core/lang/rdx_en.json.gz` | `GET`, `HEAD`, `POST` | Tiny JSON locale stub linked from the login page |
| `/cgi/login` | `GET`, `HEAD`, `POST` | Generic auth-failure HTML; `Set-Cookie: NSC_AAAC=<per-request hex>` |
| `/p/u/doAuthentication.do` | `GET`, `HEAD`, `POST` | Same response shape as `/cgi/login` (alternate Gateway POST endpoint) |
| `/Citrix/XenApp/auth/login.aspx` | `GET`, `HEAD`, `POST` | XenApp / StoreFront login HTML; POST captures `user` + `password`-presence |

All matched paths return `200` with `Cache-Control: no-store` and a
NetScaler-style `Server: NetScaler` header. Disabled deployments (or
paths outside the configured set) return `404`.

The handler logs:

- `result` tags (`citrix-vpn-index`, `citrix-logonpoint`,
  `citrix-rdx-lang`, `citrix-cgi-login`, `citrix-doauthentication`,
  `citrix-xenapp-login`)
- `citrixGatewayPath` (exact request path)
- `citrixGatewayMethod` (HTTP verb)
- `citrixUsername` and `citrixHasPassword` for credential POSTs
  (password value is never stored — only presence). Field-name handling
  accepts both the Gateway `login` + `passwd` shape and the
  XenApp `user` + `password` shape.
- `citrixHasCmdInjection` (boolean) — flips when shell-meta indicators
  (`;`, `|`, `&&`, `$(`, backticks, `wget `, `curl `, `/bin/sh`) appear
  **or** when CVE-2019-19781 path-traversal markers (`/../`, `%2f..`,
  `..%2f`) appear in the path / query / body, so Shitrix payloads are
  easy to triage
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `NSC_AAAC` cookie minted on `/cgi/login` and `/p/u/doAuthentication.do`
is per-request `uuid4().hex` — never a fixed literal across the fleet —
so every hit ships a distinct cookie. The cookie name matches the real
NetScaler Gateway session cookie that CVE-2023-4966 ("CitrixBleed") leaks
via heap memory; any later request replaying a captured cookie value can
be linked back to the issuance event in the trap log.

## Why

Multi-target VPN scanners pair `/vpn/index.html` and
`/logon/LogonPoint/index.html` with FortiGate `/remote/login` and Cisco
`/+CSCOE+/logon.html` probes. Both Citrix paths are the canonical
NetScaler ADC / Gateway SSL VPN landing endpoints, and three pre-auth
CVEs drive the volume:

- **CVE-2019-19781 ("Shitrix")** — directory traversal in
  `/vpn/../vpns/portal/scripts/newbm.pl` leading to unauthenticated RCE.
- **CVE-2023-3519** — unauthenticated RCE via OAUTH config parsing on
  the same Gateway portal.
- **CVE-2023-4966 ("CitrixBleed")** — pre-auth memory disclosure that
  leaks `NSC_AAAC` session cookies; widely abused by ransomware actors
  (LockBit, Akira) for months after disclosure. Even fully-patched
  hosts often still receive cookie-replay attempts.

Less-common but observed in current scanner traffic:

- **CVE-2022-27510** (auth bypass, CVSS 9.8) and **CVE-2023-24486**
  (session hijacking) target the StoreFront / XenApp login at
  `/Citrix/XenApp/auth/login.aspx`. Volume is lower than the Gateway
  paths but the path appears in dedicated VPN-login dictionaries.

Returning the Gateway login HTML (with the version banner where
fingerprint scrapers grep), the `/cgi/login` redirect-on-failure body,
and the per-request `NSC_AAAC` cookie keeps the probe alive past the
fingerprint stage so the credential POST and any session-replay /
path-traversal body land in `bodyPreview` / `bodySha256`.
