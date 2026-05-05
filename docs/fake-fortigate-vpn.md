# Fake FortiGate SSL VPN endpoint

Simulates the FortiGate / FortiOS SSL VPN login page, the credential POST
sink, and a slice of the `/api/v2/cmdb` REST surface so banner-grab probes
proceed past the fingerprint stage and follow-on exploit bodies land in the
access log.

| Path | Methods | Response |
| --- | --- | --- |
| `/remote/login` | `GET`, `HEAD`, `POST` | FortiOS login HTML scaffold posting to `/remote/logincheck`; embeds the configured FortiOS version + build banner in an HTML comment for fingerprint scrapers |
| `/remote/logincheck` | `GET`, `HEAD`, `POST` | `text/plain` `ret=1,redir=/remote/login&error=1` (auth-failure shape); `Set-Cookie: SVPNCOOKIE=<per-request hex>` |
| `/remote/fgt_lang` | `GET`, `HEAD`, `POST` | Empty JSON object — placeholder for the language pack the login page links to |
| `/remote/error` | `GET`, `HEAD`, `POST` | Plain HTML error page linking back to `/remote/login?lang=en` |
| `/api/v2/cmdb/system/admin` | `GET`, `HEAD`, `POST` | JSON `{"http_status":401,"status":"error", …}` permission-denied envelope |
| `/api/v2/cmdb/system/status` | `GET`, `HEAD`, `POST` | JSON status envelope advertising the configured FortiOS version + build, hostname, and a per-request unique `FGVM…` serial |
| `/api/v2/cmdb/system/global` | `GET`, `HEAD`, `POST` | Same shape as `/api/v2/cmdb/system/status` |
| `/api/v2/monitor/router/policy` | `GET`, `HEAD`, `POST` | JSON envelope with empty `results` list and a per-request unique serial |

All matched paths return `200` with `Cache-Control: no-store` and a
FortiOS-style `Server: xxxxxxxx-xxxxx` header. Disabled deployments (or
paths outside the configured set) return `404`.

The handler logs:

- `result` tags (`fortigate-login`, `fortigate-logincheck`,
  `fortigate-fgt-lang`, `fortigate-error`, `fortigate-cmdb-admin`,
  `fortigate-cmdb-status`, `fortigate-cmdb-global`,
  `fortigate-monitor-router-policy`)
- `fortigatePath` (exact request path)
- `fortigateMethod` (HTTP verb)
- `fortigateUsername` and `fortigateHasPassword` for `logincheck` POSTs
  (password value is never stored — only presence; both `credential` and
  `password` field names are accepted)
- `fortigateHasCmdInjection` (boolean) — flips when shell-meta indicators
  (`;`, `|`, `&&`, `$(`, backticks, `wget `, `curl `, `../`, `/bin/sh`,
  plus FortiOS-specific markers like `fgt_lang` / `param_str`) appear in
  the query string or body preview, so CVE-2024-21762 / CVE-2023-27997
  payloads are easy to triage
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `SVPNCOOKIE` minted on `/remote/logincheck` is per-request
`uuid4().hex` — never a fixed literal across the fleet — so every hit
ships a distinct cookie and replay analysis can distinguish sessions.
The `FGVM…` serial in the status / router-policy envelopes is similarly
per-request unique.

## Why

Multi-target VPN scanners started bundling FortiGate's `/remote/login`
next to Cisco AnyConnect (`/+CSCOE+/logon.html`) and Microsoft RDP Web
Access (`/RDWeb/Pages/`) probes in May 2026 — the FortiGate-specific
path was the new addition. CVE-2024-21762 (out-of-bounds write in the
SSL VPN, unauthenticated, CVSS 9.8) and CVE-2023-27997 (xortigate, heap
overflow, unauthenticated, CVSS 9.8) are both pre-auth and both target
the SSL VPN web surface, so banner-grab probes that find a plausible
FortiOS build are likely to follow up with the exploit body. CVE-2024-48887
(admin password reset on the REST `/api/v2/cmdb/system/admin` surface)
and post-auth chains via `/api/v2/monitor/router/policy` round out the
REST paths most often probed alongside the login page.

Returning the FortiOS login HTML (with the version banner in a comment
where fingerprint scrapers grep), the `ret=1` `logincheck` reply, and the
permission-denied REST envelope keeps the probe alive past the
fingerprint stage so the exploit body lands in `bodyPreview` /
`bodySha256`.
