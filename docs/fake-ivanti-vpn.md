# Fake Ivanti Connect Secure / Pulse Secure VPN endpoint

Simulates the Ivanti Connect Secure (formerly Pulse Secure) SSL VPN landing,
HostChecker installer assets, and the `/dana-ws/namedusers` REST surface so
banner-grab probes proceed past the fingerprint stage and follow-on exploit
bodies land in the access log.

| Path | Methods | Response |
| --- | --- | --- |
| `/dana-na/auth/url_default/welcome.cgi` | `GET`, `HEAD`, `POST` | HTML welcome page with login form pointing at `/dana-na/auth/url_default/login.cgi` |
| `/dana-na/auth/url_admin/welcome.cgi` | `GET`, `HEAD`, `POST` | Same welcome scaffold (admin variant) |
| `/dana-na/auth/welcome.cgi` | `GET`, `HEAD`, `POST` | Same welcome scaffold (alt root) |
| `/dana-na/auth/url_default/login.cgi` | `GET`, `HEAD`, `POST` | Auth-success redirect HTML; `Set-Cookie: DSID=<per-request hex>` |
| `/dana-cached/hc/HostCheckerInstaller.osx` | `GET`, `HEAD` | Mach-O magic-prefixed stub (`\xcf\xfa\xed\xfe…`) |
| `/dana-cached/hc/HostCheckerInstaller.exe` | `GET`, `HEAD` | PE magic-prefixed stub (`MZ…`) |
| `/dana-cached/hc/HostCheckerInstaller.dmg` | `GET`, `HEAD` | DMG magic-prefixed stub (`koly…`) |
| `/dana-ws/namedusers` | `GET`, `HEAD`, `POST` | JSON envelope `{"result":"success","data":{"users":[],"total":0}}` |

All matched paths return `200` with `Cache-Control: no-store`. Disabled
deployments (or paths outside the configured set) return `404`.

The handler logs:

- `result` tags (`ivanti-welcome`, `ivanti-login-post`,
  `ivanti-hostchecker-installer`, `ivanti-namedusers`)
- `ivantiPath` (exact request path)
- `ivantiMethod` (HTTP verb)
- `ivantiUsername` and `ivantiHasPassword` for login POSTs (password value
  is never stored — only presence)
- `ivantiHasCmdInjection` (boolean) — flips when shell-meta indicators
  (`;`, `|`, `&&`, `$(`, backticks, `wget `, `curl `, `../`, `/bin/sh`)
  appear in the query string or body preview, so CVE-2024-21887 payloads
  are easy to triage
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The DSID cookie minted on `login.cgi` is per-request `uuid4().hex` — never
a fixed literal across the fleet — so replay analysis can distinguish
distinct sessions and so the value carries no cross-sensor fingerprint.

## Why

Enterprise multi-target scanner dictionaries added Ivanti-shaped paths in
late April 2026, fingerprinting the
CVE-2023-46805 (auth bypass) + CVE-2024-21887 (command injection) +
CVE-2025-22457 (stack overflow, listed in CISA KEV under active
exploitation) probe chains. The early signal we see is the HostChecker
installer fetch (`/dana-cached/hc/HostCheckerInstaller.osx`) and the
welcome-page landing — both pre-exploit recon. Returning plausible HTML /
binary stubs / JSON keeps the probe alive long enough for follow-on
fetches and exploit bodies to land in the access log, where the
`ivantiHasCmdInjection` boolean separates banner-grab traffic from
attempted RCE chains targeting `/dana-ws/namedusers`.
