# Fake Palo Alto GlobalProtect Gateway

Fake GlobalProtect portal and gateway responses targeting CVE-2024-3400
(CVSS 10.0, unauthenticated command injection) exploit chains.

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/global-protect/prelogin.esp` | GET | XML prelogin cookie with PAN-OS version |
| `/ssl-vpn/prelogin.esp` | GET | Same prelogin XML (alternate path) |
| `/global-protect/login.esp` | GET | HTML login form |
| `/global-protect/login.esp` | POST | XML "Invalid credential" + per-request `PHPSESSID` cookie |
| `/global-protect/getconfig.esp` | GET | XML gateway configuration listing |

Query parameters (e.g. `?tmp=tmp&clientVer=4100&clientos=Windows`) are
stripped before path matching, so the scanner's real requests match.

## Logging

- Result tags: `globalprotect-prelogin`, `globalprotect-login`, `globalprotect-getconfig`
- On POST: extracts `user` field, flags `globalprotectHasPassword`
- Body preview captured for payload analysis
- `Server: PanWeb Server/` header matches real appliance fingerprint

## Why

Multi-vendor VPN scanning fleets systematically probe GlobalProtect
endpoints alongside FortiGate, Ivanti, and Cisco AnyConnect paths.
The prelogin XML response is the first step in determining whether to
ship a CVE-2024-3400 exploit body, making it a high-value interception
point for separating passive fingerprinters from active exploit operators.
