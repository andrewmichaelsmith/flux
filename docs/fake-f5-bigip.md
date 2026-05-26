# Fake F5 BIG-IP APM / TMUI

Fake F5 BIG-IP Access Policy Manager and Traffic Management UI responses
targeting CVE-2020-5902 (TMUI RCE, CVSS 10.0), CVE-2023-46747 (auth
bypass, CVSS 9.8), and CVE-2022-1388 (iControl REST RCE, CVSS 9.8).

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/my.policy` | GET | APM access policy login form + per-request `MRHSession` cookie |
| `/my.policy` | POST | Same form (captures credentials) |
| `/tmui/login.jsp` | GET | TMUI Configuration Utility login form |
| `/tmui/*` (prefix) | GET | TMUI login form (catches path-traversal variants) |
| `/sslvpnclient` | GET | XML VPN client negotiation response |

The `/tmui/` prefix match catches CVE-2020-5902 path-traversal payloads
like `/tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp`. The
`f5HasPathTraversal` flag fires when `/../` or `%2e%2e` appears in the
request path.

## Logging

- Result tags: `f5-bigip-apm-policy`, `f5-bigip-tmui`, `f5-sslvpnclient`
- On POST: extracts `username`/`user` field, flags `f5HasPassword`
- `f5HasPathTraversal` flag for CVE-2020-5902 detection
- Per-request `MRHSession` cookie on `/my.policy` (never fixed)
- `Server: BigIP` header matches real appliance fingerprint

## Why

F5 BIG-IP is a high-value target in enterprise VPN scanning dictionaries.
The `/my.policy` endpoint and TMUI management console are consistently
probed by multi-vendor VPN fingerprinting fleets. Path-traversal attempts
against `/tmui/` are a direct CVE-2020-5902 exploit signal that the
generic 404 response would silently drop.
