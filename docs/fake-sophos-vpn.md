# Fake Sophos XG Firewall SSL VPN

Fake Sophos XG Firewall SSL VPN login portal targeting CVE-2022-1040
(auth bypass, CVSS 9.8) reconnaissance.

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/svpn/index.cgi` | GET | HTML login form |
| `/svpn/index.cgi` | POST | Same login form (captures credentials) |
| `/userportal/webpages/myaccount/login.jsp` | GET/POST | HTML login form |
| `/userportal/` | GET/POST | HTML login form |
| `/userportal/webpages/` | GET/POST | HTML login form |

## Logging

- Result tag: `sophos-vpn-login`
- On POST: extracts `username` field, flags `sophosHasPassword`
- Per-request `JSESSIONID` cookie (never a fixed literal)
- Body preview captured for payload analysis

## Why

VPN endpoint discovery scanners include Sophos paths in their
multi-vendor sweep alongside GlobalProtect, FortiGate, and Ivanti probes.
Returning a plausible login portal captures whether scanners attempt
credential brute-force after confirming the appliance type.
