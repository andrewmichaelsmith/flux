# Fake Barracuda SSL VPN

Fake Barracuda Networks SSL VPN tunnel negotiation and login portal.

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/myvpn` | GET | Tunnel negotiation response (CONNECT, ipv4/ipv6 flags) |
| `/cgi-mod/index.cgi` | GET | HTML login form |

Query parameters on `/myvpn` (e.g. `?sess=none&hdlc_framing=no&ipv4=1&ipv6=1`)
are stripped before path matching.

## Logging

- Result tags: `barracuda-vpn-tunnel`, `barracuda-vpn-login`
- Body preview captured for payload analysis

## Why

The Barracuda SSL VPN tunnel-setup endpoint (`/myvpn`) is probed by
multi-vendor VPN scanners to discover Barracuda appliances. Returning a
plausible tunnel negotiation response keeps the probe alive and captures
the scanner's full request sequence rather than a 404 dead end.
