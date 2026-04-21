# Fake SonicWall SSL VPN endpoint

Matches three paths (exact, case-insensitive; configurable via
`HONEYPOT_SONICWALL_PATHS_CSV`):

| Path | Method | Response |
| --- | --- | --- |
| `/api/sonicos/is-sslvpn-enabled` | GET | `{"is_ssl_vpn_enabled": true, "status": {...}}` |
| `/api/sonicos/auth` | POST | SonicOS auth-success envelope with a per-request `session_id` and `tfa_required: true` |
| `/api/sonicos/tfa` | POST | SonicOS TFA-accepted envelope (same session_id shape, `tfa_required: false`) |

On POST the trap extracts `user` / `username` / `login` from the JSON
or form body and logs it alongside the full body sha + preview. The
`Cookie` header is sniffed for `swap_session=` / `SonicOS-Session=`;
presence is surfaced via `sonicwallHasAuth: true` — a signal that the
scanner already has a harvested session token.

## Why

Two overlapping behaviour patterns appeared in mid-April 2026:

- A dedicated SonicWall-precondition fleet hitting only
  `/api/sonicos/is-sslvpn-enabled` — the CVE-2024-53704 precondition
  check, stopping at the first 404.
- A broader enterprise-appliance probe running the full three-step
  sequence (`is-sslvpn-enabled` → `auth` → `tfa`) on every target.

These paths are SonicWall-specific — no legitimate client hits them.
A bare 404 yields zero intel; a plausible 200 gets the scanner to
send the next payload, which is the actual exploit try. That payload
is what `bodyPreview` + `bodySha256` capture on each hit, and what
future analysis of CVE-2024-53704 variants will read from the log.
