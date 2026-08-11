# Fake SonicWall SSL VPN endpoint

Matches eight paths (exact, case-insensitive; configurable via
`HONEYPOT_SONICWALL_PATHS_CSV`) — the SSL VPN portal, and the API chain
the portal leads into:

| Path | Method | Response |
| --- | --- | --- |
| `/auth.html` | GET | SonicOS Virtual Office portal HTML |
| `/sonicui/7/sslvpn-portal/` | GET | same portal HTML |
| `/sonicui/7/login/` | GET | same portal HTML |
| `/cgi-bin/welcome` | GET | same portal HTML |
| `/cgi-bin/sslvpnclient` | GET | same portal HTML |
| `/api/sonicos/is-sslvpn-enabled` | GET | `{"is_ssl_vpn_enabled": true, "status": {...}}` |
| `/api/sonicos/auth` | POST | SonicOS auth-success envelope with a per-request `session_id` and `tfa_required: true` |
| `/api/sonicos/tfa` | POST | SonicOS TFA-accepted envelope (same session_id shape, `tfa_required: false`) |

The portal responses carry a per-request `swap` session cookie (never a
fixed literal) and their login form posts to `/api/sonicos/auth`, which is
itself a trap path — so a scanner that fingerprints the portal and then
follows the form lands directly in the chain below.

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

The portal half was added later, after the API-only table was measured
against real traffic: the human-facing portal a scanner fingerprints
*before* it decides the host is a SonicWall at all was never listed, so it
answered 404 and the chain below it was only ever reached by tools that
skipped straight to the API. Recurring portal probes were arriving at
meaningful source diversity and being dropped at step 1.

These paths are SonicWall-specific — no legitimate client hits them.
A bare 404 yields zero intel; a plausible 200 gets the scanner to
send the next payload, which is the actual exploit try. That payload
is what `bodyPreview` + `bodySha256` capture on each hit, and what
future analysis of CVE-2024-53704 variants will read from the log.
