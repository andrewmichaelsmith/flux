# Fake Check Point Mobile Access / Gaia (CVE-2024-24919)

Serves the two web surfaces a Check Point gateway exposes, and the
arbitrary-file read that vendor identification unlocks.

| Path | Method | Response | Log tag |
| --- | --- | --- | --- |
| `/sslvpn/Login/Login`, `/sslvpn/Login`, `/sslvpn/Portal/Main`, `/sslvpn/`, `/sslvpn`, `/Login/Login` | GET / HEAD | `200` Mobile Access portal login page, per-request `CPCVPN_SESSION_ID` cookie | `checkpoint-portal` |
| same | POST | `200` same page with an authentication-failed banner | `checkpoint-portal-login-post` |
| `/cgi-bin/home.tcl` | any | `200` Gaia appliance-management login page | `checkpoint-gaia-portal` |
| `/clients/MyCRL` | POST, body with no traversal | `200`, empty body | `checkpoint-crl-probe` |
| `/clients/MyCRL` | POST, body with a traversal | `200` + whatever the canary table serves for the named file | `checkpoint-read-<trap>` |
| same, file we do not furnish | | `200`, empty body | `checkpoint-read-miss` |

Path matching is exact and case-insensitive, query string stripped. Every
path list is overridable from the environment — see
[`CONFIG.md`](../CONFIG.md).

The login POST logs `checkpointUsername`, `checkpointHasPassword` and
`checkpointRealm`; the raw body is captured in `bodyPreview` the same way
every other credential sink here captures it. Read attempts log
`checkpointReadPath` (the absolute path the source asked the gateway to
read) and `checkpointReadMatchDepth`. Every line carries
`checkpointSurface`, which is `portal`, `gaia` or `read`.

## Why

**The gap was a fingerprint, not a missing vendor.** The multi-vendor
edge-appliance sweep walks one login path per vendor and keeps whichever
answers. Every other vendor in that dictionary already has a trap here —
FortiOS, SonicWall, Citrix, Ivanti, GlobalProtect, Sophos, Barracuda, F5
— so a source running the sweep got a portal from all of them and a 404
from exactly one. That asymmetry is a property of this software rather
than of any deployment it runs on, which is what makes it worth closing.

**Two surfaces, kept apart on purpose.** Mobile Access is remote access
for users; Gaia is administration of the appliance itself. A source that
asks for one and not the other is telling us which of the two it came
for, and that separation is free — it costs one extra renderer.

**The read primitive is why the portal is worth serving.** CVE-2024-24919
(CISA KEV) reads an arbitrary file through an unauthenticated POST to the
CRL-client endpoint. The traversal rides in the request *body*, so
`normalize_path` never sees it and none of the existing traversal
handling applies — the parser is the trap. Resolution then runs through
the same table the webroot and the dev-server `/@fs/` read use, so one
filename means one document on every surface, and a source that reads a
credential file walks away with a live canary rather than a page of
plausible text.

Which file a source chooses to read is the measurement. Going for the
shadow file, the cloud profile, or the VPN configuration are three
different jobs, and until this trap existed we had no surface that asked
the question.

**Misses answer, they do not 404.** A gateway whose read found no such
file still answered the request; a 404 on the endpoint says the gateway
is not there at all and ends the exchange at the first miss. The missed
filenames are recorded either way — they describe the parts of the
filesystem a scanner expects to find that we have chosen not to furnish.

Nothing credential-shaped in these responses is a fixed literal. The
session cookie is per-request, and `/etc/shadow` hashes are minted per
hit from random material — a constant hash would ship one crackable
string from every host running this software, and would be worse than
serving nothing at all. The account list is derived from the same
`/etc/passwd` body the webshell and dev-server surfaces serve, so a
source that reads both files sees one consistent host.

Master switch: `HONEYPOT_CHECKPOINT_ENABLED` (default on).
