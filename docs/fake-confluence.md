# Fake Atlassian Confluence trap (CVE-2022-26134 OGNL RCE bait)

Simulates a Confluence 7.x install and lifts the out-of-band callback
domain out of OGNL injection payloads so the same probe is correlatable
across sensors regardless of source IP.

| Path | Methods | Response |
| --- | --- | --- |
| `/pages/createpage-entervariables.action`, `/confluence/...`, `/wiki/...` | any | Confluence login HTML; `confluence-action` (or `confluence-ognl-probe` when an OGNL indicator is present) |
| `/pages/doenterpagevariables.action`, `/confluence/...`, `/wiki/...` | any | Confluence login HTML |
| `/templates/editor-preload-container` | any | Editor template HTML fragment |
| `/users/user-dark-features` | any | Plausible JSON `{ "siteFeatures": [], "userFeatures": [] }` |
| `/login.action`, `/confluence/login.action`, `/wiki/login.action` | any | Confluence login HTML with version banner |
| Any path containing `${@...}` or `%24%7B%40...` (URL-encoded OGNL) | any | Confluence login HTML; `confluence-ognl-probe` |

The version banner advertised in the login HTML and the
`X-Confluence-Request-Time` header is pinned to a build in the public
disclosure window for CVE-2022-26134, so scanners deciding whether to
ship the exploit body don't bail on a patched banner.

The handler logs:

- `result` tags (`confluence-login`, `confluence-action`,
  `confluence-ognl-probe`, `confluence-dark-features`,
  `confluence-editor-preload`, `confluence-miss`)
- `confluencePath`, `confluenceMethod`
- `confluenceHasOgnl` — true on any OGNL indicator in path / query / body
- `confluenceOastCallback` — first OAST-family hostname extracted from
  the (URL-decoded) payload (oast.me, oast.fun, interact.sh, dnslog.cn,
  burpcollaborator.net, ceye.io, requestbin.net, pipedream.net)
- `confluencePayloadPreview` — first 400 chars of `path | query | body`
  when an OGNL indicator fired (a single OGNL expression can span
  multiple KB; the preview keeps log rows compact)
- `bodyPreview` for non-exploit POSTs (form-data login attempts etc.)

No Tracebit key is required. The trap does not emit credential-shaped
values; the goal is callback extraction and follow-on payload capture.

## Why

A scanner observed in late April 2026 was probing Confluence on a single
sensor in the same day, sending URL-encoded OGNL `Runtime.exec()`
payloads embedded in the request path itself (the canonical
CVE-2022-26134 shape) plus follow-on POSTs to
`pages/createpage-entervariables.action`. The exploit body carried an
out-of-band DNS callback hostname under an Interactsh-family TLD —
`*.oast.me`. The scanner is monitoring those resolutions to confirm
vulnerable targets.

A bare 404 leaks "this is not Confluence" on the first probe and the
scanner moves on. Returning a plausible Confluence login page with a
version banner inside the disclosure window keeps the probe alive past
the fingerprint stage and produces a follow-on POST body. Lifting the
OAST hostname out of every payload and emitting it as a structured log
field gives analysis a durable cross-sensor join key — the same
attacker-issued callback subdomain (e.g.
`d7o9gl5q3g2u7gjrcdmgdpjnby6nsjaud.oast.me`) is unique per probe but
recurs across every sensor the same campaign hits, even when source
IP rotates underneath.
