# Fake GeoServer admin / OGC trap

Simulates a GeoServer 2.x install — admin UI shell, About page, and OGC
service endpoints — to absorb both banner-grab fingerprinting and the
follow-on payload that targets CVE-2024-36401 (OGC Filter property-name
evaluation → RCE).

| Path | Methods | Response |
| --- | --- | --- |
| `/geoserver`, `/geoserver/` | `GET`, `HEAD` | `302` → `/geoserver/web/` |
| `/geoserver/index.html`, `/geoserver/web/`, `/geoserver/web/<anything>` | `GET`, `HEAD` | HTML admin landing with a login form and links to About / Demo / Layer Preview / OGC capabilities |
| `/geoserver/web/.../AboutGeoServerPage` | `GET`, `HEAD`, `POST` | About-page HTML; query string + body scanned for OGNL/exploit indicators |
| `/geoserver/ows`, `/geoserver/wfs`, `/geoserver/wms`, `/geoserver/wcs`, `/geoserver/wps` | `GET`, `HEAD`, `POST` | Minimal OGC `*_Capabilities` XML; query string + body scanned for OGNL/exploit indicators |
| `/geoserver/rest/<anything>` | any | `401 Basic realm="GeoServer Realm"` |
| `/geoserver/<anything else>` | any | `404` with a `geoserver-miss` log entry |

The handler logs:

- `result` tags (`geoserver-redirect-root`, `geoserver-web-landing`,
  `geoserver-about-page`, `geoserver-ogc-wfs/wms/wcs/wps`,
  `geoserver-rest-401`, `geoserver-miss`)
- `geoserverPath` (exact request path)
- `geoserverMethod` (HTTP verb)
- `geoserverHasOgnl` (bool — query string + first 512 body bytes contain
  any of `Runtime.getRuntime`, `java.lang.Runtime`, `ProcessBuilder`,
  `exec(`, `system-properties`, `javax.naming`, `valueReference`,
  `evaluateProperty`)
- `geoserverPayloadPreview` (only present when `geoserverHasOgnl`; up to
  400 chars of `query | body-preview`)
- `bytes` (response payload length)

Reported version is pinned via the `HONEYPOT_GEOSERVER_VERSION` env var
(default `2.25.1`) so scanners that gate on a vulnerable banner before
shipping the exploit don't bail.

## Why

Two distinct scanner families consistently probe GeoServer surfaces:

1. **Banner-grab fleets** fetch `/geoserver/`, `/geoserver/web/`, and
   `/geoserver/index.html` to confirm the service is live before
   handing off to a follow-on tool.
2. **Multi-target enterprise scanners** request
   `/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage`
   — the wicket surface where CVE-2024-36401 lands. The same CVE is
   reachable via crafted `evaluateProperty` / `valueReference`
   parameters in OGC service requests (`/ows`, `/wfs`).

Returning plausible HTML and `*_Capabilities` XML keeps the probe alive
past the fingerprint stage so the payload body is captured. The
`geoserverHasOgnl` flag exists to give analysis a single bool to filter
on when triaging which probes shipped exploit content vs. just doing
liveness checks.
