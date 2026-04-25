# Fake ColdFusion admin / component browser trap

Simulates the ColdFusion surfaces now appearing in the enterprise scanner
dictionary: public `.cfm` anchor pages, the built-in component browser, the
Administrator login, and AdminAPI CFC calls.

| Path | Methods | Response |
| --- | --- | --- |
| `/indice.cfm`, `/menu.cfm`, `/base.cfm` | `GET`, `HEAD`, `POST` | HTML page with ColdFusion generator metadata and links into `/CFIDE/componentutils/` and Administrator |
| `/CFIDE/componentutils/` and subpaths | any | HTML Component Browser page with a CFC explorer form and AdminAPI link |
| `/CFIDE/administrator/<anything>` | any | Login page on `GET`/`HEAD`; plausible Administrator dashboard on `POST` |
| `/CFIDE/adminapi/<anything>` | any | Minimal WDDX-shaped XML response with the requested `method` |

The handler logs:

- `result` tags (`coldfusion-public-cfm`, `coldfusion-componentutils`,
  `coldfusion-admin-login`, `coldfusion-admin-post`, `coldfusion-adminapi`,
  `coldfusion-miss`)
- `coldfusionPath` and `coldfusionMethod`
- `coldfusionHasAuth` when `Authorization` or `Cookie` is present
- `coldfusionHasExploit` when the path/query/body contains AdminAPI, WDDX,
  traversal, Java runtime, deserialization, JNDI, or admin-password indicators
- `coldfusionAction` from the query-string `method` parameter
- `bodyPreview` and `coldfusionPayloadPreview` for POST/exploit triage
- `bytes` response length

No Tracebit key is required. This trap does not emit credential-shaped values;
the measurement goal is enumeration count and follow-on payload capture.

## Why

The April 25 weekly novelty run called out a new ColdFusion branch in the
enterprise multi-target scanner dictionary. Fresh worker evidence showed
recurring `/CFIDE/componentutils/`, `/menu.cfm`, `/base.cfm`, and
`/indice.cfm` hits across relay and lab sensors, all sharing the same
enterprise-scanner JA4. Flux's own trap log also showed those paths currently
falling through as `not-handled`.

Returning plausible ColdFusion HTML/XML gives the scanner a reason to send
the next request. The `coldfusionHasExploit` flag gives analysis a single
filter for separating plain fingerprinting from CVE payload attempts.
