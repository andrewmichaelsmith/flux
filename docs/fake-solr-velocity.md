# Fake Apache Solr admin API + Velocity-template RCE

A fake Apache Solr install: the unauthenticated admin API that recon walks,
and the two legs of CVE-2019-17558 that carry attacker-authored code.

| Path | Method | Response |
|---|---|---|
| `/solr`, `/solr/`, `/solr/index.html`, `/solr/admin[/]`, `/solr/admin/info/properties` | GET | admin-root fingerprint — `solr-admin-probe` |
| `/solr/admin/info/system` | GET | version + Lucene + JVM/system facts JSON — `solr-system-info` |
| `/solr/admin/cores` (no/`STATUS` action) | GET | `CoreStatus` listing two cores — `solr-cores-status` |
| `/solr/admin/cores?action=CREATE\|RELOAD\|UNLOAD\|RENAME\|SWAP\|MERGE` | GET | success envelope; logs `solrCoreAction` + `solrCoreName` — `solr-core-action` |
| `/solr/<core>/admin/ping` | GET | `status: OK` — `solr-ping` |
| `/solr/<core>/config` | POST | empty-success; **captures the body** (`solrConfigBodyPreview` / `…Sha256` / `…Len`) — `solr-config-post` |
| `/solr/<core>/select` with `v.template.custom` | GET/POST | empty render; **captures the Velocity template** (`solrVelocityTemplate`, `solrVelocityHasRce`) — `solr-velocity-exec` |
| `/solr/<core>/select` (plain) | GET | empty `response` — `solr-select-probe` |
| `/solr/<core>/{dataimport,replication,stream,update}` | any | empty-success — `solr-endpoint-probe` |

The `<core>` segment is attacker-chosen, so it is regex-matched. The
Velocity extractor pulls `v.template.custom` from the query string or the
POST body with form decoding, which is what a real payload needs: its
spaces arrive as `+`, its `#`/`'` as `%23`/`%27`, and a literal `+` inside a
Java expression as `%2B`. The config POST body and the Velocity template are
the only requests in the chain that carry attacker-authored content; the
recon responses are host facts, so nothing credential-shaped is emitted and
there is no issuing key to gate on.

## Why

Solr's admin API answers unauthenticated on a default install, and the
recon vocabulary (`/solr/admin/info/system?wt=json`,
`/solr/admin/cores?action=STATUS&wt=json`) is one of the most constant on
the wire, overwhelmingly from Go HTTP clients. The family 404s on a stock
server, so a scanner's walk normally ends at the fingerprint and the one
request that matters — the Velocity template — is never sent. CVE-2019-17558
turns the VelocityResponseWriter into unauthenticated RCE in two steps: a
`config` POST flips `params.resource.loader.enabled`, then a
`select?wt=velocity&v.template.custom=<vtl>` runs the template (the
`#set($x.class.forName('java.lang.Runtime'))` idiom). Answering the
fingerprint plausibly enough to draw that payload, and capturing it, is the
point.
