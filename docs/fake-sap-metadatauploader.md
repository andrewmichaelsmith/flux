# Fake SAP NetWeaver Visual Composer MetadataUploader trap (CVE-2025-31324 / CVE-2017-9844 bait)

Simulates the SAP NetWeaver Visual Composer `MetadataUploader` servlet
and captures the upload body scanners attempt to drop into the J2EE
cluster apps directory.

| Path | Methods | Response |
| --- | --- | --- |
| `/developmentserver/metadatauploader` | GET, HEAD | SAP-formatted XML error envelope (`<sap:Error>METADATA_UPLOAD_NO_REQUEST</sap:Error>`); `sap-metadatauploader-probe` |
| `/developmentserver/metadatauploader` | POST | `OK: stored <filename> in /usr/sap/CE1/J00/j2ee/cluster/apps/...` plaintext receipt; `sap-metadatauploader-upload` (with multipart filename) or `sap-metadatauploader-noupload` (POST without a multipart filename, e.g. XXE) |
| Same path under `/irj/`, `/nwa/`, `/sap/` prefixes | both | Same response (Enterprise Portal / NetWeaver Administrator / SAP webroot variants) |

The `Server` header advertises `SAP NetWeaver Application Server / ABAP (7.50)`
on every response — pinned to a build inside the public-disclosure window for
CVE-2025-31324 so scanners deciding whether to ship the upload body don't
bail on a patched banner.

The handler logs:

- `result` tags (`sap-metadatauploader-probe`,
  `sap-metadatauploader-upload`, `sap-metadatauploader-noupload`)
- `sapMetadataUploaderPath`, `sapMetadataUploaderMethod`
- `sapMetadataUploaderHasMultipart`, `sapMetadataUploaderPartCount`
- `sapMetadataUploaderFieldNames`, `sapMetadataUploaderFilenames`,
  `sapMetadataUploaderPartContentTypes`
- `sapMetadataUploaderHasJspShell` — true if the body contains JSP /
  `Runtime.getRuntime()` / `ProcessBuilder` indicators
- `sapMetadataUploaderHasXxe` — true if the body contains XML external
  entity declarations (CVE-2017-9844 shape)
- `bodyPreview` (first 400 bytes of the decoded body)
- `contentType` (request `Content-Type` header, capped at 120 chars)

The full multipart body is already covered by `bodySha256`; this handler
adds the per-part fields that make payload-bearing uploads easy to
cluster across source IPs.

No Tracebit key is required. The trap does not emit credential-shaped
values; the goal is upload-payload capture and follow-on shell-fetch
visibility (the supposed shell URL the scanner then GETs still hits
flux's path classifier and lands in the access log, even though no file
actually exists).

## Why

The Visual Composer `MetadataUploader` servlet accepts unauthenticated
multipart uploads in vulnerable NetWeaver builds. Two public CVEs target
this same path:

- **CVE-2025-31324** — unauthenticated arbitrary file upload allowing
  JSP webshell drops into the J2EE cluster apps directory. Active
  in-the-wild exploitation has been observed since the public
  disclosure window opened.
- **CVE-2017-9844** — XML external entity (XXE) injection in the same
  servlet, allowing local-file read and SSRF.

Real NetWeaver returns a small SAP-formatted error envelope on bare GET
(the servlet only accepts POST in production) and a plaintext "OK:
stored …" receipt on successful POST upload. Mirroring both shapes
keeps scanners from bailing on the fingerprint and captures the upload
payload (filename, content-type, embedded JSP / XXE / cmd-injection
indicators) for triage.

Echoing the uploaded filename in the response receipt is what most
scanners look for as a "shell installed" success indicator — that's
enough for them to follow up with a GET request to the would-be shell
URL, which our access log still captures even though no file actually
exists. Sorting by `sapMetadataUploaderHasJspShell` lets analysis
separate "fingerprint" hits from "exploitation attempt" hits without
re-parsing the bodies.

The handler also sanitises the echoed filename (alphanumeric / `._-`
only, capped at 120 chars) so flux's own response body never ships
attacker-controlled tokens that downstream log/SIEM pipelines might
re-render unsafely.
