# Fake file-upload responder

Matches legacy PHP file-upload library probe paths (KCFinder, jquery.filer,
Blueimp jQuery-File-Upload) with arbitrary directory prefixes, then
either returns a presence-detection-friendly response (on GET) or
captures multipart bodies (on POST). Three matchers, all default-on:

| Family | Path regex (case-insensitive, prefix-tolerant) | Methods | Response |
| --- | --- | --- | --- |
| `kcfinder` | `^(?:/[^/]+)*/kcfinder/(?:upload\|browse\|kcfinder)\.php$` | `GET`, `HEAD`, `POST` | KCFinder browser HTML (carries `<input type="file" name="upload[]">`) on GET; KCFinder-shaped `/<filename>` line per part on POST |
| `jquery-filer` | `^(?:/[^/]+)*/jquery\.filer/(?:php/)?(?:upload\.php\|readme\.txt\|index\.html)$` | `GET`, `HEAD`, `POST` | Plain-text README on `/readme.txt`; `{"OK":1,"files":[]}` JSON on `/upload.php` GET; `{"OK":1,"files":[{name,size,type,file,id}, …]}` on POST |
| `blueimp-jquery-file-upload` | `^(?:/[^/]+)*/jquery-file-upload/server/php/?$` | `GET`, `HEAD`, `POST` | `{"files":[…]}` JSON (empty on GET, populated on POST) |

The prefix-tolerant regex covers the long tail of `/admin/ckeditor/plugins/`,
`/app/webroot/js/`, `/assets/plugins/`, `/core/scripts/wysiwyg/`, etc. that
file-upload-vulnerability scanners walk before hitting the leaf path —
without enumerating each one.

## Logging

The handler logs:

- `result`: `file-upload-probe` (GET / HEAD) or `file-upload-attempt` (POST)
- `fileUploadFamily`: `kcfinder` / `jquery-filer` / `blueimp-jquery-file-upload`
- `fileUploadPath`: exact request path (the prefix variant the scanner used)
- `fileUploadMethod`: `GET` / `HEAD` / `POST`
- `fileUploadHasMultipart`: bool — true when `Content-Type` is `multipart/form-data`
- `fileUploadPartCount`: number of multipart parts parsed (capped at
  `HONEYPOT_FILE_UPLOAD_MAX_PARTS`)
- `fileUploadFieldNames`: sorted, deduped multipart `name="..."` values
- `fileUploadFilenames`: multipart `filename="..."` values (empty/absent
  filenames excluded — those represent plain text fields, not uploads)
- `fileUploadPartContentTypes`: sorted, deduped per-part `Content-Type`
  header values
- `fileUploadHasPhpShell`: bool — flips when any part body contains
  `<?php`, `<?=`, `<%@`, `eval(`, `system(`, `passthru(`, `shell_exec(`,
  `proc_open(`, or a backtick. Single-pass triage flag; the full body is
  already covered by the request envelope's `bodySha256` field.
- `bodyPreview`: first ~8 KB decoded (best-effort UTF-8)

## Configuration

- `HONEYPOT_FILE_UPLOAD_ENABLED` (default: `true`) — master switch.
- `HONEYPOT_FILE_UPLOAD_BODY_DECODE_LIMIT` (default `8192`) — bytes of
  POST body to decode into `bodyPreview`.
- `HONEYPOT_FILE_UPLOAD_MAX_PARTS` (default `16`) — multipart parts
  enumerated per request. Parts past this cap aren't dropped — the body
  itself is hashed via the standard `bodySha256` envelope field — they
  just don't get per-part fields in the log row.

## Why

The webshell trap covers "is my planted shell still here" probes against
fixed filenames. This trap covers the *active exploitation* shape against
file-upload libraries that pre-date modern path-traversal sanitisation:
KCFinder (CVE-2018-15706), jquery.filer (pre-1.3.5 SDK upload bugs),
Blueimp jQuery-File-Upload (CVE-2018-9206 — `htaccess` bypass leading
to arbitrary PHP file upload). Scanners that walk these path families
post a multipart body with a `.php` filename and a `<?php` payload,
expecting the server to write it under the webroot.

Without this trap the POST 404s and the scanner walks away with nothing
logged past the path. The trap returns a plausible "uploaded OK"
envelope per family, so:

1. Field-keyed scanners (KCFinder's single-line `/<filename>` parse,
   jquery.filer's `OK: 1` JSON parse, Blueimp's `files[]` parse) accept
   the upload as complete and either fetch the (fake) uploaded file
   next — which is a `404` — or send their next payload variant.
2. Either way, the actual exploit body (filename, content-type, the
   first chunk of `<?php`-bearing source) lands in the access log
   alongside `bodySha256`. Repeated multipart bodies with matching
   sha256 across IPs cluster naturally into a single payload family
   for downstream analysis.

The handler does not write anything to disk and does not execute any
captured PHP. The multipart parser is permissive about quoting and
malformed bodies because exploit clients in the wild commonly emit
slightly off-spec multipart (mixed `\r\n` / `\n`, missing closing
boundary, etc.).
