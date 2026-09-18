# WordPress plugin upload-vector matrix

Answers the WordPress plugin upload endpoints that arbitrary-file-upload
tooling walks, and — the point of the trap — keeps the landing path each
one names consistent with the answer it gave.

| Path | Method | Landing directory |
| --- | --- | --- |
| `/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php` (and `connector.php`) | POST | `/wp-content/plugins/wp-file-manager/lib/files/` |
| `/wp-content/plugins/contact-form-7-db/img/upload.php` | POST | `/wp-content/plugins/contact-form-7-db/img/` |
| `/wp-content/plugins/backup-backup/includes/backup-heart.php` | POST | `/wp-content/uploads/` |
| `/wp-admin/admin-ajax.php?action=uploadFontIcon` | POST | `/wp-content/uploads/kaswara/fonts/` |
| `/wp-admin/admin-ajax.php?action=wpr_addons_upload_file` | POST | `/wp-content/uploads/wpr-addons/templates/` |
| `/wp-admin/admin-ajax.php?action=ecsload` | POST | `/wp-content/uploads/` |
| a claimed landing path, `.php` leaf | GET / HEAD | the acceptance decides — see below |

`admin-ajax.php` is claimed only when `action` names one of the upload
handlers. Every other use of that address — which is nearly all of it —
is left to the trap that already owns it.

## One vector is writable, not all of them

Each source is told exactly one of the vectors accepted its upload,
chosen from a per-process secret. The choice is stable for a source, so a
repeat probe gets the same answer, and it is not the same vector on every
host, so a fleet cannot be identified by which vector it accepts.

The accepted vector answers in its plugin's success idiom (an elFinder
`added[]` entry, a WordPress AJAX `{"success":true,...}` with the file's
URL, or a bare path line) and its landing path then serves the sender's
own uploaded bytes back. The refused vectors answer in their plugin's
*failure* idiom, and their landing paths stay 404 — including against the
[shell-jacking sweep gate](./webshell-sweep.md), which would otherwise
answer a `/wp-content/**.php` name on shape alone and contradict the
refusal inside the same burst.

Two of the vectors write into the same directory. When one of those is
accepted, that address stays writable whichever POST arrived first: the
file really is there, and a GET cannot tell which vector put it there.

## Logging

- `result`: `wp-plugin-upload-attempt` (POST), `wp-plugin-upload-verified`
  (GET that found its file), `wp-plugin-upload-refuted` (GET for a vector
  that was refused)
- `wpPluginUploadVector`, `wpPluginUploadAccepted`, `wpPluginUploadAction`,
  `wpPluginUploadLandingDir`, `wpPluginUploadClaims`
- `wpPluginUploadFilenames`, `wpPluginUploadFieldNames`,
  `wpPluginUploadPartContentTypes`, `wpPluginUploadPartCount`,
  `wpPluginUploadHasPhpShell`, `bodyPreview`

The attempt rows carry the payload; the verified row names the vector the
sender will escalate on. Joining the two is the measurement.

## What the landing path serves

The bytes of the first file part in the upload, not the multipart
envelope around it. A verification stub is almost always a single
`echo`/`print` of a literal — the sender greps the response for the token
it prints — so that one shape is emulated and the response is what a host
running the file would return. Anything else is served as it arrived,
which is what a host that stored the file without executing it returns.
Nothing here interprets an upload, and nothing is written to disk.

Config: `HONEYPOT_WP_PLUGIN_UPLOAD_ENABLED` (default on),
`..._TTL_SECONDS` (3600), `..._MAX_SOURCES` (4096),
`..._MAX_CLAIMS_PER_SOURCE` (32), `..._BODY_LIMIT` (8192). The last three
bound the claim registry the way the sweep gate and canary cache are
bounded; it is in memory and per-process.

## Why

Arbitrary file upload in WordPress plugins is a long-running exploit
class — the file-manager connector lineage (CVE-2020-25213) is the
best-known, and the font-icon, template and backup upload handlers are
the same shape in different plugins. Tooling that walks it does not stop
at the POST. It posts to several vectors in one burst under a single
token, then GETs that token back from each vector's landing directory,
because the POST response is not trustworthy and the GET is: a file that
reads back is a file that was written.

That verification round is the whole reason to answer carefully. A blanket
404 ends the exchange and tells the sender the host is not writable. A
blanket 200 is worse — it claims every plugin vulnerability on the host is
live at once, which no real install looks like, and one extra request
proves the responses are fabricated. Answering one vector out of several
is what a single writable plugin actually looks like.

It also closes a contradiction that a success envelope creates on its own:
telling a sender an upload succeeded and then 404ing the URL that same
response named is a tell available to anyone who follows their own link.
Here the acceptance and the landing path are the same decision, recorded
once and answered consistently for as long as the claim lives.

What that buys, in order: the payload lands in the log either way; the
sender learns which vector worked, so their next move names the plugin
they will escalate on; and they leave holding a URL they believe is a live
shell, which is a reason to come back and use it.
