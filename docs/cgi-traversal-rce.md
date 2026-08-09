# Apache mod_cgi path-traversal RCE (CVE-2021-41773 / CVE-2021-42013)

Answers the encoded-traversal-to-shell-interpreter shape the way an
unpatched Apache 2.4.49/2.4.50 does, so the probe that tests for the bug
is followed by the request that carries the command.

| Method | Target shape | Response | Log tag |
| --- | --- | --- | --- |
| GET / HEAD / POST with no body | `/<dir>/<traversal>{2,}[usr/]bin/{sh,bash,dash,busybox}` | `500` + Apache's stock "Internal Server Error" page (`Apache/2.4.49 (Unix)` footer) | `cgi-traversal-rce-probe` |
| POST with a body | same | `200` + simulated command output | `cgi-traversal-rce-command` |

Traversal segments match `.`/`%2e`/`%252e` (one or two per segment)
separated by `/`, `%2f` or `%252f`, case-insensitively — covering the
CVE-2021-41773 single-encoded form and the CVE-2021-42013 double-encoded
bypass that defeated the 2.4.50 fix.

The handler parses the mod_cgi exploitation preamble
(`echo Content-Type: text/plain; echo; <command>`) off the body and logs
the remainder as `cgiTraversalCommand`, with `cgiTraversalPayloadUrls`
and `cgiTraversalDownloaders` lifted from it by the shared extraction
helpers. `cgiTraversalRawTarget` records the request target verbatim.

## Why

Matching runs on the **raw** request target rather than the normalised
path. `normalize_path` resolves the traversal for us, so by the time
dispatch computes `path` the request has already collapsed to `/bin/sh`
and every trace of the CVE shape is gone — the raw-target field is the
only place the signature survives, which is also why it is logged
explicitly.

The 500-then-200 asymmetry is the point. On a vulnerable server a
bodyless request execs the interpreter with no stdin, so the shell exits
before emitting CGI headers and Apache answers 500 ("End of script output
before headers"); a patched server answers 403/404. That 500 *is* the
positive vulnerability signal the scanner is looking for. Answering 404
to both requests collapses the exchange: the scanner concludes "patched"
on the first request and never sends the second one — the POST that
carries the operator's actual command and the stage-2 URL inside it.
Reproducing the asymmetry is therefore the only way to reach the
payload-bearing request at all.

Scope is deliberately narrow. Only traversals whose target is a shell
interpreter reach this handler; the same CVEs are also used to *read*
files (`.../etc/passwd`, `.../root/.aws/credentials`,
`.../var/www/html/.env`), and those keep flowing through normalisation
into the canary trap table, which already answers them with credential
material. Claiming them here would trade a replay-detectable credential
for a page of shell output.

Master switch: `HONEYPOT_CGI_TRAVERSAL_RCE_ENABLED` (default on).
