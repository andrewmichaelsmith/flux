# Fake Oracle WebLogic Admin Console

Simulates the Oracle WebLogic Server AdminServer console — the Java EE
admin panel that scanners recognise as a `/console/` deployment. Real
WebLogic AdminServer's login flow uses J2EE FORM auth
(`j_username` / `j_password`) submitted to `/console/j_security_check`
and mints an `ADMINCONSOLESESSION` cookie scoped to `/console`. The
trap replicates that flow so credential-stuffing dictionaries and
CVE-2020-14882-style RCE scanners see the response shape they expect
and continue past the first probe.

| Path | Methods | Response |
| --- | --- | --- |
| `/console` | `GET`, `HEAD` | WebLogic admin login HTML (Oracle branding + WebLogic-Version meta + form posting to `/console/j_security_check`) + per-request `ADMINCONSOLESESSION=<hex>; Path=/console; HttpOnly` cookie |
| `/console` | `POST` | Credential POST: parses `j_username` / `j_password`, re-serves login HTML with `Authentication Denied` error notice, mints fresh session cookie |
| `/console/` | `GET`, `HEAD`, `POST` | Same responses as `/console` |
| `/console/login/LoginForm.jsp` | `GET`, `HEAD`, `POST` | Same responses — case-insensitive; the ASP.NET-esque JSP path is the direct-form-fetch target |
| `/console/j_security_check` | `GET`, `HEAD` | Same login HTML (real WebLogic 302-redirects to the login form on GET here; the trap short-circuits to the form for symmetry) |
| `/console/j_security_check` | `POST` | Canonical J2EE FORM-auth submit target: captures credentials, re-serves login page with error |

Path match is case-insensitive on the exact set. Deep sub-paths under
`/console/` (asset fetches, `console.portal?_pageLabel=...`
navigation, RCE payload targets like
`/console/css/%252e%252e/consolejndi.portal`) are intentionally NOT
matched here — they overlap with other traps (URL-encoded traversal
caught elsewhere) or produce plausible-response ambiguity in the
login flow. Query string is stripped before comparison.

Response headers pin `Server: WebLogic Server <version>` (default
`14.1.1.0.0`, override via `HONEYPOT_WEBLOGIC_CONSOLE_VERSION`), the
Oracle Diagnostic-Message-Service context IDs (`X-ORACLE-DMS-ECID`,
`X-ORACLE-DMS-RID`) scanners cross-reference to confirm a WebLogic
origin, and standard cache-defeating (`Cache-Control: no-cache,
no-store, must-revalidate` + `Pragma: no-cache` + `X-Frame-Options:
SAMEORIGIN`).

The handler logs:

- `result` tags (`weblogic-console-login`, `weblogic-console-credential-post`)
- `weblogicConsolePath` (exact request path)
- `weblogicConsoleMethod` (HTTP verb, GET/HEAD only)
- `weblogicConsoleUsername` on any POST (accepts canonical
  `j_username` / `j_Username` / `j_UserName` / lowercased `username`
  / `j_user` variants — every scanner kit submits a slightly
  different case).
- `weblogicConsoleHasPwd` and `weblogicConsolePwdLen` — presence and
  length only; password bytes are never surfaced in a dedicated log
  field. (The generic `bodyPreview` field DOES include the raw POST
  body for triage, matching how the Adminer trap logs credential
  POSTs.)
- `weblogicConsoleSessionCookiePresent` — whether the request already
  had an `ADMINCONSOLESESSION` (or `JSESSIONID`) cookie, so
  post-login-simulation replay attempts are attributable.
- `bytes` (response payload length)

Configuration:

- `HONEYPOT_WEBLOGIC_CONSOLE_ENABLED` (default `true`) — master switch.
- `HONEYPOT_WEBLOGIC_CONSOLE_VERSION` — WebLogic version stamped in
  the `Server:` header and the login-page `<meta>` version tag. Defaults
  to `14.1.1.0.0` (current LTS build — scanners deciding whether to
  ship an exploit body don't bail on a "patched" banner).
- `HONEYPOT_WEBLOGIC_CONSOLE_PATHS_CSV` — override the exact-match set.
- `HONEYPOT_WEBLOGIC_CONSOLE_BODY_DECODE_LIMIT` — max bytes of POST
  body decoded into `bodyPreview` (default 4096).

## Why

`/console/` is Oracle WebLogic's AdminServer web console. When an
AdminServer is exposed to the internet it becomes a credential-stuff
target and a full RCE surface via the CVE-2020-14882 / CVE-2020-14750
auth-bypass chain, CVE-2019-2725 / CVE-2019-2729 (WLS9-async /
wls-wsat XMLDecoder deserialisation), and CVE-2023-21839 (JNDI
injection). Coordinated multi-IP scanner fleets walk `/console/`
alongside a small dictionary (`/console/payments/config.js`,
`/console/base/config.js`, URL-encoded `%2eenv` / `%2ejson` variants,
`/console.php`) — the top hit is always `/console/` itself, and it
currently 404s at flux, so the scanner moves on without stressing
the surface.

Serving the WebLogic login HTML with the exact Oracle-branded shape
(WebLogic-Version meta, `j_username` / `j_password` FORM-auth field
names, `/console/j_security_check` action, `Server: WebLogic Server
14.1.1.0.0`) turns the miss into a first-response scanners expect
to see on a real deployment — the credential POST arrives on
`/console/j_security_check`, the trap captures the submitted
username + password-presence, and mints a fresh `ADMINCONSOLESESSION`
so scanners that then walk post-auth paths keep chaining probes
into other flux handlers.

RCE payload capture for the CVE-2020-14882 chain is deferred to a
later expansion (the payload arrives on `/console/css/%252e%252e/...`
paths that overlap with other traversal traps); v1 focuses on the
credential-flow signal.
