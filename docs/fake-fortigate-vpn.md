# Fake FortiGate SSL VPN endpoint

Simulates the FortiGate / FortiOS SSL VPN login page, the credential POST
sink, and a slice of the `/api/v2/cmdb` REST surface so banner-grab probes
proceed past the fingerprint stage and follow-on exploit bodies land in the
access log.

| Path | Methods | Response |
| --- | --- | --- |
| `/remote/login` | `GET`, `HEAD`, `POST` | FortiOS login HTML scaffold posting to `/remote/logincheck`; embeds the configured FortiOS version + build banner in an HTML comment for fingerprint scrapers |
| `/remote/logincheck` | `GET`, `HEAD`, `POST` | `text/plain` `ret=1,redir=/remote/login&error=1` on rejection, no session cookie; `ret=1,redir=/remote/portal` plus `Set-Cookie: SVPNCOOKIE=<per-request hex>` on acceptance (see [the conversion gate](#the-conversion-gate)) |
| `/remote/portal`, `/sslvpn/portal.html` | `GET`, `HEAD`, `POST` | SSL VPN web portal — bookmark list and tunnel-mode link. Where an accepted login lands |
| `/remote/portal.css` | `GET`, `HEAD`, `POST` | Stylesheet the portal names for itself |
| `/remote/network` | `GET`, `HEAD`, `POST` | Tunnel-mode landing page the portal's most prominent link points at |
| `/remote/logout` | `GET`, `HEAD`, `POST` | Expires `SVPNCOOKIE` (`Max-Age=0`) |
| `/remote/fgt_lang` | `GET`, `HEAD`, `POST` | Empty JSON object — placeholder for the language pack the login page links to |
| `/remote/error` | `GET`, `HEAD`, `POST` | Plain HTML error page linking back to `/remote/login?lang=en` |
| `/api/v2/cmdb/system/admin` | `GET`, `HEAD`, `POST` | JSON `{"http_status":401,"status":"error", …}` permission-denied envelope |
| `/api/v2/cmdb/system/status` | `GET`, `HEAD`, `POST` | JSON status envelope advertising the configured FortiOS version + build, hostname, and a per-request unique `FGVM…` serial |
| `/api/v2/cmdb/system/global` | `GET`, `HEAD`, `POST` | Same shape as `/api/v2/cmdb/system/status` |
| `/api/v2/monitor/router/policy` | `GET`, `HEAD`, `POST` | JSON envelope with empty `results` list and a per-request unique serial |

All matched paths return `200` with `Cache-Control: no-store` and a
FortiOS-style `Server: xxxxxxxx-xxxxx` header. Disabled deployments (or
paths outside the configured set) return `404`.

The handler logs:

- `result` tags (`fortigate-login`, `fortigate-logincheck`,
  `fortigate-logincheck-accepted`, `fortigate-portal`,
  `fortigate-portal-asset`, `fortigate-network`, `fortigate-logout`,
  `fortigate-fgt-lang`, `fortigate-error`, `fortigate-cmdb-admin`,
  `fortigate-cmdb-status`, `fortigate-cmdb-global`,
  `fortigate-monitor-router-policy`)
- `fortigatePath` (exact request path)
- `fortigateMethod` (HTTP verb)
- `fortigateUsername` and `fortigateHasPassword` for `logincheck` POSTs
  (no dedicated field carries the secret value; both `credential` and
  `password` field names are accepted). Note that `bodyPreview` below is
  a raw capture of the request body and will contain the submitted
  password like any other posted payload — the structured credential
  fields are what avoid duplicating it, not the log as a whole
- `fortigateCredentialId` — SHA-256 over `username\0password`, truncated
  to 32 hex chars, on every `logincheck` POST that carries both halves
- `fortigateAttempt`, `fortigateAccepted`, and `fortigateFirstAccept`
  (only on the transition) — conversion-gate state
- `fortigatePortalHasSession` and `fortigateBookmark` on portal requests
- `fortigateHasCmdInjection` (boolean) — flips when shell-meta indicators
  (`;`, `|`, `&&`, `$(`, backticks, `wget `, `curl `, `../`, `/bin/sh`,
  plus FortiOS-specific markers like `fgt_lang` / `param_str`) appear in
  the query string or body preview, so CVE-2024-21762 / CVE-2023-27997
  payloads are easy to triage
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `SVPNCOOKIE` minted on an accepted `/remote/logincheck` is
per-request `uuid4().hex` — never a fixed literal across the fleet — so
every session is distinct and replay analysis can tell them apart. The
`FGVM…` serial in the status / router-policy envelopes is similarly
per-request unique.

## The conversion gate

`/remote/logincheck` is the busiest credential POST surface this honeypot
exposes: a handful of sources account for tens of thousands of guesses.
Rejecting all of them records the dictionary and nothing else — what an
operator does with a credential that *works* stays unobservable, because
none ever does.

So a source is allowed to find one. It accumulates attempts, and once it
crosses a threshold the credential it happens to be trying at that moment
becomes the one that authenticates — and the only one that authenticates
from that source thereafter. Every other pair keeps failing, so the run
looks like what a successful brute-force actually looks like: one hit in
a long sequence of misses, rather than a portal that waves everything
through on the first try.

The threshold is derived from the client address *and* the host being
served rather than fixed, so it differs both per source and per
deployment. A constant would mean every host running this honeypot
converts on the same attempt number — and keying on the address alone
would give one operator the same threshold on every host they hit, which
is the same fingerprint measured across hosts instead of across sources.
Per-source state is scoped the same way, so a source working through
several hostnames runs a separate brute against each.

| Env var | Default | Meaning |
| --- | --- | --- |
| `HONEYPOT_FORTIGATE_VPN_ACCEPT_ENABLED` | on | Master switch for the gate. Off ⇒ every credential is rejected, as before |
| `HONEYPOT_FORTIGATE_VPN_ACCEPT_MIN_ATTEMPTS` | `40` | Lower bound of the per-source threshold band |
| `HONEYPOT_FORTIGATE_VPN_ACCEPT_MAX_ATTEMPTS` | `160` | Upper bound of the band |
| `HONEYPOT_FORTIGATE_VPN_BRUTE_STATE_TTL_SECONDS` | `86400` | How long per-source state survives |
| `HONEYPOT_FORTIGATE_VPN_BRUTE_STATE_MAX_ENTRIES` | `4096` | Bound on the per-source state table |

Per-source state is in-process, so it resets when the service restarts
and is not shared between hosts. That is deliberate: it costs nothing
upstream, and a source that reconverts after a restart simply finds a
different credential.

`fortigateCredentialId` is what makes the gate measurable beyond a single
host. It is a hash of the submitted pair, logged on every attempt, so
analysis can ask whether the credential one source was allowed to find
later turns up from a *different* source — the remote-access equivalent
of watching a planted cloud credential move between the host that
harvests it and the host that spends it. A brute-forcer that hands its
hits to a separate consumer looks different in that join from one that
uses what it finds itself.

## Why

Multi-target VPN scanners started bundling FortiGate's `/remote/login`
next to Cisco AnyConnect (`/+CSCOE+/logon.html`) and Microsoft RDP Web
Access (`/RDWeb/Pages/`) probes in May 2026 — the FortiGate-specific
path was the new addition. CVE-2024-21762 (out-of-bounds write in the
SSL VPN, unauthenticated, CVSS 9.8) and CVE-2023-27997 (xortigate, heap
overflow, unauthenticated, CVSS 9.8) are both pre-auth and both target
the SSL VPN web surface, so banner-grab probes that find a plausible
FortiOS build are likely to follow up with the exploit body. CVE-2024-48887
(admin password reset on the REST `/api/v2/cmdb/system/admin` surface)
and post-auth chains via `/api/v2/monitor/router/policy` round out the
REST paths most often probed alongside the login page.

Returning the FortiOS login HTML (with the version banner in a comment
where fingerprint scrapers grep), the `logincheck` reply, and the
permission-denied REST envelope keeps the probe alive past the
fingerprint stage so the exploit body lands in `bodyPreview` /
`bodySha256`.

Credential-stuffing against this surface is a separate population from
the exploit traffic, and a much larger one by request count. The gate
exists for that population: pre-auth CVEs tell us what a scanner will
throw at an appliance, but only a session that opens tells us what an
operator wants from one once they are inside.
