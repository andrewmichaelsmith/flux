# Fake Microsoft RDWeb (RD Web Access) trap

Simulates the Microsoft Remote Desktop Web Access landing page, the
credential POST sink, and the post-auth resource list so password-spraying
scanners that bundle `/RDWeb/Pages/` next to other VPN / remote-access
login probes ship the credential body and any session-replay attempts
to the trap log.

| Path | Methods | Response |
| --- | --- | --- |
| `/RDWeb` | `GET`, `HEAD` | RDWeb logon HTML (same scaffold as `/RDWeb/Pages/en-US/login.aspx`) |
| `/RDWeb` | `POST` | Credential POST through the conversion gate: rejected ⇒ logon HTML with the error block and no session; accepted ⇒ post-auth resource list + `Set-Cookie: TSWAAuthHttpOnlyCookie=<per-request hex>; Path=/RDWeb; Secure; HttpOnly` |
| `/RDWeb/` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/` | `POST` | Credential POST through the gate (same two outcomes as above) |
| `/RDWeb/Pages` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/Pages` | `POST` | Credential POST through the gate (same two outcomes as above) |
| `/RDWeb/Pages/` | `GET`, `HEAD` | Same logon HTML |
| `/RDWeb/Pages/` | `POST` | Credential POST through the gate (same two outcomes as above) |
| `/RDWeb/Pages/en-US/login.aspx` | `GET`, `HEAD` | Logon HTML with a per-request `__VIEWSTATE` placeholder; form posts back to the same path |
| `/RDWeb/Pages/en-US/login.aspx` | `POST` | Credential POST through the gate (same two outcomes as above) |
| `/RDWeb/Pages/<xx-yy>/login.aspx` | `GET`, `HEAD`, `POST` | Same behaviour as the en-US login form — any two-letter language + two-letter region tag matches (`tr-TR`, `es-ES`, `zh-CN`, `fr-FR`, …), covering the pre-built locale directories Server 2019 / 2022 RDWeb ships |
| `/RDWeb/Pages/en-US/Default.aspx` | `GET`, `HEAD`, `POST` | `RemoteApp and Desktop Connection` panel; with `TRACEBIT_API_KEY` set, advertises one `Cloud Console` tile whose `RDPFileContents` HTML comment embeds a per-hit Tracebit AWS canary (`aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`). Without an API key, falls back to `No resources are currently available.` |
| `/RDWeb/Pages/<xx-yy>/Default.aspx` | `GET`, `HEAD`, `POST` | Same behaviour + canary as the en-US default page for every locale variant |
| `/RDWeb/WebClient`, `/RDWeb/WebClient/`, `/RDWeb/WebClient/index.html` | `GET`, `HEAD`, `POST` | HTML5 Remote Desktop Web Client landing paths (Windows Server 2019 / 2022 ship the webclient alongside the classic ASP.NET login flow) — GET returns the same login HTML; POST runs the gate |

All matched paths return `200` with `Cache-Control: no-store`,
`Server: Microsoft-IIS/10.0`, and `X-Powered-By: ASP.NET`. Disabled
deployments (or paths outside the configured set) return `404`.

Path matching is case-insensitive — real scanners send mixed-case
variants (`/RDWeb/Pages/en-US/login.aspx`, `/rdweb/pages/en-us/login.aspx`,
…) and all route to the same handler.

The handler logs:

- `result` tags (`rdweb-login`, `rdweb-login-post` for a rejected
  credential, `rdweb-login-post-accepted` for one the gate accepted,
  `rdweb-default`, `rdweb-asset`)
- `rdwebPath` (exact request path)
- `rdwebMethod` (HTTP verb)
- `rdwebUsername` and `rdwebHasPassword` for any landing-path POST
  (short landings `/RDWeb`, `/RDWeb/`, `/RDWeb/Pages`, `/RDWeb/Pages/`,
  the classic `/RDWeb/Pages/en-US/login.aspx` handler, every locale
  variant `/RDWeb/Pages/<xx-yy>/login.aspx`, and the HTML5 web-client
  landings `/RDWeb/WebClient[/index.html]`). Password value is never
  stored — only presence. Field-name handling accepts both the
  canonical `DomainUserName` + `UserPass` form-field names and the
  lowercased / generic `username` / `password` variants some scanners
  emit.
- `rdwebCredentialId` — a hash of the submitted `(username, password)`
  pair, logged on every attempt. The secret value never reaches a
  structured field; this stands in for it. The same hash is produced by
  the other credential sinks for the same pair, so one dictionary walked
  across several surfaces is a measurable claim rather than an
  impression.
- `rdwebAttempt`, `rdwebAccepted`, and `rdwebFirstAccept` (once) —
  conversion-gate bookkeeping, present while the gate is enabled.
- `canaryTypes` — list of Tracebit canary types embedded in the
  response (e.g. `["aws"]` on an accepted credential POST and on
  `Default.aspx` GETs/HEADs/POSTs when an API key is configured). A
  rejected guess mints nothing.
- `bodyPreview` (first 400 bytes, decoded best-effort)
- `bytes` (response payload length)

The `__VIEWSTATE` value embedded in the login HTML and the
`TSWAAuthHttpOnlyCookie` minted on an accepted credential are per-request
`uuid4().hex` — never a fixed literal across the fleet. The cookie name matches the real RDWeb session cookie name so
any later request replaying a captured cookie is attributable to the
issuance event in the trap log.

## The conversion gate

This is the busiest credential POST surface the honeypot exposes:
password-spraying sources work through hundreds of guesses in a day,
walking a password list per account name across several generic service
account names. Until the
gate landed, every one of those guesses was answered with the post-auth
resource list — the mirror image of the failure the
[VPN sink's gate](./fake-fortigate-vpn.md#the-conversion-gate) was built
for. A sink that accepts everything has three problems: what an operator
does with a credential that *works* stays unobservable, because there is
nothing to distinguish; an upstream canary is spent on every guess, for
a population that in practice never comes back for the resource list;
and "every password is correct" is a tell to any client that submits two
passwords for one account.

So a source is allowed to find one. It accumulates attempts, each
rejected with the logon page and the error block a real deployment
renders above the form, and once it crosses a threshold the credential it
happens to be trying at that moment becomes the one that authenticates —
and the only one that authenticates from that source thereafter. The run
then looks like what a successful brute-force actually looks like: one
hit in a long sequence of misses.

A rejection carries no `TSWAAuthHttpOnlyCookie` and no canary. Shipping a
session alongside an error body told a client keying on the cookie that
every guess had succeeded while a client keying on the body read every
guess as failed, which is not a shape a real server produces.

The threshold is derived from the client address, the host being served,
and the surface, rather than fixed. A constant would mean every host
running this honeypot converts on the same attempt number; keying on the
address alone would give one operator the same threshold on every host
they hit; and keying without the surface would mean a source working both
this sink and the VPN sink on one host finds them both give way on the
same attempt. Per-source state is scoped per (source, host) and held
separately from the VPN sink's, so guesses spent on one surface do not
advance the other's count.

| Env var | Default | Meaning |
| --- | --- | --- |
| `HONEYPOT_RDWEB_ACCEPT_ENABLED` | on | Master switch for the gate. Off ⇒ every credential is rejected |
| `HONEYPOT_RDWEB_ACCEPT_MIN_ATTEMPTS` | `60` | Lower bound of the per-source threshold band |
| `HONEYPOT_RDWEB_ACCEPT_MAX_ATTEMPTS` | `240` | Upper bound of the band |
| `HONEYPOT_RDWEB_BRUTE_STATE_TTL_SECONDS` | `86400` | How long per-source state survives |
| `HONEYPOT_RDWEB_BRUTE_STATE_MAX_ENTRIES` | `4096` | Bound on the per-source state table |

The band is wider than the VPN sink's because per-source volume here is
heavier. Per-source state is in-process, so it resets when the service
restarts and is not shared between hosts; a source that reconverts after
a restart simply finds a different credential.

## Why

`/RDWeb/Pages/` is a frequent re-pivot for password spraying after
Active-Directory credential dumps and is a persistent target for
multi-IP credential-harvesting fleets even though no single CVE drives
the volume — RDWeb is rarely the initial-access vector but it's a
high-yield post-foothold target. Multi-target VPN scanners pair the
RDWeb login path with `/+CSCOE+/logon.html` (Cisco AnyConnect),
`/remote/login` (FortiGate), `/global-protect/login.esp` (Palo Alto
GlobalProtect), and Citrix Gateway probes; recent fleet telemetry
shows several actor groups bundling all five paths in a single
session.

Returning the RDWeb logon HTML (with `Server: Microsoft-IIS/10.0` so
fingerprint scrapers diff a real Server 2019 RDWeb deployment) plus a
per-request `__VIEWSTATE` keeps the probe chain alive past the
credential POST, and the error block on a rejected guess keeps it alive
without claiming the guess worked.

On the credential the gate accepts, the resource list ships a single
`Cloud Console` RemoteApp tile whose `RDPFileContents` HTML comment
embeds a per-hit Tracebit AWS canary (access key, secret, session
token). Real RDWeb deployments occasionally leak cloud-console
bookmarks via the `PubName` / `RDPFileContents` slots, so a client that
walks the post-auth resource list after finding a credential harvests
the canary as if it were a careless admin's stashed cloud key — any
later replay against AWS fires Tracebit. Issuing on acceptance rather
than on every guess is also what makes the issuance meaningful: a key
handed to a source that has not found anything is a key nobody has a
reason to spend. Without a `TRACEBIT_API_KEY` the panel falls back to
the empty `No resources are currently available.` shape so keyless
deployments still emit a plausible response. Per-IP TTL-cached issuance
(`CANARY_TRAP_CACHE_TTL_SECONDS`, default 1h) bounds Tracebit cost on
top of that.

The credential POST body, body sha, and form-field name list
(including which credential rotations the scanner submits) are
captured in the trap log regardless of whether a canary was minted.
