# Auth.js / NextAuth credential-provider surface

Serves the `/api/auth/*` route table an Auth.js (NextAuth) deployment
exposes, including the credentials sign-in flow. Default-on via
`HONEYPOT_NEXTAUTH_ENABLED`; no branch issues a canary, so it needs no
API key and costs nothing upstream.

| Path | Method | Response | Result tag |
| --- | --- | --- | --- |
| `/api/auth/providers` | GET | Provider map (JSON) | `nextauth-providers` |
| `/api/auth/csrf` | GET | `{"csrfToken": …}` + `Set-Cookie` | `nextauth-csrf` |
| `/api/auth/session` | GET | `{}` — the unauthenticated answer | `nextauth-session` |
| `/api/auth/signin`, `/signin/<provider>` | GET | Built-in sign-in page (HTML) | `nextauth-signin-page` |
| `/api/auth/callback`, `/callback/<provider>` | GET | Sign-in page | `nextauth-callback-probe` |
| `/api/auth/signin`, `/api/auth/callback/<provider>` | POST | `302` to the error page | `nextauth-credentials` |
| `/api/auth/signout` | GET | Sign-out page (HTML) | `nextauth-signout` |
| `/api/auth/error?error=<e>` | GET | Error page, value escaped | `nextauth-error` |
| anything else under the prefix | — | 404 | — |

Both mount points are served: `/api/auth` (the framework default) and
`/auth` (the `basePath` override, which sweeps carry as its own
spelling). Every URL in a response points back at whichever prefix the
client used. Matching is case-insensitive and tolerates a trailing
slash; one optional `/<provider>` segment is accepted on `signin`,
`signout` and `callback` and nowhere else.

The credentials POST is read from both `application/x-www-form-urlencoded`
and JSON, because the framework accepts both and stuffer tooling sends
both. Usernames are taken from `username` / `email` / `user` / `login` /
`identifier`, whichever is present, and the key that matched is logged
alongside the value. **The password value is never recorded** — only
`nextauthHasPwd`.

Every credentials attempt is rejected with a `302` to
`…/error?error=CredentialsSignin`, which is what a real app does to a
wrong guess. No branch sets a session cookie. The CSRF token is a
per-request `secrets.token_hex(32)`; there are no fixed credential-shaped
literals.

Logged on every request: `nextauthOp`, `nextauthProvider`. On the
credentials POST: `nextauthUsername`, `nextauthUsernameKey`,
`nextauthHasPwd`, `nextauthCsrfSubmitted`, `nextauthCsrfKnown`,
`nextauthCallbackUrl`, `bodyPreview`. On the token-issuing routes:
`nextauthCsrfIssued`.

## Why

Credential-stuffing dictionaries that used to stop at `/wp-login.php` and
`/login` now carry the JavaScript-framework auth namespace in the same
sweep. Those paths were reaching a 404, so the sweep's PHP-era half got a
plausible answer and its modern half got nothing.

The reason this is a trap and not a path alias is that the namespace is a
small protocol. A credentials sign-in is two steps: the client must GET
`/api/auth/csrf`, read the token out of the JSON, and POST that exact
value back with the credentials — the real framework rejects a POST
without it before any credential check runs. So the token doubles as a
probe of the client. We mint one per source, remember it, and record on
the POST whether what came back is a token we actually issued.

That is a discriminator request volume cannot produce. A tool replaying a
path list POSTs with no token or an invented one. A client that fetched
the token first and echoed it implemented the flow, which is a materially
different level of effort. `nextauthCsrfKnown` separates them on a single
request. The sign-in page embeds a registered token too, so a client that
scrapes the HTML instead of calling the JSON endpoint scores as
protocol-aware — it did more work, not less. Tokens are scoped per
source, so a harvested value cannot make a different actor look
sophisticated.

The second capture is inverted, in the same way the install-wizard trap
is. Auth.js takes a `callbackUrl` and redirects to it after sign-in,
which makes it a standing open-redirect target. A `callbackUrl` pointing
off-host is not a guess about our credentials — it is a piece of the
attacker's own infrastructure, so it is logged as its own field rather
than buried in the body preview.
