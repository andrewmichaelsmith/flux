# WordPress wp-login canary

Fake WordPress login page at `/wp-login.php` with per-hit unique
`_wpnonce`, plus `/wp-admin/*` redirect-to-login. Distinguishes
tools that parse the GET response (nonce-harvesting) from tools
that blind-POST credentials without the nonce.

| Path | Methods | Response |
| --- | --- | --- |
| `/wp-login.php` | `GET`, `HEAD` | WordPress 6.x login HTML with per-hit `_wpnonce` hidden field + `wordpress_test_cookie` |
| `/wp-login.php` | `POST` | `302 Location: /wp-login.php?reauth=1` (auth-failure shape) |
| `/<install>/wp-login.php` | as above | same, with every emitted address rewritten into `/<install>` |
| `/wp-admin/`, `/wp-admin/index.php`, `/wp-admin/admin.php`, `/wp-admin/profile.php`, `/wp-admin/admin-ajax.php`, `/wp-admin/install.php` | `GET` | `302 Location: /wp-login.php?redirect_to=...&reauth=1` (unauthenticated redirect) |

The handler logs:

- `wp-login-probe` (GET) — issued nonce in `wpLoginNonceIssued`
- `wp-login-credentials` (POST) — `wpLoginUsername`, `wpLoginHasPwd`,
  `wpLoginNonceSubmitted`, `wpLoginNonceMatch` (boolean: did the
  submitted nonce match one we recently issued to this IP?),
  `wpLoginTestcookiePresent` (boolean: did the request carry the
  `wordpress_test_cookie` we set on GET?), `wpLoginRedirectTo`,
  `bodyPreview`
- `wp-admin-redirect` — unauthenticated admin-path redirect

Per-IP nonce cache (TTL 3600s, max 1024 entries) correlates
GET-issued nonces with follow-up POSTs from the same source IP.

## Configuration

- `HONEYPOT_WP_LOGIN_ENABLED` (default: `true`) — master switch
- `HONEYPOT_WP_LOGIN_BODY_PREVIEW_LIMIT` (default: `400`)
- `HONEYPOT_WP_LOGIN_NONCE_CACHE_TTL` (default: `3600`)
- `HONEYPOT_WP_LOGIN_NONCE_CACHE_MAX` (default: `1024`)

## Why

WordPress credential-stuffing scanners probe `/wp-login.php` with a
repeating GET-then-POST pattern, suggesting the tool first harvests
the `_wpnonce` from the login form. Returning a realistic login page
with a per-hit nonce and checking whether the follow-up POST echoes
it separates sophisticated nonce-harvesting tools from naive
blind-POST stuffers — a behavioral distinction that existing
path-only logging cannot make.

## Install subdirectories

`<install>` is one leading segment from the dictionary the REST route
aliaser and the setup wizard already walk — `blog`, `wordpress`, `wp`,
`site`, `news`, `cms`, `press`, `old`, `test`, `dev`, `backup`,
`staging`, `new`, `web`, `main`. Matching only the webroot meant a sweep
probing a subdirectory install got the generic 404 and never reached the
credential POST, which is the sharpest signal this trap produces.

The form action, the lost-password link and the post-submit redirect are
all rewritten into the matched install, because a form served from a
subdirectory that posts back to the webroot is not a shape any
deployment produces. `wpLoginInstallPrefix` records which install
answered, so a sweep's choice of install is readable rather than
inferred.

Depth is capped at one segment deliberately. Scanners also walk
`wp-login.php` under *asset* directories — `/wp-includes/images/`,
`/wp-content/uploads/`, `/wp-admin/css/` — and those are not install
roots; a request there is a hunt for a webshell somebody else already
dropped, expecting a previously-uploaded file rather than a login form.
Answering it would assert a deployment shape no install has, so those
keep their 404.
