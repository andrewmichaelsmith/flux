# WordPress wp-login canary

Fake WordPress login page at `/wp-login.php` with per-hit unique
`_wpnonce`, plus `/wp-admin/*` redirect-to-login. Distinguishes
tools that parse the GET response (nonce-harvesting) from tools
that blind-POST credentials without the nonce.

| Path | Methods | Response |
| --- | --- | --- |
| `/wp-login.php` | `GET`, `HEAD` | WordPress 6.x login HTML with per-hit `_wpnonce` hidden field + `wordpress_test_cookie` |
| `/wp-login.php` | `POST` | `302 Location: /wp-login.php?reauth=1` (auth-failure shape) |
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
