# Web-app form responder

Returns plausible HTML form responses on common web-app form paths
(`/login`, `/signup`, `/checkout`, `/contact`, `/profile`, …) so
credential-stuffing and form-fuzzing scanners walk through their
rotation and the POST bodies they submit land in the access log.

| Path group | Methods | Response |
| --- | --- | --- |
| login (`/login`, `/signin`, `/auth/login`, `/admin/login`, `/api/login`, `/account/login`, …) | `GET`, `HEAD`, `POST` | HTML sign-in form on GET; `302 Location: <path>?error=1` on POST (auth-failure shape). `Set-Cookie: session_id=<per-request>` on POST. |
| signup (`/signup`, `/sign_up`, `/register`, `/auth/register`, …) | `GET`, `HEAD`, `POST` | HTML sign-up form (email + username + password) on GET; same 302 on POST. |
| checkout (`/checkout`, `/cart`, `/order/checkout`, …) | `GET`, `HEAD`, `POST` | HTML checkout form (email + username + password) on GET; same 302 on POST. |
| contact (`/contact`, `/contact-us`, `/api/contact`, `/subscribe`, `/newsletter`, …) | `GET`, `HEAD`, `POST` | HTML contact form (email + username + message + password) on GET; same 302 on POST. |
| profile (`/profile`, `/dashboard`, `/settings`, `/admin`, `/api/profile`, …) | `GET`, `HEAD`, `POST` | HTML account-settings form on GET; same 302 on POST. |

All HTML bodies post back to the same path so the scanner's next
request lands the credential POST on the same handler. Field `name`
attributes match the most common shapes seen in the wild
(`username`, `email`, `password`) so naive scanners bind without
needing to inspect the markup.

The handler logs:

- `result` tags by group: `webapp-form-login`, `webapp-form-signup`,
  `webapp-form-checkout`, `webapp-form-contact`, `webapp-form-profile`,
  plus `webapp-form-form` for any operator-supplied extra paths.
- `webappFormPath` (exact request path)
- `webappFormMethod` (`GET` / `HEAD` / `POST`)
- `webappFormSuffix` (one of the group names above)
- For POST: `webappFormUsername`, `webappFormHasPassword`,
  `webappFormHasEmail`, `webappFormFieldNames` (sorted, capped at 32
  names — useful for fingerprinting tooling that uses non-default
  field names like `user_email`, `credential`, `pwd`)
- `webappFormHadInboundSession` (boolean) — flips when the request
  carried our previously-issued `session_id` cookie, so multi-step
  scanner sessions are easy to thread together
- `bodyPreview` (first 400 bytes, decoded best-effort) on POST
- `bodySha256` (already part of the standard log envelope) — the
  full body hash, useful for clustering reused payload templates
  across IPs

The hidden `csrf_token` rendered into the form and the `session_id`
set on POST responses are both per-request `uuid4().hex` — never a
fixed literal across the fleet. Scanners that scrape the token off a
GET and submit it back on POST end up with a unique pair per session,
which makes session-replay analysis tractable.

## Configuration

- `HONEYPOT_WEBAPP_FORM_ENABLED` (default: `true`) — master switch.
- `HONEYPOT_WEBAPP_FORM_EXTRA_PATHS_CSV` (default empty) — additional
  paths to claim, mapped to the generic `webapp-form-form` result tag.
  Use when an operator wants to extend the path set without losing
  the per-group classification of the built-ins.
- `HONEYPOT_WEBAPP_FORM_BODY_PREVIEW_LIMIT` (default `400`) — bytes
  of POST body to decode into `bodyPreview`. The full body is always
  hashed via the standard `bodySha256` envelope field regardless.

## Why

Multi-operator scanner fleets started bursting POSTs against generic
web-app form paths in May 2026 — `/login`, `/signin`, `/signup`,
`/checkout`, `/contact`, `/dashboard`, `/profile`, `/auth`,
`/subscribe`, `/newsletter`, `/cart`, `/register`, `/settings`,
`/admin` — alongside the usual `.env` and `.git/*` probes. The POST
bodies are HTML form-encoded and unique per request (no fixed payload
template), consistent with credential-stuffing or form-fuzzing
tooling cycling through a credential list. Stock flux 404s every one
of those paths and the scanner walks away with nothing useful logged
beyond the path itself.

Returning a plausible HTML form on GET (with hidden CSRF + a session
cookie so a follow-on POST looks credible to the scanner) and a 302
redirect on POST (most credential-stuffing tools interpret a redirect
back to the form as "wrong password, try the next pair") is the
cheapest way to elicit the rest of the credential rotation. The
captured POST bodies — username/email + the field-name list + the
sha256 — feed clustering downstream, and the per-request `session_id`
gives us a thread-id when the same scanner bounces between paths.

This trap pairs naturally with the existing canary file traps
(`/wp-config.php`, `/.git/*`, `/.aws/credentials`, …): together they
cover the credential-discovery → credential-submission half of a
typical credential-harvest chain.
