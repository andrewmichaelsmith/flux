# Fake Joomla 4 public-config disclosure trap (CVE-2023-23752)

Mirrors the Joomla 4 WebService config-disclosure endpoint that an
unauthenticated scanner can hit at
`/api/index.php/v1/config/application?public=true` to harvest a site's
`configuration.php` over the API.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/api/index.php/v1/config/application` (+ trailing slash, case-insensitive) | any | When `?public=true` is present: full Joomla 4 WebService JSON envelope with `configuration.php`-shaped attributes — DB / mailer / secret / S3 storage block. When absent: `{"errors":[{"title":"Access is not permitted...","code":"401"}]}` |
| `/api/index.php/v1/config/com_users`, `/api/index.php/v1/config/com_config`, … | any | Same response shape, component slug echoed back in the JSON envelope (`"id"` and `"links.self"`) — covers per-component WebService variants scanner dictionaries enumerate |

## Result tags

- `joomla4-config-disclosure` — `?public=true` present, full
  configuration JSON served (the actual CVE-2023-23752 disclosure
  shape).
- `joomla4-config-access-denied` — `?public=true` absent, the auth-
  failure envelope served. Still high-signal: a request to this path
  at all means the scanner is gated on the CVE-2023-23752 fingerprint.

## Logged fields

Standard request metadata plus:

- `joomla4ConfigPath`, `joomla4ConfigMethod`, `joomla4ConfigComponent`
- `joomla4ConfigPublic` — boolean, whether the disclosure-trigger
  query was present
- `joomla4ConfigVersion` — the fingerprinted Joomla version string the
  body claims (env-tunable, defaults to a build inside the
  CVE-2023-23752 public-disclosure window)
- `queryPreview` (first 400 chars)

## Per-hit uniqueness

Every credential-shaped field in the disclosure response is randomised
per request:

- The AWS access key id / secret / session token in the
  `filesystem.s3.*` block come from Tracebit's per-issuance canary
  (`_aws()`) — keyless deployments leave these empty.
- The Joomla DB password (`password`), SMTP password (`smtppass`), and
  site `secret` are per-hit `_fake_db_password()` / `token_urlsafe`
  values. Never a fixed literal across the fleet.

The `dbtype`, `host`, `user`, mailer hostname and from-address are
non-credential filler — they can stay fixed.

## Why

`/api/index.php/v1/config/application?public=true` is the URL surface
for **CVE-2023-23752** — an unauthenticated information disclosure in
Joomla 4.0.0 through 4.2.7 (patched in 4.2.8 / Feb 2023). The
WebService endpoint serves the site's `configuration.php` as JSON when
the `public=true` query flag is set, with no auth header required.
Real disclosures include the DB credentials, mailer/SMTP password, the
`$secret` value used for session signing, and (in deployments using
the AWS S3 storage driver) the S3 access/secret keys.

The trap doesn't gate on the query: hitting the path at all is
already a high-signal probe, because the only thing scanners are
looking for at this URL is the CVE-2023-23752 disclosure. Returning a
plausible response on both branches (`?public=true` →
configuration JSON, otherwise → access-denied envelope) keeps the
scanner walking and ensures the disclosure-trigger path lands in our
log with a replay-fireable canary.
