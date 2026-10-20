# Generic application-log locations

Flux already answered the framework-canonical log locations — Monolog's
`storage/logs/laravel.log` and WordPress's `wp-content/debug.log`. This
family answers the **generic names**: `error_log`, `debug.log`,
`access.log`, `production.log` and their siblings, at the webroot and under
`log/` and `logs/`.

That is where a credential-dredging sweep actually asks. It does not start
from the framework's layout, and a misconfigured static-file route leaves
the file at the webroot rather than in the framework's tree — so these
spellings answered 404 while the canonical ones answered, and a sweep's
first request missed where only a later, more specific one hit.

## Routed paths

Each row is registered as the **bare leaf**; the layout walk resolves the
directory spellings (`log/`, `logs/`, `public/`, `admin/`, `var/`,
`var/log/nginx/`, …) from that one registration.

| Path | Renderer | Shape |
| --- | --- | --- |
| `/error_log`, `/error.log`, `/errors.log`, `/debug.log`, `/php_errors.log` | `render_php_error_log` | PHP error log — `[DD-Mon-YYYY HH:MM:SS UTC] PHP <level>:` lines, a fatal with a `Stack trace:` block, then a `var_dump($_ENV)` |
| `/server.log`, `/app.log`, `/application.log` | `render_php_error_log` | generic server/application log names, PHP shape (see below) |
| `/production.log`, `/development.log`, `/staging.log`, `/dev.log`, `/test.log` | `render_rails_log` | Rails logger — `I, [ts] INFO -- :` request blocks, SQL at debug level, an unrescued `Aws::S3` exception with a backtrace |
| `/access.log`, `/access_log` | `render_web_access_log` | nginx/Apache combined access log |
| `/laravel.log`, `/laravel.log.bak`, `/laravel.log.old` | `render_laravel_log` | the existing Monolog renderer, now reachable at the bare spelling |

Content-Type: `text/plain; charset=utf-8`.

## Shape follows the filename, not the path pattern

Serving a Monolog body for a path named `error_log`, or a stack trace for
`access.log`, would tell a reader this host answers **by path pattern**
rather than by what the file is — the same tell as a `wsgi.py` whose body
is a `manage.py`. So each name gets the shape its real writer produces, and
the regression tests assert the three shapes stay mutually exclusive.

The generic `server.log` / `app.log` / `application.log` names take the PHP
shape deliberately: on a host that otherwise presents a PHP stack
(`wp-config.php`, `phpinfo`, the webshell surface), a PHP error log is the
consistent answer and a Rails or Monolog body would be the mismatch.

## Where the credential sits in each shape

Each renderer leaks the way its real counterpart leaks, which is the point
— the body has to survive a reader, not just a `grep`:

- **PHP error log** — an error handler left dumping `var_dump($_ENV)` after
  a fatal, so the whole environment lands in the log. `grep AKIA` over a
  leaked `error_log` is a standard dredging step.
- **Rails log** — the logger's `filter_parameters` list covers `password`
  but almost never the AWS keys, so an `Aws::S3::Errors` failure logs the
  client options, access key included, inline.
- **Access log** — an access log holds no config, so request lines alone
  would be a weak answer. The realistic leak is that anything a client puts
  in a query string is logged verbatim: the canary rides a sync job's
  `GET /api/v1/assets/sync?aws_access_key_id=…` line.

## Logged fields

Standard request metadata plus `result` = `php-error-log`,
`rails-env-log` or `web-access-log`, and canary issuance metadata recorded
against the source IP via the shared `_get_or_issue_canary` per-IP TTL
cache.

## Per-hit uniqueness

Every credential-shaped field is per-hit: the Tracebit AWS triple is issued
per request, and the synthetic `DB_PASSWORD`, Rails `secret_key_base` and
all log-line timestamps (randomised epoch base plus jitter) are minted per
render. Two adjacent reads of the same route produce different bytes, which
the tests assert directly — a fixed literal would make them identical,
detect nothing on replay, and fingerprint every host serving it.

## Tuning

`HONEYPOT_APP_LOG_ENABLED` (default: **on**) gates the family at the single
`find_canary_trap` lookup seam, so the switch covers the layout walk too.
The flag is scoped to the generic-name expansion: `laravel-log` and
`wp-debug-log` are deliberately **not** in its set, so turning it off
restores the pre-expansion surface instead of taking the
framework-canonical routes down with it.

## Why this trap exists

A log is worth answering because of what a real one leaks. A stack trace
carries the env block, a PHP fatal carries the `var_dump`, and an access
line carries whatever the client put in a query string — so a log file sits
in credential-dredging dictionaries right next to `.env`, and for the same
reason.

Closing it also required one vocabulary fix. The layout walk knew `logs`
but not `log`, which split the family in half: `logs/error.log` resolved
while `log/error.log` 404'd, and the entire Rails tree — whose directory is
`log/` by convention, never `logs/` — was unreachable. `apache2` and
`nginx` joined for the same reason: the system log tree a sweep walks is
`/var/log/<server>/error.log`, and only the unsuffixed `apache` was listed,
so the spelling Debian and Ubuntu actually install missed while `apache`
hit.
