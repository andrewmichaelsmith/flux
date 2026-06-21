# `storage/logs/laravel.log` canary trap

Flux serves a Monolog-shaped Laravel debug log on `/storage/logs/laravel.log`
and the editor-backup + absolute-webroot variants where a misconfigured
static-file route exposes the file. The `ERROR`-level
`Illuminate\Database\QueryException` line carries the per-request Tracebit
AWS canary inside the JSON `context.$_ENV` block — the slot a real
`APP_DEBUG=true` Laravel app surfaces via Illuminate's `HandleExceptions`
bootstrap when an uncaught exception fires.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/storage/logs/laravel.log` | `GET`, `HEAD`, `POST` | Monolog `INFO` + `NOTICE` + `ERROR` lines; AWS canary in the ERROR line's `context.$_ENV.AWS_*` slots |
| `/storage/logs/laravel.log.bak` | same | same renderer (log-rotate / editor backup sibling) |
| `/storage/logs/laravel.log.old` | same | same renderer |
| `/var/www/html/storage/logs/laravel.log` | same | same renderer (Docker / `nginx root /var/www/html` deploys) |
| `/var/www/storage/logs/laravel.log` | same | same renderer |
| `/srv/www/html/storage/logs/laravel.log` | same | same renderer |
| `/app/storage/logs/laravel.log` | same | same renderer (container working-dir variant) |
| `/home/laravel/storage/logs/laravel.log` | same | same renderer (per-user app-dir variant) |

Content-Type: `text/plain; charset=utf-8`.

## Logged fields

Standard request metadata plus:

- `result` = `laravel-log`
- canary issuance metadata recorded against the source IP via the
  shared `_get_or_issue_canary` per-IP TTL cache

## Per-hit uniqueness

The AWS canary triple (`awsAccessKeyId` / `awsSecretAccessKey` /
`awsSessionToken`) is Tracebit-issued per request and embedded in
`context.$_ENV.AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` plus the SES `MAIL_USERNAME` slot (where real
Laravel apps shipping mail via Amazon SES place the same access key).
Per-hit synthetic `APP_KEY` (32-byte token-urlsafe), `DB_PASSWORD`,
`REDIS_PASSWORD`, `MAIL_PASSWORD`, log-line timestamps (randomised epoch
base + jitter), and `userId` keep the body from acting as a fleet
fingerprint — two adjacent renders produce different bytes.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
No per-trap env var — toggle the whole canary file family with
`CANARY_TRAPS_ENABLED` if needed.

## Why this trap exists

Laravel ships Monolog wired to a single rotating file at
`storage/logs/laravel.log` whenever `LOG_CHANNEL=single` (or the
`daily` channel's un-suffixed symlink). The directory sits under the
project root, which lives outside the public webroot on a clean
deploy — but a misconfigured static-file route (`location / { root
/var/www/html; }` without an `/storage` exclusion, or a Docker image
that copies the whole app tree into a path the static handler serves)
exposes the log file directly. Scanner dictionaries walk it under the
bare project path and the canonical absolute-webroot variants
because both shapes appear in real-world exposures.

Real Laravel apps in `APP_DEBUG=true` mode log the full `$_ENV` array
inside the Monolog "context" dict whenever the `HandleExceptions`
bootstrap catches an uncaught exception — that's the slot
`Illuminate\Foundation\Bootstrap\HandleExceptions` populates with the
runtime environment when it formats the error. A scanner that fetches
the log file greps raw bytes for `AWS_ACCESS_KEY_ID=` / `AKIA…` /
`DB_PASSWORD=` / `MAIL_PASSWORD=` patterns and replays anything
credential-shaped. The trap reproduces the same line shape so the
harvest walks away with a per-hit AWS canary, which Tracebit then
fires on replay.

The editor-backup siblings (`.bak`, `.old`) match log-rotate fallbacks
some operators leave alongside the rotating file when they manually
rotate before redeploying. The absolute-webroot variants
(`/var/www/html/storage/logs/laravel.log`, `/var/www/`, `/srv/www/html/`,
`/app/`, `/home/laravel/`) cover the working-directories standard
Laravel Docker images and the OS-package-driven `nginx root` defaults
put the app at — common scanner-pattern same as the
`/var/www/html/wp-config.php` family.
