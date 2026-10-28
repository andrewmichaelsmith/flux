# Framework dev-mode debug surfaces

Canary file-trap entries for the dev-mode debug pages PHP framework
scanners enumerate alongside `/.env` and `/wp-config.php`. These pages
should never be reachable in production — when they are, the framework
itself happily prints DB credentials, `APP_SECRET`, AWS keys, and SMTP
auth as part of normal debug output. Scanner populations gating on
these endpoints are looking for that disclosure.

| Trap | Paths | Canary type | Log tag |
|---|---|---|---|
| Symfony Web Profiler phpinfo() + dashboard | `/_profiler/phpinfo`, `.php`, plus `/app_dev.php/_profiler/...`, `/symfony/_profiler/...`, `/frontend_dev.php/_profiler/...` variants; profiler-dashboard endpoints `/_profiler/latest`, `/_profiler/search`, `/_profiler/` (incl. `/app_dev.php/`, `/symfony/`, `/frontend_dev.php/` prefixes). URL-encoded prefix variants (`%2f_profiler/...`, `%252F_profiler/...`) collapse via `normalize_path`. | `aws` | `symfony-profiler-phpinfo` |
| Symfony parameters.yml / profiler/open | `/parameters.yml`, `/config/parameters.yml`, `/app/config/parameters.yml`; `/_profiler/open`, `/app_dev.php/_profiler/open`, `/symfony/_profiler/open`, `/frontend_dev.php/_profiler/open` | `aws` | `symfony-parameters-yml` |
| symfony 1.x dev front controller exception | `/frontend_dev.php/$` (`%24` folds onto it), `/frontend_dev.php/` | `aws` | `symfony1-dev-exception` |
| Yii2 debug toolbar config panel | `/debug/default/view`, `.html`, plus `/web/...`, `/frontend/web/...`, `/backend/web/...`, `/sapi/...` variants; `/debug/default/db-explain` | `aws` | `yii2-debug-view` |
| Django debug toolbar | `/__debug__/render_panel/`, `/__debug__/`, `/__debug__/sql_select/`, `/__debug__/sql_explain/`, `/__debug__/sql_profile/`, `/__debug__/template_source/` | `aws` | `django-debug-toolbar` |
| Laravel Ignition error page | `/_ignition/execute-solution` (+ trailing-slash); reverse-proxy aliases `/api/_ignition/execute-solution`, `/backend/_ignition/execute-solution`; scanner-recon variants `/_ignition/health-check`, `/api/_ignition/health-check`, `/_ignition/scripts/ignition.js`, `/_ignition/styles/ignition.css`. Same renderer on every method — POST bodies (CVE-2021-3129 RCE payloads) are captured via the request's `bodySha256` log field. | `aws` | `laravel-ignition` |

All paths are case-insensitive exact matches (CanaryTrap shape) — the
canary trap dispatcher matches the path-only piece, so any
`?panel=config`, `?panel=db`, `?file=...` query suffix still routes
into the matching renderer. Each renderer embeds the canary in the
slot a real dev-mode leak would expose it from:

- **Symfony profiler phpinfo** — the page lists `$_ENV` keys; the AWS
  canary triple sits in the `AWS_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY`
  / `_SESSION_TOKEN` rows, alongside Symfony-flavored
  `APP_SECRET`, `DATABASE_URL` (per-hit DB password), and `MAILER_DSN`
  (per-hit SMTP password). Field-keyed harvesters that grep for either
  the AWS env-var names or the Symfony names land on the canary.
- **Symfony parameters.yml** — YAML body with the `aws_access_key_id`
  / `aws_secret_access_key` / `aws_session_token` keys plus per-hit
  `database_password`, `mailer_password`, `secret`. The same body is
  returned for `/_profiler/open` regardless of the `?file=` value,
  since scanners gating on `_profiler/open` are checking dev-mode
  presence rather than reading specific files.
- **Yii2 debug toolbar** — HTML page that mimics the
  `yii\debug\Module` `ConfigPanel` rendering: `$_ENV` table with the
  AWS canary, plus `components.db.*` and `components.mailer.*` rows
  carrying per-hit synthetic DB and SMTP passwords. The same body is
  returned for `?panel=config`, `?panel=db`, etc. — credential
  grepping scanners don't differentiate the panel type.
- **Django debug toolbar** — HTML page mimicking the
  `django-debug-toolbar` SettingsPanel: `SECRET_KEY` (per-hit unique),
  `DATABASE_URL` (per-hit DB password), plus `$_ENV` with the AWS
  canary triple. The same body is returned for `?panel_id=SettingsPanel`,
  `?panel_id=TemplatePanel`, etc. — the `panel_id` query suffix is
  ignored since credential-grepping scanners target the path, not the
  panel type.
- **Laravel Ignition** — HTML stack-trace page that mimics the
  `facade/ignition` dev-mode error display. Header is a
  `Illuminate\Database\QueryException`; the "Environment" panel emits
  the full `$_ENV` block Laravel exposes when `APP_DEBUG=true`,
  carrying `APP_KEY` (per-hit `base64:<32-byte>`), `DB_PASSWORD`
  (per-hit), `REDIS_PASSWORD` (per-hit), `MAIL_PASSWORD` (per-hit),
  plus the AWS canary triple. CVE-2021-3129 (the
  `MakeViewVariableOptionalSolution` RCE) POSTs land on the same
  renderer; the exploit body is captured via the request's
  `bodySha256` log field, so payload rotations across scanner
  populations are attributable.

## Why

These paths land in access logs at steady high-IP-fanout cadence —
recent dictionaries have hundreds of hits per source IP on
`/_profiler/phpinfo`, `/app_dev.php/_profiler/phpinfo`, and
`/debug/default/view?panel=config` across many distinct sources, with
the same source IPs often hitting both Symfony and Yii2 paths from
the same scan. Returning canary-bearing dev-mode output closes that
attribution gap and aligns the credentials with where a real
misconfigured dev-mode framework would leak them.

Per-hit-unique DB password / mailer password / app secret keep each
rendered body unique so the response can't be cross-sensor
fingerprinted. The credential-shaped slots that map to a real
Tracebit canary type (AWS) are populated from a per-IP cached
canary; the rest are per-hit `secrets.token_urlsafe(16)` synthetic
values.

## symfony 1.x dev front controller

`frontend_dev.php` is the debug-mode front controller symfony 1.x
generates for every app. Scanners request it with a module name no app
routes (`$`), because a reachable debug install answers that with the
full `sfError404Exception` page rather than a 404. The trap renders
that page: the `Action "$/index" does not exist.` message (the module
is echoed from the request), a stack trace, and the expandable Settings
and Global vars dumps. The AWS canary sits in the `app_amazon_s3_*`
settings, where an `app.yml` key surfaces; the DB DSN and a per-hit
`DB_PASSWORD` sit in `$_SERVER`, where vhost `SetEnv` puts them; the
mailer password is per-hit too. The bare `/frontend_dev.php` keeps its
existing handler.

## Replay attribution for per-hit DB passwords

Per-hit DB passwords are not Tracebit canaries, so a replay raises no
alert upstream. But clients that harvest a leaked DSN commonly submit
it to the Adminer / phpMyAdmin login traps next. Every canary-trap
response logs `syntheticSecretFps`: a 16-hex sha256 prefix of each
password it minted, never the value. The two login traps log `pwdFp`
for a submitted password with the synthetic shape (22 url-safe
characters, so dictionary words are never hashed). When the same
process served the leak, they also log `pwdReplayOf`: the leaking
trap, its `requestId`, whether the same client replayed it, and the
age in seconds. Matching `pwdFp` against `syntheticSecretFps` across
logs catches replays that land on another host.
