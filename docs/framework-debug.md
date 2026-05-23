# Framework dev-mode debug surfaces

Canary file-trap entries for the dev-mode debug pages PHP framework
scanners enumerate alongside `/.env` and `/wp-config.php`. These pages
should never be reachable in production — when they are, the framework
itself happily prints DB credentials, `APP_SECRET`, AWS keys, and SMTP
auth as part of normal debug output. Scanner populations gating on
these endpoints are looking for that disclosure.

| Trap | Paths | Canary type | Log tag |
|---|---|---|---|
| Symfony Web Profiler phpinfo() | `/_profiler/phpinfo`, `.php`, plus `/app_dev.php/_profiler/...`, `/symfony/_profiler/...`, `/frontend_dev.php/_profiler/...` variants | `aws` | `symfony-profiler-phpinfo` |
| Symfony parameters.yml / profiler/open | `/parameters.yml`, `/config/parameters.yml`, `/app/config/parameters.yml`; `/_profiler/open`, `/app_dev.php/_profiler/open`, `/symfony/_profiler/open`, `/frontend_dev.php/_profiler/open` | `aws` | `symfony-parameters-yml` |
| Yii2 debug toolbar config panel | `/debug/default/view`, `.html`, plus `/web/...`, `/frontend/web/...`, `/backend/web/...`, `/sapi/...` variants; `/debug/default/db-explain` | `aws` | `yii2-debug-view` |
| Django debug toolbar | `/__debug__/render_panel/`, `/__debug__/`, `/__debug__/sql_select/`, `/__debug__/sql_explain/`, `/__debug__/sql_profile/`, `/__debug__/template_source/` | `aws` | `django-debug-toolbar` |

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
