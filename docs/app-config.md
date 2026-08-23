# Application-config canary trap

Flux serves the framework-agnostic application-config files that
credential-harvester dictionaries walk alongside the framework-specific
ones that already had traps here (`wp-config.php`, `.env`,
`config/database.yml`, `appsettings.json`). `config.php`,
`config/database.php`, `config/mail.php`, `settings.py`, `config.yaml`,
`config.toml`, `env.json`, `bootstrap.properties`, and the
unauthenticated `/api/config` runtime-introspection endpoint are all in
the same sweep as the covered files, and all of them used to 404 — so one
request in a twenty-request sweep issued a canary and the rest issued
nothing.

Grouping is by **serialization format, not framework**. What the renderer
has to get right is that a `.php` response parses as PHP and a `.toml`
response parses as TOML; the path only selects which format to emit. That
also makes the families useful as a behavioural split: a harvester that
loads and parses these files is a different population from one that
greps raw bytes for `AKIA`, and the per-format log tags separate them.

## Routed paths

| Family | Path(s) | Renderer | Canary slot |
| --- | --- | --- | --- |
| `app-config-php` | `/config.php`, `/configuration.php`, `/settings.php`, `/local.config.php`, `/config/config.php`, `/includes/config.php`, `/inc/config.php`, `/include/config.php`, `/application/config/config.php`, plus the family-wide editor/backup sibling set (`.bak`, `.old`, `.save`, `.orig`, `.swp`, `~`) and `.txt` and the `_app_layout_variants` webroot-prefix matrix | `render_php_config` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` `define()` constants |
| `app-config-php-database` | `/config/database.php`, `/config/db.php`, `/config/connection.php`, `/application/config/database.php`, plus backup and webroot-prefix variants | `render_php_database_config` | `connections.backups.key` / `secret` / `token` |
| `app-config-php-mail` | `/config/mail.php`, `/config/mailer.php`, `/config/email.php`, `/config/smtp.php`, plus backup and webroot-prefix variants | `render_php_mail_config` | `mailers.ses.key` / `secret` / `token` |
| `app-config-php-services` | `/config/services.php`, `/config/api.php`, `/config/keys.php`, `/config/credentials.php`, `/config/app.php`, `/config/secrets.php`, plus backup and webroot-prefix variants | `render_php_services_config` | `aws.key` / `secret` / `token` |
| `app-config-python` | `/settings.py`, `/config.py`, `/app/settings.py`, `/app/config.py`, `/config/settings.py`, `/instance/config.py`, `/project/settings.py`, `/core/settings.py`, `/core/config.py`, `/backend/settings.py`, `/backend/config.py`, `/src/settings.py`, `/src/config.py`, `/local_settings.py`, `/production_settings.py`, plus backup variants | `render_python_settings` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` module constants |
| `app-config-yaml` | `/config.yaml`, `/config.yml`, `/secrets.yml`, `/secrets.yaml`, `/bootstrap.yml`, `/bootstrap.yaml`, `/config/storage.yml`, `/config/config.yml`, `/config/config.yaml`, `/.hermes/config.yaml`, `/.hermes/config.yml`, plus backup and webroot-prefix variants | `render_generic_config_yaml` | `storage.accessKeyId` / `secretAccessKey` / `sessionToken` |
| `app-config-toml` | `/config.toml`, `/settings.toml`, `/config/config.toml`, plus backup and webroot-prefix variants | `render_generic_config_toml` | `[s3] access_key_id` / `secret_access_key` / `session_token` |
| `app-config-json` | `/env.json`, `/local.settings.json`, `/config.json.bak`, and the runtime-introspection endpoints `/api/config`, `/api/v1/config`, `/api/v2/config`, `/api/settings`, `/api/config.json`, `/api/v1/settings`, `/api/v2/settings`, `/api/v1/env`, `/api/v2/env`, plus the front-end runtime-config bundles `/app-config.json` and `/push_config.json` | `render_app_config_json` | `aws.accessKeyId` / `secretAccessKey` / `sessionToken` |
| `app-config-properties` | `/bootstrap.properties`, `/config.properties`, `/config/bootstrap.properties`, `/config/application.properties`, plus backup and webroot-prefix variants | `render_java_properties` | `cloud.aws.credentials.accessKey` / `secretKey` / `sessionToken` |

Content-Types follow the format: `text/plain; charset=utf-8` for PHP,
Python and properties, `text/yaml; charset=utf-8` for YAML,
`application/toml; charset=utf-8` for TOML, `application/json` for JSON.

## Ownership boundaries

The family is deliberately the *generic* sibling set and must not
re-home the framework-specific traps. Pinned by
`test_app_config_does_not_shadow_framework_traps`:

- `/config/database.yml`, `/config/secrets.yml`, `/config/master.key` →
  the `rails-*` traps.
- `/env.php` → `env-production`.
- `/application.yml`, `/application.yaml` → `application-yml`.
- `/settings.json` → `config-json`.

## Logged fields

Standard request metadata plus `result` = the family name
(`app-config-php`, `app-config-python`, …) and the canary-issuance
metadata recorded against the source IP. The per-format tag is the point:
it separates the PHP-dictionary population from the Python one and from
the `/api/config` runtime-endpoint probers without any extra plumbing.

## Per-hit uniqueness

Every credential-shaped field is per-hit random, so nothing pins the
deployment to a shared fingerprint. DB, Redis, and SMTP passwords are
independent `_fake_db_password()` values within a single response;
session-signing keys use `_fake_app_secret_key()`; Stripe, Mailgun and
SendGrid filler use the existing `_fake_mail_api_key()` /
`secrets.token_urlsafe` helpers. The only value that repeats across two
renders is the Tracebit AWS canary itself, which is supplied per request.
Pinned by `test_app_config_renderers_are_per_hit_unique` across all nine
renderers.

## Why

Generic config-file names are the long tail of every credential-harvest
dictionary, and they are framework-agnostic precisely because the
harvester does not know what the target runs. Serving a plausible,
format-correct body turns each of those requests into a canary issuance
instead of a 404, and — because the response is parseable rather than a
stub — gives a downstream signal on whether the harvester consumes what
it collects.

## Editor / backup leftovers are a rule, not a list

A harvester dictionary walks the `.bak` / `.old` / `~` form of every
config file it probes, because a webroot that serves the original
usually serves the backup as plain text even where PHP execution is on.

The sibling set used to be hand-written per path, and had drifted:
`/config.php` carried six siblings, `/configuration.php` three,
`/settings.php` two, and `/includes/config.php` none. That split one
dictionary pass across two outcomes for no reason the caller could see —
the same sweep asking for `/config.php.swp` and `/settings.php.swp` got a
config from the first and a 404 from the second.

The set is now filled by a rule over the whole family, so a path added
later gets its siblings without anyone remembering to. Two properties
keep it safe, both pinned by tests:

- **It can only add.** The fill uses `setdefault`, so a suffix spelling a
  framework-specific trap already owns (`/wp-config.php.bak`,
  `/.env.old`, `/config/database.yml.bak`) keeps its own renderer. The
  fill can turn a 404 into an answer; it can never move a route.
- **A sibling renders the same document as its base.** A `.bak` routing
  to a different renderer than the file it is a backup of would hand one
  caller two different configs for the same path, which is a tell rather
  than a trap.

Leftovers are not stacked (`/config.php.bak.old` is not served) — no
scanner asks for that spelling.
