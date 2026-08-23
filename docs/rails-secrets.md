# Rails secrets bundle canary trap

Flux serves four secret-shaped files every Rails app ships: the
plaintext `config/database.yml`, the pre-5.2 plaintext
`config/secrets.yml`, the 5.2+ `config/master.key` decryption key, and
the 5.2+ `config/credentials.yml.enc` encrypted YAML blob. Scanner
dictionaries walk them together — a source hitting `database.yml`
almost always follows up with `secrets.yml` and `master.key`. Real
webroot-misconfigured Rails apps (nginx `root` pointed at the project
directory instead of `public/`) leak all four in one shot.

## Routed paths

| Family | Path(s) | Renderer | Canary slot |
| --- | --- | --- | --- |
| `rails-database-yml` | `/config/database.yml` plus editor/backup variants (`.example`, `.sample`, `.dist`, `.default`, `.bak`, `.old`, `.save`, `.orig`, `.swp`, `~`), dialect variants (`.pgsql`, `.postgres`, `.postgresql`, `.mysql`, `.sqlite`, `.sqlite3`), leading-dot vim swap (`/.config/database.yml.swp`), app-layout webroot-prefix variants (`/app/`, `/storage/`, `/backend/`, `/backup/`, `/public/`, `/public_html/`, `/www/`, `/htdocs/`), the webroot-dropped leaf (`/database.yml`, `/database.yaml`, `/db.yml`, `/db.yaml` + `.bak` / `.old` / `~`), and the application-prefixed spellings where the prefix replaces `config/` (`/{api,app,backend,server,services,src,db,conf}/database.yml`) | `render_rails_database_yml` | `production.s3_bucket_key_id` / `s3_bucket_secret` / `s3_bucket_session_token` |
| `rails-secrets-yml` | `/config/secrets.yml` plus the same editor/backup/webroot-prefix matrix | `render_rails_secrets_yml` | `production.aws.access_key_id` / `secret_access_key` / `session_token` |
| `rails-master-key` | `/config/master.key` plus backup variants and Rails 6+ multi-environment `/config/credentials/{production,staging,development,test}.key` | `render_rails_master_key` | (no canary slot — bare AES key) |
| `rails-credentials-enc` | `/config/credentials.yml.enc` plus backup variants and Rails 6+ multi-environment `/config/credentials/{production,staging,development,test}.yml.enc` | `render_rails_credentials_enc` | (no canary slot — encrypted GCM blob) |

Content-Types: `text/yaml; charset=utf-8` for `database.yml` and
`secrets.yml`, `text/plain; charset=utf-8` for `master.key`, and
`application/octet-stream` for `credentials.yml.enc`.

## Logged fields

Standard request metadata plus:

- `result` = `rails-database-yml` / `rails-secrets-yml` /
  `rails-master-key` / `rails-credentials-enc`
- canary issuance metadata (canary id, expiration) recorded against
  the source IP for the two families that embed a Tracebit AWS canary

## Per-hit uniqueness

Every credential-shaped field is per-hit random so nothing pins the
fleet to a shared fingerprint:

- **database.yml** — `development.password`, `test.password`,
  `production.password` are three independent `_fake_db_password()`
  values (verified different by `test_render_rails_database_yml_shape_and_per_hit_uniqueness`).
- **secrets.yml** — `development.secret_key_base`,
  `test.secret_key_base`, `production.secret_key_base` are three
  independent `secrets.token_hex(64)` values (128 hex chars each,
  matching what `rails secret` emits); the `production.smtp.password`
  is a separate `_fake_db_password()`.
- **master.key** — plain `secrets.token_hex(16)` (32 lowercase hex
  chars + trailing newline, matching what `bin/rails
  credentials:edit` writes).
- **credentials.yml.enc** —
  `<base64(384 random bytes)>--<base64(12 random bytes)>--<base64(16 random bytes)>`
  (Rails 5.2+ ActiveSupport::MessageEncryptor AES-128-GCM shape:
  ciphertext + 12-byte IV + 16-byte auth tag).

## Tuning

Master switch: `CANARY_TRAPS_ENABLED` (defaults on). No per-trap env
var. Deployments without `TRACEBIT_API_KEY` fall through to the
tarpit / 404 dispatch, same as the rest of the canary-file family.

## Why

`config/database.yml` is the file Rails apps have always shipped as
plaintext — the community-standard leak surface predating the 5.2+
encrypted-credentials rework. `config/secrets.yml` is the pre-5.2
plaintext successor to `secret_token.rb` and the pre-`master.key`
home for `secret_key_base` — knowing this key alone lets an attacker
forge Rails session cookies (they're HMAC'd with `secret_key_base`),
regardless of anything else in the app. Both are still in wide use
across long-lived Rails 4/5 deployments and misconfigured Rails 6+
apps that never migrated to encrypted credentials.

`config/master.key` and `config/credentials.yml.enc` are the 5.2+
pair. Scanners probe them separately because a harvester holding
both can decrypt the encrypted YAML with a two-line Ruby script;
serving both under the same trap surface lets us capture that
follow-up pairing as a linked probe signature. Since the encrypted
blob is opaque to a byte-grepper, we push the canary into
`secrets.yml` and `database.yml` (which harvesters read as plaintext)
and let `master.key` / `credentials.yml.enc` serve their per-hit
random shape-plausible bytes for fingerprinting.

The `production.s3_bucket_*` slot in `database.yml` is a Rails-
community anti-pattern that shows up in real leaks exactly because
`database.yml` is the first file operators accidentally commit or
leave in the webroot — S3 credentials stashed next to the DB config
so a single `require 'aws-sdk-s3'; Aws::S3::Client.new(...)` call
inside a rake task can read them. Field-keyed harvesters grep for
both `password:` and `access_key_id` shapes; a single-file leak
covers both harvest patterns.

App-layout webroot-prefix variants (`/app/`, `/storage/`, `/backend/`,
`/backup/`, `/public/`, `/public_html/`, `/www/`, `/htdocs/`) share
the `_app_layout_variants` helper with `.aws/credentials`,
`.env.production`, and other credential-file families — scanner
dictionaries walk the same prefix matrix regardless of the specific
target file, so anything not covered by that matrix falls through to
404.

## Webroot-dropped and application-prefixed spellings

`/config/database.yml` is the canonical path, but it is not the one
dictionaries ask for most. Two other shapes arrive more often and both
used to 404:

- **The bare leaf** — `/database.yml`, `/db.yml` and their `.yaml`
  spellings. A deploy that serves the `config/` directory contents at the
  docroot puts the file there, and the dictionary reflects that. This is
  the same asymmetry the bare `/credentials` entry closes for the AWS
  credentials family.
- **The prefix replacing `config/`** — `/api/database.yml`,
  `/backend/database.yml`, `/src/database.yml`. Distinct from the
  `_app_layout_variants` matrix, which yields `/api/config/database.yml`:
  there the prefix precedes `config/`, here it stands in for it. Both
  shapes are now served, and both render the same document, because they
  are the same file seen from two docroots — serving two different
  configs for them would be a tell rather than a trap.
