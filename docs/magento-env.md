# `app/etc/env.php` Magento canary trap

Flux serves a plausible Magento 2 `env.php` merchant-side config with a
Tracebit AWS canary in the `system.default.aws_s3` slot and every other
credential-shaped field (crypt.key, DB password, session password, AMQP
password, admin URL secret, admin frontName) randomised per hit.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/app/etc/env.php`                 | `GET`, `HEAD`, `POST` | PHP-array env.php, AWS canary in aws_s3 slot |
| `/app/etc/env.php.{bak,old,save,swp,dist}` | `GET`, `HEAD`, `POST` | same |
| `/app/etc/env.php~`                | `GET`, `HEAD`, `POST` | same |
| `/app/etc/env.sample.php`          | `GET`, `HEAD`, `POST` | same |
| `/app/etc/local.xml`               | `GET`, `HEAD`, `POST` | same (Magento 1.x alias — grep-based scanners still walk it) |
| `/app/etc/config.php`              | `GET`, `HEAD`, `POST` | same |
| `/magento/app/etc/env.php`         | `GET`, `HEAD`, `POST` | same (sub-path deploy) |
| `/magento2/app/etc/env.php`        | `GET`, `HEAD`, `POST` | same |
| `/shop/app/etc/env.php`            | `GET`, `HEAD`, `POST` | same |
| `/store/app/etc/env.php`           | `GET`, `HEAD`, `POST` | same |
| `/var/www/{,html/}app/etc/env.php` | `GET`, `HEAD`, `POST` | absolute-webroot traversal variants |
| `/srv/www/app/etc/env.php`         | `GET`, `HEAD`, `POST` | same |
| `/usr/share/nginx/html/app/etc/env.php` | `GET`, `HEAD`, `POST` | same |
| `/var/www/html/magento{,2}/app/etc/env.php` | `GET`, `HEAD`, `POST` | same |
| `/%61%70%70/%65%74%63/%65%6e%76.%70%68%70` | `GET`, `HEAD`, `POST` | double-encoded scanner-dict variant |

Content-Type: `application/x-php; charset=utf-8`.

## Logged fields

Standard request metadata plus:

- `result` = `magento-env`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

The AWS canary lives in the `system.default.aws_s3` block (`access_key`,
`secret_key`, `session_token`), sitting next to a plausible bucket name
(`magento-media-prod`) and region. Every non-canary credential-shaped
slot is per-hit random so nothing pins the fleet to a shared fingerprint:

- `db.connection.default.password` — `_fake_db_password()`
- `session.redis.password` — `_fake_db_password()`
- `queue.amqp.password` — `_fake_db_password()`
- `crypt.key` — 16-byte hex
- `admin_url_secret` — `secrets.token_urlsafe(20)`
- `backend.frontName` — `admin_<4-byte hex>`

## Tuning

Master switch: `CANARY_TRAPS_ENABLED` (defaults on). No per-trap env
var. Deployments without `TRACEBIT_API_KEY` fall through to the tarpit /
404 dispatch, same as the rest of the canary-file family.

## Why

`app/etc/env.php` is the merchant-side config `bin/magento setup:install`
writes on every Magento 2 deploy — it carries the DB credentials, the
crypt.key used to encrypt admin password hashes and stored payment
info, the session save handler + credentials, the cache backend, the
queue.amqp broker config, and the admin URL secret. Broad
credential-hunting scanners walk it alongside `.env` / `wp-config.php`
because misconfigured static routes (or backup archives left in the
webroot) leak the file whole. Field-keyed harvesters key off the
Magento-specific slot names (`crypt`, `admin_url_secret`, `frontName`)
in addition to raw AKIA bytes, so folding this into a generic env
renderer would miss the population that greps for those slot names
specifically.

Sub-path deploys (`/magento/`, `/magento2/`, `/shop/`, `/store/`) and
Apache/nginx canonical install-root prefixes (`/var/www/html/`,
`/srv/www/`, `/usr/share/nginx/html/`) are included because scanner
dictionaries enumerate them alongside the webroot variant. The Magento
1.x aliases (`local.xml`, `config.php`) share the render — same canary
slot survives against dictionaries that walk both major-version
filename conventions.
