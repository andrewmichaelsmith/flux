# Fake Gravity SMTP plugin (WordPress REST) trap

Simulates the [Gravity SMTP](https://www.gravity.io/gravitysmtp/)
WordPress plugin's REST API surface at
`/wp-json/gravitysmtp/v1/...`. The `config` and per-connector
endpoints disclose the configured mail-backend credentials when the
plugin's REST permission callback is misconfigured — a class of
WordPress-REST authorisation gap that scanner dictionaries probe in
bulk alongside the namespace's other diagnostic endpoints.

| Path | Methods | Response |
| --- | --- | --- |
| `/wp-json/gravitysmtp/v1/settings` | `GET`, `HEAD` | `200` JSON plugin-wide settings (`default_connector`, debug toggles, retention, advertised connector list) |
| `/wp-json/gravitysmtp/v1/config` | `GET`, `HEAD` | `200` JSON per-connector config; AWS SES block carries the per-request Tracebit AWS canary in `aws_access_key_id` / `aws_secret_access_key` |
| `/wp-json/gravitysmtp/v1/connector/amazonses` | `GET`, `HEAD` | `200` JSON single-connector slice with the Tracebit AWS canary |
| `/wp-json/gravitysmtp/v1/connector/{mailgun,sendgrid,sparkpost,smtp,office365,gmail}` | `GET`, `HEAD` | `200` JSON single-connector slice with per-hit synthetic credentials in the published shape for that provider |
| `/wp-json/gravitysmtp/v1/tests/mock-data`<br>(also `?page=gravitysmtp-settings`) | `GET`, `HEAD` | `200` JSON sample outbound-email payload (no credentials) |
| `/wp-json/gravitysmtp/v1/data/debug` | `GET`, `HEAD` | `200` JSON recent-events slice (no credentials) |
| `/{blog,wordpress,wp,site,news,cms,press}/wp-json/gravitysmtp/v1/...` | any | Same dispatch as the bare path — sub-directory placements where WordPress is mounted under a webroot folder rather than at `/` |
| anything else under `/wp-json/gravitysmtp/v1/...` | any | `404` WordPress-REST-shaped `rest_no_route` envelope |

The handler logs:

- `result` tags (`gravitysmtp-settings`, `gravitysmtp-config`,
  `gravitysmtp-mock-data`, `gravitysmtp-debug`,
  `gravitysmtp-connector-amazonses` /
  `gravitysmtp-connector-mailgun` / `gravitysmtp-connector-sendgrid`
  / `gravitysmtp-connector-sparkpost` /
  `gravitysmtp-connector-smtp` / `gravitysmtp-connector-office365`
  / `gravitysmtp-connector-gmail`, `gravitysmtp-miss`)
- `gravitysmtpPath` (exact request path)
- `gravitysmtpMethod` (HTTP verb)
- `gravitysmtpConnector` (set on `/connector/<name>` requests that
  resolved to a known connector)
- `canaryTypes` and `bytes`

Every credential-shaped field is per-hit unique:

- AWS SES block ships the per-request Tracebit AWS canary
  (`awsAccessKeyId` / `awsSecretAccessKey`).
- Mailgun, SendGrid, SparkPost, Office 365, SMTP, and Gmail blocks
  ship per-hit random synthetics in the published shape for each
  provider — `key-<32 hex>` for Mailgun, `SG.<22>.<43>` for SendGrid,
  40-hex for SparkPost, a `secrets.token_urlsafe`-backed SMTP
  password, hex tenant/client IDs for Office 365, and the
  `ya29.…` / `GOCSPX-…` / `1//…` shapes for Gmail OAuth.

The trap defaults on (`HONEYPOT_GRAVITY_SMTP_ENABLED`). Keyless
deployments still serve every endpoint; the AWS canary slots simply
go empty.

## Why

`/wp-json/gravitysmtp/v1/...` is the WordPress REST namespace for
the Gravity SMTP plugin. Several scanner shapes consistently probe
the namespace:

1. **WP-REST namespace enumeration.** Generic WordPress scanners
   walk `/wp-json/`, `/wp-json/wp/v2/users`, and any installed
   plugin's REST namespace alongside `/.env` and `/wp-config.php`.
   A 404 on the namespace leaks "plugin not installed"; serving
   a populated namespace keeps the scanner walking.
2. **Mailer-credential harvesters.** SMTP/SES/Mailgun/SendGrid keys
   are a high-value scrape target (free transactional-email
   capacity for phishing, SES quota abuse). The `config` and
   `connector/<name>` slots in Gravity SMTP store those credentials
   in plaintext on the WordPress site — the slot scrapers grep for
   `aws_access_key_id` / `SG.` / `key-` / OAuth refresh tokens.
3. **Diagnostic-surface probes.** `/tests/mock-data` and
   `/data/debug` are the plugin's debug endpoints. They don't carry
   credentials themselves but recur in scanner dictionaries because
   they're a fingerprint marker — they confirm the plugin is
   installed before the scanner moves on to the credential slots.

Returning shape-correct JSON on every path keeps each probe alive
past fingerprint and harvests an AWS-replayable canary on the
`config` and `connector/amazonses` cells. Per-hit synthetics on
the other connector blocks prevent the trap from fingerprinting
the fleet (every sensor would otherwise ship the same fixed key
string).
