# Mail-service `.env` canary trap

Flux serves service-specific `.env` files for transactional email
providers, each with realistic API key formats alongside a Tracebit AWS
canary. Scanners hitting `/sendgrid/.env` get a SendGrid-shaped config
(`SENDGRID_API_KEY=SG.xxx`); `/postmark/.env` gets Postmark-shaped
content, etc.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/sendgrid/.env`   | `GET`, `HEAD`, `POST` | SendGrid config (`SENDGRID_API_KEY=SG.xxx`) + AWS canary |
| `/postmark/.env`   | `GET`, `HEAD`, `POST` | Postmark config (`POSTMARK_SERVER_TOKEN=xxx`) + AWS canary |
| `/mailjet/.env`    | `GET`, `HEAD`, `POST` | Mailjet config (`MJ_APIKEY_PUBLIC` + `MJ_APIKEY_PRIVATE`) + AWS canary |
| `/brevo/.env`      | `GET`, `HEAD`, `POST` | Brevo config (`BREVO_API_KEY=xkeysib-xxx`) + AWS canary |
| `/mailgun/.env`    | `GET`, `HEAD`, `POST` | Mailgun config (`MAILGUN_API_KEY=key-xxx`) + AWS canary |
| `/mailing/.env`    | `GET`, `HEAD`, `POST` | SendGrid-shaped (generic mail prefix) + AWS canary |
| `/mail/.env`       | `GET`, `HEAD`, `POST` | SendGrid-shaped (generic mail prefix) + AWS canary |
| `/mailserver/.env` | `GET`, `HEAD`, `POST` | Postmark-shaped (generic mail prefix) + AWS canary |

## Per-hit uniqueness

Every credential-shaped field is per-request unique: the service API key
(format-correct synthetic, not Tracebit-backed), the SMTP password, the
DB password (`_fake_db_password()`), and the AWS canary triple (Tracebit-
issued). No fixed literals.

## Why

Multi-region scanner fleets expanded their `.env` dictionaries in May 2026
to specifically target transactional email service configuration paths.
These paths were previously caught by the generic tarpit (which drip-feeds
random bytes with no credentials); upgrading them to canary traps with
service-specific content provides: (1) AWS canary replay detection, (2)
service-specific API key format in the body that tests whether scanners
parse provider-specific formats vs. generic `AWS_*` grep, and (3) more
plausible responses that should increase follow-on behavior.
