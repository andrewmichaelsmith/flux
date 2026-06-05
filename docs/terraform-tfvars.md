# Terraform tfvars (HCL + JSON) canary

Flux serves a plausible Terraform variables file at the two
scanner-dictionary aliases for `terraform.tfvars` (HCL) and its JSON
sibling `terraform.tfvars.json`. Each response carries the Tracebit
AWS canary as the `aws_access_key` / `aws_secret_key` input values
plus a per-hit `db_password`.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/terraform.tfvars`              | `GET`, `HEAD`, `POST` | HCL `key = "value"` lines with canary AWS creds + per-hit DB password |
| `/.terraform/terraform.tfvars`   | `GET`, `HEAD`, `POST` | same |
| `/terraform.tfvars.json`         | `GET`, `HEAD`, `POST` | JSON object with canary AWS creds + per-hit DB password |
| `/.terraform/terraform.tfvars.json` | `GET`, `HEAD`, `POST` | same |

## Logged fields

Standard request metadata plus:

- `result` = `terraform-tfvars` (HCL) or `terraform-tfvars-json` (JSON)
- canary issuance metadata (canary id, expiration) recorded against
  the source IP

## Per-hit uniqueness

- `aws_access_key` / `aws_secret_key` / `aws_session_token` are
  Tracebit-issued per-hit canaries.
- `db_password` is a per-hit `_fake_db_password()` synthetic — never
  a fixed literal.

Non-credential filler (`environment`, `db_host`, `db_user`, VPC CIDR,
`allowed_admin_cidrs`) is plausible-static and not required to be
per-hit unique.

## Why this trap exists

The existing `terraform-tfstate` trap covers
`/.terraform/terraform.tfstate` and the bare `/terraform.tfstate(.backup)`
variants — but tfstate echoes input credentials only after Terraform's
sensitive-attribute redaction step. `terraform.tfvars` is the more
direct credential leak: it carries the *input* values (raw AWS keys,
database passwords) that the operator typed into the file.

Public scanner dictionaries that probe tfstate routinely walk tfvars
alongside it; covering only tfstate creates a 200/404 split that
fingerprints the host as hand-rolled. Both HCL and the JSON sibling
(`.tfvars.json`) are in the same dictionaries — Terraform accepts both
formats interchangeably, so harvesters check both.
