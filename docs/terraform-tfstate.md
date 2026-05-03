# Terraform tfstate canary trap

Flux serves a plausible `terraform.tfstate` JSON document with a Tracebit
AWS canary embedded as the access key + secret of an `aws_iam_access_key`
resource (and again as a top-level `outputs` block, so a scraper that
walks `outputs[].value` rather than `resources[]` still picks up the
live canary).

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/.terraform/terraform.tfstate` | `GET`, `HEAD`, `POST` | tfstate JSON, AWS canary in `aws_iam_access_key.deploy` resource |
| `/terraform.tfstate`            | `GET`, `HEAD`, `POST` | same |
| `/terraform.tfstate.backup`     | `GET`, `HEAD`, `POST` | same |

## Logged fields

Standard request metadata plus:

- `result` = `terraform-tfstate`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

Both the AWS canary credentials AND the document's `lineage` (uuid) and
`serial` (small int) vary per request. A real tfstate has a stable
`lineage` per state file, but here every fetch should look like an
independent leak — a fixed lineage shipped across the fleet would
itself become a cross-sensor fingerprint.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
There is no per-trap env var; toggle with `CANARY_TRAPS_ENABLED` if you
want to disable the whole canary file family.

## Why this trap exists

Scanners walking `.git`, `.env`, and `.aws/credentials` paths have
started enumerating Terraform-state files alongside SSH private keys
and Next.js build manifests — the unifying theme is "config artifact a
sloppy CI deploy might leak below the webroot." `terraform.tfstate` is
particularly high-value because Terraform writes provider credentials
(AWS / GCP / Azure) into it in plaintext under
`resources[].instances[].attributes`, so an exposed file is a one-shot
cloud-credential leak. The trap mints a Tracebit AWS canary in the
exact two field shapes scrapers actually parse.
