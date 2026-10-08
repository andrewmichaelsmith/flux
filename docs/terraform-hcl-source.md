# Terraform HCL source-tree traps

Flux already answered the two files that hold Terraform's *values* —
`terraform.tfstate` and `terraform.tfvars` — but 404ed every `.tf` source
file that declares and references them. That is backwards from how a
leaked project tree is actually read: the `.tf` files are what a webroot
checkout exposes first, and they are what tell the reader which provider
is in use and what the value files are called. It was also a fingerprint
in its own right — no real checkout has a `terraform.tfvars` without a
`variables.tf` beside it.

## Routed paths

| Path | Method | Response | Result tag |
| --- | --- | --- | --- |
| `/variables.tf`, `/variable.tf`, `/vars.tf` | `GET`, `HEAD`, `POST` | `sensitive = true` variable declarations, no values | `terraform-hcl-variables` |
| `/main.tf` | `GET`, `HEAD`, `POST` | resource blocks referencing `var.*` | `terraform-hcl-main` |
| `/providers.tf`, `/provider.tf`, `/aws.tf` | `GET`, `HEAD`, `POST` | `provider "aws"` block, **AWS canary inlined** | `terraform-hcl-providers` |
| `/ovh.tf` | `GET`, `HEAD`, `POST` | `provider "ovh"` block, **canary inlined** as the key triple | `terraform-hcl-provider-ovh` |
| `/backend.tf`, `/state.tf` | `GET`, `HEAD`, `POST` | `backend "s3"` block naming the remote state object | `terraform-hcl-backend` |
| `/outputs.tf`, `/output.tf` | `GET`, `HEAD`, `POST` | outputs marked `sensitive` | `terraform-hcl-outputs` |
| `/versions.tf`, `/version.tf` | `GET`, `HEAD`, `POST` | `required_providers` pins | `terraform-hcl-versions` |

Each member also answers under the `terraform/`, `infra/`,
`infrastructure/`, `ops/` and `deploy/` prefixes a monorepo commits its
root module into. An arbitrary parent still 404s.

## Logged fields

Standard request metadata, plus a `result` tag per member rather than one
shared `terraform` tag — so a walk through the tree reads in the log as a
sequence (which file first, which followed) instead of one undifferentiated
hit. The two provider members additionally record canary issuance against
the source IP.

## Credential placement

Credentials sit where real practice puts them rather than being spread
evenly over the tree:

- **The five structural members spend no canary at all.** A correct
  `variables.tf` declares `sensitive = true` variables and holds no
  values; `main.tf` and `outputs.tf` reference `var.*` rather than
  literals; `backend.tf` and `versions.tf` carry none by nature. Their
  `canary_types` are empty, and a test asserts they do not emit canary
  material even when handed a populated one.
- **The two provider members carry it.** Inlining a key pair into a
  `provider "aws" {}` block instead of taking it from the environment is
  the classic committed-credential mistake, and it is the one place in a
  `.tf` tree where a raw key plausibly sits. Per-hit unique, never a fixed
  literal: with no canary issued the fields render empty rather than
  falling back to a placeholder.

## Why

The tree is internally consistent on purpose, and that consistency is the
point rather than decoration. `variables.tf` names the secrets the project
needs without supplying them, which is exactly what steers a reader to
`terraform.tfvars`; `backend.tf` names the remote state object, which
steers to `terraform.tfstate`. Both of those destinations are paths Flux
already serves a canary from, so the source tree turns a single
config-file read into a chain with a measurable next step — and because
each member logs its own result tag, whether a reader actually follows the
names it just read is now an observable rather than an assumption.

Tests pin all three properties — that every member resolves to its own
tag, that every `var.*` referenced is declared and every tfvars assignment
has a declaration behind it, and that the structural/provider split in
credential placement holds — in `tests/test_terraform_hcl_source.py`.
