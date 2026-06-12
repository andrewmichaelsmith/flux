# AWS Console-downloaded `credentials.csv` canary trap

Flux serves the CSV file the AWS Management Console drops in the
operator's browser when an IAM user is created or a new programmatic
access key is minted — the file format is documented in the AWS IAM
user guide ("Managing access keys for IAM users"). A live Tracebit AWS
canary sits in the access-key + secret columns; field-keyed credential
harvesters greppe row 2 for `AKIA…` regardless of the surrounding
columns.

Two shapes are covered, mirroring the two real Console downloads:

| Shape | Columns | Filenames |
| --- | --- | --- |
| IAM user creation (with Console access) | `User name,Password,Access key ID,Secret access key,Console login link` | `/credentials.csv`, `/aws-credentials.csv`, `/aws_credentials.csv`, `/new_user_credentials.csv`, `/iam-credentials.csv`, `/iam_credentials.csv` |
| "Create access key" (existing user) | `Access key ID,Secret access key` | `/accesskeys.csv`, `/access_keys.csv`, `/access-keys.csv`, `/accesskey.csv`, `/rootkey.csv`, `/root_key.csv`, `/root-key.csv`, `/aws-access-keys.csv`, `/aws_access_keys.csv` |

The five-column shape also accepts webroot-prefix variants for
monorepos that drop the CSV into an `infra/`-style subdir:
`/admin/credentials.csv`, `/users/credentials.csv`,
`/iam/credentials.csv`, `/app/credentials.csv`,
`/backend/credentials.csv`, `/api/credentials.csv`,
`/private/credentials.csv`, `/backup/credentials.csv`.

## Routed paths

All paths above respond to `GET`, `HEAD`, `POST`, etc. with a
`text/csv; charset=utf-8` body using CRLF line endings (the AWS
Console download is byte-for-byte CRLF).

## Logged fields

Standard request metadata plus:

- `result` = `aws-credentials-csv` (five-column) or
  `aws-access-keys-csv` (two-column)
- canary issuance metadata against the source IP

## Per-hit uniqueness

- Access key ID and secret access key: per-hit Tracebit AWS canary.
- Console-login password (five-column shape only): per-hit synthetic
  via `_fake_db_password()`. The `gitlab-username-password` canary
  type fires only against a hosted GitLab URL, not the AWS Console,
  so a Tracebit canary in this slot would be inert; a synthetic
  prevents the password column from becoming a fleet-wide
  fingerprint literal.
- 12-digit AWS account ID embedded in the Console-login URL: per-hit
  random. A fixed account ID would mean every sensor's CSV body
  hashes identically, which is exactly the fingerprint a competent
  scanner would collapse on.

The IAM username (`iam-deploy-bot`) is fixed plausible filler — it's
structural, not secret, so it can be the same string across the
fleet without weakening detection.

## Tuning

The trap is a `CanaryTrap`, gated on `CANARY_TRAPS_ENABLED`
(default: on) and on `TRACEBIT_API_KEY`. There is no per-trap env
var.

## Why this trap exists

AWS-named credential paths see substantially higher canary-replay
intent than generic `.env`-class paths in observed scanner traffic —
attackers prioritise validating credentials they can identify as AWS
from the filename alone. `~/.aws/credentials` is the runtime config
file; the CSV download is what tends to end up in misconfigured
static-file servers, because the AWS Console hands the operator a
literal `credentials.csv` and a non-trivial number of those get
"backed up" into the webroot.

Scanner dictionaries walk a recognisable AWS-CSV path family in
lockstep — `/credentials.csv`, `/accessKeys.csv`, `/rootkey.csv`,
`/new_user_credentials.csv` — issuing identical 4-path bursts from
each member of a coordinated fleet. The trap converts that
unhandled-404 surface into a fired Tracebit canary with the same
content shape an actual leaked download would have, including the
five-column "Console + programmatic" download produced when the IAM
admin selects "Provide user access to the AWS Console" at user
creation. `rootkey.csv` is the deprecated root-account access-key
download (retired by AWS in 2014); scanner dictionaries still walk
it because the filename appeared in legacy AWS documentation.
