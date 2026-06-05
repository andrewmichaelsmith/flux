# GCP service-account JSON canary at generic webroot paths

Flux serves a GCP service-account JSON (the file
`gcloud iam service-accounts keys create` writes) at six off-the-shelf
scanner-dictionary aliases that the canonical `firebase-json` trap does
not cover. Each response carries a Tracebit AWS canary embedded in
`private_key_id` and inside the `private_key` PEM body.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/gcp-credentials.json`         | `GET`, `HEAD`, `POST` | GCP `service_account` JSON; canary AWS secret in `private_key` PEM body |
| `/config/gcp-credentials.json`  | `GET`, `HEAD`, `POST` | same |
| `/private/gcp-credentials.json` | `GET`, `HEAD`, `POST` | same |
| `/api/credentials.json`         | `GET`, `HEAD`, `POST` | same |
| `/private/credentials.json`     | `GET`, `HEAD`, `POST` | same |
| `/backend/credentials.json`     | `GET`, `HEAD`, `POST` | same |
| `/app/credentials.json`         | `GET`, `HEAD`, `POST` | same |

## Logged fields

Standard request metadata plus:

- `result` = `gcp-credentials-json`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

Every credential-shaped field is randomised per request:

- The Tracebit AWS canary `awsSecretAccessKey` is embedded inside the
  `private_key` PEM body as a `# CANARY-AWS-SECRET=...` comment line —
  the secret rotates per Tracebit issuance.
- `private_key_id` is derived from the per-hit canary access-key id
  mapped into the 40-char lowercase-hex shape that GCP SDK validators
  accept.

`project_id`, `client_email`, `client_id`, and the OAuth URLs are
plausible-static filler — not credentials — so leaving them fixed
across hits does not create a fleet fingerprint. Only the
credential-shaped fields are required to be per-hit unique.

## Why this trap exists

The canonical Firebase / GCP filenames
(`/firebase-adminsdk.json`, `/.config/gcloud/application_default_credentials.json`,
`/serviceaccount.json`, etc.) are already covered by the
`firebase-json` trap, but recurring scanner dictionaries walk a
separate alias set: the bare `/gcp-credentials.json` plus generic
"webroot leak" prefixes (`/api/`, `/private/`, `/backend/`, `/app/`,
`/config/`) on the generic `credentials.json` filename. Without these
aliases the same dictionary collects 1 canary
(`/firebase-adminsdk.json`) instead of 5–7, and the harvester walks
away with the false signal that the host is not a GCP-deploy target.

Harvesters filter the response on `"type": "service_account"` before
extracting `private_key` — we set that field first in the JSON so the
shape filter passes immediately. The AWS canary in the PEM body fires
on replay against the issuer's tracking surface even though the file's
nominal credential type is GCP, because grep-style harvesters extract
any `wJa...` AWS secret they recognise irrespective of the surrounding
file shape.

The bare `/credentials.json` (no prefix) remains routed to the older
`config-json` generic-config trap and is not re-claimed by this trap.
