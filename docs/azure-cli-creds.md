# Azure CLI credential / profile cache traps

Flux serves format-accurate `~/.azure/*` files for every Azure CLI
credential cache and profile a scanner walks. Each file embeds a
Tracebit AWS canary in the slot a credential harvester actually grabs
— so a replay of the harvested string against any AWS surface trips
the canary even though the field name is Azure-flavoured.

## Routed paths

| Trap name | Path | Format | Canary slot |
| --- | --- | --- | --- |
| `azure-cli-profile` | `/.azure/azureProfile.json` | JSON — CLI account profile | `subscriptions[].user.name` of the service-principal subscription |
| `azure-cli-access-tokens` | `/.azure/accessTokens.json` | JSON — ADAL token cache (CLI ≤ 2.30) | `accessToken` (access key) + `refreshToken` (secret key) |
| `azure-cli-msal-cache` | `/.azure/msal_token_cache.json` | JSON — MSAL token cache (CLI ≥ 2.30) | `AccessToken.<key>.secret` + `RefreshToken.<key>.secret` |
| `azure-cli-service-principal` | `/.azure/service_principal_entries.json` | JSON — SP cred cache | `client_secret` |
| `azure-cli-config` | `/.azure/config` | INI — `az configure` output | `[storage].key` + `[storage].connection_string` (AccountKey) |
| `azure-cli-clouds-config` | `/.azure/clouds.config` | INI — Active cloud + endpoints | none — no native credential slot |

Path lookup is case-insensitive, so the real camelCase filenames
(`azureProfile.json`, `accessTokens.json`) and any lowercased variant
both route through the same trap.

## What the handler emits

Every credential-shaped field is either the AWS canary or a per-hit
synthetic identifier:

- **Tenant / subscription / installation / oid / client / home_account
  / local_account / first_run timestamp** — per-hit synthetic GUIDs and
  timestamps from `uuid.uuid4()` / `secrets.token_hex` / `time.time()`.
- **`user.name` (user-typed subscription) and MSAL `Account.username`** —
  per-hit synthetic `azureadmin@<random>.onmicrosoft.com` email.
- **`user.name` (service-principal subscription)** — Tracebit AWS access
  key. Real Azure CLI profiles cache the SP application-id there; a
  harvester scraping `subscriptions[].user.name` for cred-shaped strings
  picks the canary out.
- **`accessTokens.json` `accessToken` / `refreshToken`** — Tracebit AWS
  access key + secret. The HuggingFace-style "cat-and-exfil scanner
  just wants any string" precedent: a regex-strict harvester filtering
  for `eyJ…` headers rejects it, but a field-keyed harvester replays
  the value verbatim.
- **`msal_token_cache.json` `secret`** — Tracebit AWS access key
  (AccessToken entry) + secret (RefreshToken entry).
- **`service_principal_entries.json` `client_secret`** — Tracebit AWS
  secret key.
- **`config` `[storage].key` and `[storage].connection_string` AccountKey** —
  Tracebit AWS secret key. Real-world Azure CLI deploys do stash a
  long-lived Azure Storage account key in `~/.azure/config` for CI
  convenience; harvesters grabbing either field get the canary.
- **`clouds.config`** — no credential slot in real-world content. The
  trap exists so a `.azure/` directory walk doesn't see a partial
  install (which a sophisticated harvester would skip and bail).

## Logging

Every served path appends a `result: azure-cli-<…>` row to the
canary log with the canaryTypes list, status 200, and bytes served.
A 404 on any of these paths means either `TRACEBIT_API_KEY` is
unset (the deployment runs without canary issuance), or the
candidate path is outside the routed set.

## Why

A persistent credential-hunter dictionary observed in mid-2026
walks `~/.azure/azureProfile.json`, `~/.azure/accessTokens.json`,
`~/.cargo/credentials`, `~/.cache/huggingface/token`, `/.env`,
`/.aws/config`, and a handful of cloud-CLI cache files in a single
sweep. Flux already covered HuggingFace + Cargo + AWS; the Azure
CLI cache was the gap. A 404 on any one breaks the discovery chain
— the scanner concludes "no Azure CLI installed here" and skips the
token files. Returning plausible content keeps the scanner on the
follow-on request and lands the AWS canary in the slot they
actually scrape.
