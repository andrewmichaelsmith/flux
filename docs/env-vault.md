# `.env.vault` canary trap

Flux serves a plausible `dotenv-vault`-format file with per-environment
ciphertext entries and a "REMOVE before merge" plaintext fallback block
at the bottom that embeds a Tracebit AWS canary.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/.env.vault`         | `GET`, `HEAD`, `POST` | dotenv-vault body, AWS canary in plaintext block |
| `/.env.vault.bak`     | `GET`, `HEAD`, `POST` | same |
| `/.env.vault.example` | `GET`, `HEAD`, `POST` | same |

## Logged fields

Standard request metadata plus:

- `result` = `env-vault`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

Both the AWS canary credentials and the encrypted vault values
(`DOTENV_VAULT_DEVELOPMENT`, `DOTENV_VAULT_STAGING`,
`DOTENV_VAULT_PRODUCTION`) are randomized per request. The DB password
in the plaintext fallback is also per-hit unique
(`_fake_db_password()`). Without per-hit randomization the response
would turn the fleet into a single fingerprint — every sensor shipping
the identical ciphertext would be a tell.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
There is no per-trap env var; toggle with `CANARY_TRAPS_ENABLED` if you
want to disable the whole canary file family.

## Why this trap exists

`.env.vault` is the file format produced by the
[dotenv-vault](https://www.dotenv.org/docs/security/env-vault) tool —
encrypted ciphertext per environment that requires a separate
`DOTENV_KEY` URL to decrypt. A clean `.env.vault` is therefore not a
direct credential leak. Scanners harvest it anyway because operators
who push `.env.vault` to a webroot (or commit it alongside `.env.me`)
often *also* commit a plaintext fallback block "temporarily" while
debugging the rotation. That mistake is common enough that
`.env.vault` is now a standard line in scanner secret-hunting
dictionaries — and it's the misconfiguration we're simulating here.

The 2026-05-06 weekly novelty pass observed the path in scanner
traffic against our existing `.env`-family tarpit, which makes a real
canary at the path more useful than a generic tarpit response: the
canary fires on replay, the tarpit doesn't.
