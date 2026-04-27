# Fake IBM Aspera Faspex trap

Flux ships a lightweight IBM Aspera Faspex deception surface aimed at
CVE-2022-47986-era scanner chains.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/aspera/faspex/` (and no-trailing-slash variant) | `GET`, `HEAD`, `POST` | HTML login shell with version marker |
| `/aspera/faspex/account/logout` | `GET`, `HEAD`, `POST` | JSON logout envelope with per-request `csrf` token |
| `/aspera/faspex/package_relay/relay_package` | `GET`, `HEAD`, `POST` | plain-text relay ack |

## Logged fields

Standard request metadata is logged for every event plus:

- `result` (`aspera-faspex-landing`, `aspera-faspex-logout`, `aspera-faspex-relay-package`)
- `asperaFaspexPath`
- `asperaFaspexMethod`
- `bodyPreview` for requests with payload bodies

## Tuning

- `HONEYPOT_ASPERA_FASPEX_ENABLED` (default: enabled)
- `HONEYPOT_ASPERA_FASPEX_PATHS_CSV` to override matched path set
- `HONEYPOT_ASPERA_FASPEX_VERSION` to change the landing page banner

## Why this trap exists

Aspera Faspex probes are often the first phase of a two-step scanner flow:
fingerprint, then push payloads to follow-on endpoints. Returning plausible
application responses helps keep scanners in-flow so we capture payload bodies
instead of one-shot 404 noise.
