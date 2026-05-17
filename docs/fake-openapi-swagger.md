# Fake OpenAPI / Swagger trap

Serves a plausible OpenAPI 3.0.3 document on the SpringDoc / FastAPI /
Swashbuckle / drf-yasg / NSwag spec paths, plus Swagger UI / ReDoc HTML
bootstrap pages for the UI variants. The JSON/YAML spec embeds a
per-request Tracebit AWS canary in three distinct slots so a scraper
that extracts any of them gets a key that fires Tracebit on replay.

| Path | Methods | Response |
| --- | --- | --- |
| `/swagger.json`, `/swagger/v{1,2,3}/swagger.json`, `/swagger/swagger.json`, `/api/swagger.json`, `/api/swagger` | `GET`, `HEAD` | OpenAPI 3.0.3 JSON document with canary |
| `/api-docs`, `/api-docs/`, `/api-docs.json`, `/api-docs/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api/v1/openapi.json`, `/docs/openapi.json`, `/api/api-docs`, `/openapi`, `/openapi.json`, `/api/openapi.json` | `GET`, `HEAD` | Same JSON document |
| `/openapi.yaml`, `/openapi.yml`, `/swagger.yaml`, `/swagger.yml` | `GET`, `HEAD` | Same document as YAML |
| `/swagger-ui.html`, `/swagger-ui/`, `/swagger-ui/index.html`, `/swagger/index.html`, `/swagger/swagger-ui.html`, `/swagger/ui`, `/swagger/ui/index.html`, `/webjars/swagger-ui/index.html`, `/webjars/swagger-ui/swagger-ui.html`, `/api/swagger-ui`, `/api/swagger-ui/`, `/api/swagger-ui/index.html`, `/api/docs`, `/api/docs/`, `/docs`, `/docs/` | `GET`, `HEAD` | Swagger UI bootstrap HTML pointing at `/swagger.json` |
| `/redoc`, `/redoc/`, `/redoc.html` | `GET`, `HEAD` | ReDoc bootstrap HTML pointing at `/openapi.json` |

## Canary placement

The Tracebit AWS canary is embedded in three independent slots inside
the JSON/YAML spec because credential-scraping tooling varies in which
parts of an OpenAPI document it pulls keys from:

- `components.securitySchemes.bearerAuth.x-example` — an extension
  field many spec-aware extractors treat as the bearer-token example
  to try first.
- `components.securitySchemes.apiKeyAuth.x-example` — same value, for
  scrapers that filter on `type: apiKey`.
- `servers[0].variables.adminApiKey.default` — server-variable defaults
  are surfaced by Swagger UI's dropdowns and pre-filled by autocomplete
  clients.
- `info.description` — plain-text mention of the bearer token in the
  free-text description so a `grep AKIA…` substring sweep finds it.

The advertised `paths` surface (`/auth/login`, `/admin/users`,
`/admin/config`, `/actuator/env`, `/healthz`) is chosen so that any
follow-up enumeration the scanner kicks off after parsing the spec
lands on other flux handlers (web-app form responder, cmd-injection
responder, actuator-env canary) rather than 404s.

## Logged fields

- `result` tags: `openapi-spec-json-issued`, `openapi-spec-yaml-issued`,
  `openapi-spec-json-skeleton`, `openapi-spec-yaml-skeleton`,
  `openapi-swagger-ui-html`, `openapi-redoc-html`
- `swaggerPath` — exact request path
- `swaggerKind` — `spec-json` / `spec-yaml` / `ui-html`
- `swaggerMethod` — HTTP verb
- `swaggerHasAuth` — bool, true when the probe arrived with an
  `Authorization` header or `X-Api-Key`
- `swaggerAuthScheme` — lowercased first word of the `Authorization`
  header when present (e.g. `bearer`, `basic`)
- `canaryStatus` — `issued` / `issue-failed` (spec paths only)
- `canaryTypes` — list of canary types present on the issued response

## Keyless behaviour

Without `TRACEBIT_API_KEY`, JSON/YAML paths return a credential-free
skeleton (`{"openapi": "3.0.3", "info": …, "paths": {}}`) instead of a
404. The skeleton is cheap to serve and avoids advertising the fake
admin endpoints without a canary backing them; UI paths still serve the
HTML stub because it carries no secrets either way.

## Why

OpenAPI/Swagger spec discovery is one of the highest-volume unauth
recon surfaces a public HTTP endpoint sees. Scanners walk a stable list
of canonical locations (SpringDoc at `/v3/api-docs`, FastAPI at
`/openapi.json` and `/docs`, Swashbuckle at `/swagger/v1/swagger.json`,
drf-yasg at `/api-docs/`, NSwag at `/swagger/v3/swagger.json`, plus the
`webjars/swagger-ui/` static-asset directory the Spring world serves
through). A real spec leaks the host's endpoint inventory plus, if a
developer left them in, example credentials. We embed a Tracebit AWS
canary in three places a credential-scraping bot reliably grabs and
return a single document on every variant, so a fan-out probe gets one
canary instead of N.
