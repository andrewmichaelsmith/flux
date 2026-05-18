# Fake Spring Cloud Gateway Actuator surface (CVE-2022-22947 bait)

Extends the Spring Boot Actuator trap surface beyond `/env`,
`/heapdump`, `/configprops`, `/health`, `/mappings`, `/threaddump`
with the `/actuator/gateway/*` route-management endpoints scanners
walk for **CVE-2022-22947** — a SpEL (Spring Expression Language)
injection in Spring Cloud Gateway 3.0.x / 3.1.0 that yields
unauthenticated remote code execution.

## Routed paths

| Path | Methods | Response |
| --- | --- | --- |
| `/actuator/gateway/routes` | GET, HEAD | Fake route list as JSON with Tracebit AWS canary in `metadata.adminApiKey` / `metadata.adminApiSecret`; `spring-gateway-routes-list` |
| `/actuator/gateway/routes/{id}` | GET, HEAD | Same shape; `spring-gateway-route-get` |
| `/actuator/gateway/routes/{id}` | POST, PUT | Captures the SpEL payload, returns 201 Created with sanitised echoed id; result tag `spring-gateway-spel-rce-attempt` (when SpEL indicators fire) or `spring-gateway-route-add` |
| `/actuator/gateway/routes/{id}` | DELETE | 200 OK; `spring-gateway-route-delete` |
| `/actuator/gateway/refresh` | POST, PUT | Empty 200 OK; `spring-gateway-refresh` |
| `/actuator/gateway/globalfilters` | GET | Plausible Spring Cloud Gateway global-filter chain JSON; `spring-gateway-globalfilters` |
| `/actuator/gateway/routefilters`, `/actuator/gateway/routepredicates` | GET | Empty-object JSON (matches stock deployments); `spring-gateway-routefilters` / `spring-gateway-routepredicates` |
| Same paths under `/manage/gateway`, `/management/gateway`, `/api/actuator/gateway` prefixes | all | Same response — covers the reverse-proxy aliases the existing `actuator-env` CanaryTrap also serves |

Every response advertises `Server: Spring Cloud Gateway/3.1.0` —
pinned inside the CVE-2022-22947 public-disclosure window so
scanners deciding whether to ship the SpEL body don't bail on a
patched banner.

## Logged fields

Standard request metadata plus:

- `result` — one of the result tags above
- `springGatewayPath`, `springGatewayMethod`
- `springGatewayRouteId` — sanitised echoed id, capped at 120 chars
- `springGatewayHasSpel` — boolean; fires when the body or query
  contains any of `#{`, `${`, `T(java.lang`, `T(java.io`,
  `T(java.util`, `getRuntime`, `ProcessBuilder`, `Runtime.exec`,
  `ReflectiveOperation`, `new java.`
- `bodyPreview` (first 400 bytes of the request body)
- `canaryTypes` — set when a Tracebit canary was issued for the GET
  response

## Per-hit uniqueness

The fake route list embeds the per-request Tracebit AWS canary in
the `metadata.adminApiKey` / `metadata.adminApiSecret` slots, plus
in an `AddRequestHeader` filter named `X-Admin-Api-Key`. Two
back-to-back probes from the same IP within the canary cache TTL
get the same key (per-IP cache, mirrors `/.env`); probes from
different IPs get different keys.

The handler sanitises the echoed route id (alphanumeric / `._-`
only, capped at 120 chars) so flux's own response never ships
attacker-controlled tokens that downstream log/SIEM pipelines
might re-render unsafely.

## Why

Spring Cloud Gateway 3.0.x / 3.1.0 expose route-management
endpoints under `/actuator/gateway/*` when the Spring Boot
Actuator surface is configured to include them
(`management.endpoints.web.exposure.include=*` is a common
misconfiguration). CVE-2022-22947 lets an unauthenticated attacker:

1. **POST** to `/actuator/gateway/routes/{id}` with a JSON body
   whose `filters[].args.value` field contains a SpEL expression
   (`#{T(java.lang.Runtime).getRuntime().exec("id")}`). The gateway
   stores the route but does not yet evaluate the SpEL.
2. **POST** to `/actuator/gateway/refresh` — this forces the
   gateway to recompile the route table, evaluating the SpEL
   expression as a side effect.
3. **GET** `/actuator/gateway/routes/{id}` — the response echoes the
   evaluated value, so the command output lands back at the scanner.
4. **DELETE** `/actuator/gateway/routes/{id}` to clean up.

This trap mimics the entire four-step chain. The GET endpoint also
serves as an independent credential-leak surface even without the
exploit chain: a real Spring Cloud Gateway exposing
`/actuator/gateway/routes` to the public internet leaks every route
definition including any header / metadata values an operator put
in there. The canary lives in exactly that slot.

The existing `actuator-env` / `actuator-heapdump` / `actuator-mappings`
CanaryTraps cover the broader Spring Boot Actuator surface but route
each path by exact match. The dynamic-id `/actuator/gateway/routes/{id}`
shape required a dedicated handler — extending the CanaryTrap exact
list with every possible id would not work.
