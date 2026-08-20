# Fake WordPress REST Batch API (`/wp-json/batch/v1`)

WordPress core's request multiplexer, added in 5.6. One POST carries an
array of sub-requests; the server runs them and returns an array of
responses.

| Path | Method | Response |
| --- | --- | --- |
| `/wp-json/batch/v1`, `/wp-json/batch/v1/` | POST | `207` `{"failed":false,"responses":[…]}` — one entry per sub-request |
| same | GET / HEAD | `404` `rest_no_route` (core registers the route for POST only) |
| same, body not JSON | POST | `400` `rest_invalid_json` |
| same, no `requests` array | POST | `400` `rest_missing_callback_param` |
| same, over `HONEYPOT_WP_BATCH_MAX_REQUESTS` (25) | POST | `400` `rest_invalid_param` |
| `/{blog,wordpress,wp,site,news,cms,press,old,test,dev,backup,staging,…}/wp-json/batch/v1` | | same, subdirectory stripped |
| `/index.php?rest_route=/batch/v1` and its encoded spellings | | same, via the [REST route alias](./wp-rest-route-alias.md) |

Nothing is registered below the endpoint in core, so `/wp-json/batch/v1/run`
is left to fall through rather than answered on a guess.

The handler logs the sub-request array before answering any of it:
`wpBatchRequestCount`, `wpBatchRoutes`, `wpBatchMethods`,
`wpBatchValidation`, plus `wpBatchUsernames` and per-attempt
`wpBatchPasswordSha256` / `wpBatchPasswordLens` when a sub-request body
carries credentials under any of the spellings core, WooCommerce and the
common login plugins use. Password hashes make a dictionary correlatable
across rows, IPs and sensors without re-parsing bodies; the body preview
retains the attempt verbatim, the same contract the login trap uses.

Each sub-request is answered individually rather than with one canned
envelope. A sub-request enumerating users gets the same fake author roster
the standalone user-enum trap serves; everything else gets the stock
`rest_no_route` envelope. (Real WordPress additionally requires a route to
declare `allow_batch` — a deliberate deviation, since refusing every
sub-request would end the exchange at the first request.)

## Why

The batch endpoint is rate-limit amplification, which is what puts it in
credential tooling: a login brute that gets one attempt per request gets
`n` attempts per request through the multiplexer, and per-request throttles
never see the difference. It is reached through a
[path-variant generator](./wp-rest-route-alias.md) that spells the one
endpoint many ways to defeat literal WAF matching — the endpoint is worth
enough to the operator to be worth that effort.

That is also the argument for answering it rather than 404ing. A 404 costs
the operator one request. A plausible batch response costs them their plan:
the sub-request array is the entire list of what the tool intended to do,
submitted in one body, before any of it has been attempted. Nothing else in
the trap set gets an operator to declare intent up front, and the
enumerate-vs-brute distinction — visible in whether the bodies carry
credentials — is normally only recoverable after the fact, from volume.

Answering each sub-request individually keeps the chain alive: enumeration
returns usernames, usernames are the input to a brute-force run against
`/wp-login.php`, and the login trap captures the credential POST.
