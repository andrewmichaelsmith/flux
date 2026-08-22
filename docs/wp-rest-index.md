# Fake WordPress REST API index

Serves `/wp-json/` — the document a REST-aware WordPress client reads
first — and every route that document advertises.

| Address | Response |
| --- | --- |
| `/wp-json`, `/wp-json/`, `/{blog,wordpress,wp,site,…}/wp-json/`, `/?rest_route=/` | `200` — index: site identity, `namespaces`, and a `routes` map with a self link per route |
| `/wp-json/wp/v2` | `200` — namespace index, the same document filtered to `wp/v2` |
| `/wp-json/wp/v2/{posts,pages,media,categories,tags,comments}` | `200` — collection listing, with `X-WP-Total` / `X-WP-TotalPages` |
| `/wp-json/wp/v2/{posts,pages,…}/<id>` | `200` object, or `404` with core's `rest_post_invalid_id` / `rest_term_invalid` / `rest_comment_invalid_id` envelope |
| `/wp-json/wp/v2/{types,taxonomies,statuses}` | `200` — the read-only descriptor objects |
| `/wp-json/wp/v2/search` | `200` — empty result set |
| `/wp-json/wp/v2/{settings,plugins,themes,users/me}` | `401` — core's own `rest_forbidden` / `rest_cannot_view_plugins` / `rest_cannot_view_themes` / `rest_not_logged_in` |
| `POST` to a collection | `401` `rest_cannot_create`; the submitted body is captured by the shared log context |
| `/wp-json/wp/v2/users[/<id>]`, `/wp-json/batch/v1` | Not claimed here — dispatched to their own traps, ahead of this one |

Trailing slashes and query strings are ignored for routing, matching is
case-insensitive, and an install subdirectory is stripped, so all the
spellings of one route reach one branch. Each response logs
`wpRestRoute`, `wpRestVariant` and `wpRestMethod` under a per-shape
result tag (`wp-rest-index`, `wp-rest-namespace-index`,
`wp-rest-collection`, `wp-rest-single`, `wp-rest-descriptor`,
`wp-rest-search`, `wp-rest-auth-required`, `wp-rest-collection-write`).

No canary is issued and no credential-shaped field appears in any body —
this trap is the chain that reaches the traps that do mint one, and a
test asserts nothing secret-shaped leaks into it.

## The advertised set is the served set

`_wp_rest_advertised_routes()` is read by both the index renderer and
the dispatcher, and a guard test fetches the index and then follows
every self link it publishes over the real dispatch path, failing on the
first one that reaches the generic 404 instead of a trap. A second test
mutates an unserved route into the advertised table and asserts the
guard notices. The index therefore cannot drift into advertising a route
nothing answers.

Routes WordPress does *not* register are deliberately left unmatched and
pinned by tests: `/wp/v2/custom-css`, `/wp/v2/attachments`,
`/wp/v2/global-styles`, and the prefix-less `/wp/v2/...` spelling that
some tooling emits after mis-joining a route key to the origin. A real
install 404s all of them; answering any would make this host
distinguishable from a real one, identically on every host.

## Why

Scanner tooling asks the discovery document before it spends a request
on a route, because the index is how it learns whether REST is reachable
at all. Traps were already sitting behind two of those routes — the user
roster and the request multiplexer — while the index that names them
returned the generic 404, so they were reachable only by a client that
already had the route hardcoded, and a client that started at the index
concluded REST was disabled and stopped.

This is the same defect the observability trap fixed for the Spring
actuator discovery index, in the same shape and for the same reason: a
vendor index whose own routes 404 is a shape no real deployment
produces, and it ends the walk exactly where the interesting part
begins.

The auth-gated routes matter more than they look. `401` with core's own
error code is a *stronger* answer than `200` would be: it is what proves
the route is registered, which is the thing the client is testing for,
and it is what a real unauthenticated request gets. The same logic
drives the indexed-miss envelope — a scanner walking ids reads
`rest_post_invalid_id` as "REST is live, that id is not" and keeps
going, where a bare 404 page reads as "REST is off".

The measurement this produces: a client that fetches the index and then
fetches a route it could only have learned there is implementing the
REST protocol rather than replaying a path dictionary, and the per-shape
result tags keep those two populations apart in the log.
