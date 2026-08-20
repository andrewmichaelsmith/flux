# WordPress REST route alias (`?rest_route=`)

Not a trap — a normalisation that runs ahead of every path matcher, so
that the WP-REST traps flux already ships are reachable at both of the
addresses WordPress serves them from.

| Request | Dispatches as |
| --- | --- |
| `/?rest_route=/wp/v2/users` | `/wp-json/wp/v2/users` |
| `/index.php?rest_route=/batch/v1` | `/wp-json/batch/v1` |
| `/?rest_route=%2Fbatch%2Fv1` | `/wp-json/batch/v1` |
| `/blog/?rest_route=/gravitysmtp/v1/config` | `/wp-json/gravitysmtp/v1/config` |
| `/app/api?rest_route=/wp/v2/users` | *(not rewritten)* |
| `/?rest_route=/` | *(not rewritten — REST index, no trap behind it)* |

Every WordPress REST route has two public addresses. `/wp-json/<route>`
is the pretty one and only exists when permalinks are enabled and the
rewrite rules are live; `/?rest_route=/<route>` is the query form the
REST server always answers, equally valid on `/index.php`. WordPress
resolves both to the same handler. Flux matched only the first, so every
WP-REST trap it shipped was reachable at one address and invisible at the
other.

The resolver decodes `%2F`-escaped separators, takes the first value when
`rest_route` is repeated (PHP's `$_GET` is first-wins, so a decoy second
parameter cannot steer the rewrite), collapses a doubled leading
separator, and refuses any route containing `..`. It fires only when the
path is a WordPress front controller — `/` or `/index.php`, at the root
install or under a common install subdirectory — because that is the only
place WordPress itself honours the parameter. An unrelated application
that happens to take a `rest_route` query parameter is left alone.

The request is logged exactly as it arrived; the rewrite is recorded
beside it as `wpRestRouteAliasFrom` + `wpRestRoutePath`, so alias use
stays countable rather than being silently folded into the canonical
path's numbers.

## Why

Rule-based WAFs have the same blind spot flux had: a rule written against
the literal `/wp-json/wp/v2/users` does not fire on
`/index.php?rest_route=%2Fwp%2Fv2%2Fusers`. That is why scanners send the
query form. Tooling has been observed spelling a single REST endpoint ten
ways in one run — case-swapped namespace, `%2F`-encoded separators,
install-subdirectory guesses, and the `index.php?rest_route=` fallback —
firing an identical payload at each until one is not blocked.

Enumerating those spellings one at a time would lose the same race the WAF
loses, because the spelling set is generated rather than fixed.
Normalising the alias back to its canonical form wins it once, for every
WP-REST trap present and future, including spellings not yet observed.
