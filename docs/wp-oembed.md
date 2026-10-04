# Fake WordPress oEmbed namespace

Serves the two routes of `oembed/1.0`, one of the three namespaces
WordPress core registers on every site.

| Path | Method | Response | Result tag |
|---|---|---|---|
| `/wp-json/oembed/1.0/embed?url=<local>` | GET, HEAD | `200` oEmbed document naming an author | `wp-oembed-embed` |
| `/wp-json/oembed/1.0/embed` (no `url`) | GET, HEAD | `400` `rest_missing_callback_param` | `wp-oembed-embed-missing-url` |
| `/wp-json/oembed/1.0/embed?url=<foreign>` | GET, HEAD | `404` `oembed_invalid_url` | `wp-oembed-embed-foreign-url` |
| `/wp-json/oembed/1.0/embed?format=<other>` | GET, HEAD | `400` `rest_invalid_param` | `wp-oembed-embed-invalid-format` |
| `/wp-json/oembed/1.0/proxy` | GET, HEAD | `401` `rest_forbidden` | `wp-oembed-proxy-unauthorized` |
| either route | other | `405` `rest_invalid_method` + `Allow: GET, HEAD` | `wp-oembed-method-not-allowed` |

Both routes resolve through the shared REST route helper, so every
spelling that layer already normalises arrives here for nothing: install
subdirectory prefixes (`/blog/wp-json/...`), the `?rest_route=` query
form permalink-less installs use, and percent-encoded separators the
path normaliser decodes before dispatch — the dot in `1.0` has been seen
encoded, which is a rule-bypass shape rather than a typo.

The embed route accepts `json` and `xml`, mirroring core's own format
enum. The handler logs `wpOembedRoute`, `wpOembedRequestedUrl`,
`wpOembedUrlOnHost`, `wpOembedMatchedSlug`, `wpOembedFormat` and, on a
hit, `wpOembedAuthor`. The author named is read out of the same roster
the user-enumeration trap lists, resolved from the matched post's own
author, so the two surfaces cannot disagree about who exists. Nothing
credential-shaped is fixed: the `data-secret` nonce in core's embed
markup is minted per response.

## Why

The discovery document has named this namespace since the REST index
trap shipped, and nothing underneath it answered. That is the
advertised-but-dead shape the index trap was built to remove, one level
up — in the namespace list rather than the routes map — so the routes
guard could not see it. A namespace that appears in the index and 404s
beneath is a tell no real install produces, because core registers both
routes unconditionally. A guard test now ties the namespace list to the
advertised routes table.

Each route also earns an answer on its own behaviour. `embed` is a
public author-disclosure surface: it names the author of the post behind
the URL, which is the username source that still works after the core
user list has been locked down. That name is the input to a run against
the login form, where that trap records the submitted pair — the same
enumerate / brute / capture chain the user-enumeration trap drives, on
the vector that survives hardening. The slot disclosed here is
deliberately not the one the user list leads with, so a credential run
opening on that name says which surface the operator trusted.

`proxy` is the server-side fetcher core adds for the block editor, and
it draws probes as a request-forgery primitive. Core gates it behind a
capability check that runs ahead of parameter validation, so an
anonymous caller gets a flat `401` — which is what this serves, because
the only other option is making the outbound request the caller asked
for. The refusal is both the authentic response and the one that still
records the target: a caller testing a server-side fetcher has to name
the host it wants contacted, and that name is infrastructure
attribution available from no other surface here. **This trap never
makes an outbound request.**
