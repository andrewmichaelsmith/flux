# WordPress user-enumeration trap

Three public username-disclosure endpoints WordPress installs expose
out of the box: the core REST `/wp-json/wp/v2/users` surface, the
WordPress 5.5+ `/wp-sitemap-users-N.xml` shards, and the Yoast SEO
`/author-sitemap.xml` variant. Credential-stuffing scanners walk
these to harvest valid usernames before hammering `/wp-login.php`.

| Path | Methods | Response |
| --- | --- | --- |
| `/wp-json/wp/v2/users`, `/wp-json/wp/v2/users/` (any query string) | `GET`, `HEAD` | JSON array of fake user objects (`id`, `slug`, `name`, `link`, `avatar_urls`, `_links`) |
| `/wp-json/wp/v2/users/<numeric-id>` | `GET`, `HEAD` | `200` JSON user object on known id; `404` JSON `rest_user_invalid_id` envelope otherwise |
| `/wp-sitemap-users-N.xml` (any N) | `GET`, `HEAD` | WordPress core sitemap XML listing `<loc>https://<host>/author/<slug>/</loc>` per fake user |
| `/author-sitemap[N].xml` | `GET`, `HEAD` | Yoast SEO / RankMath sitemap XML with `<lastmod>` markers |

The handler logs:

- `wp-user-enum-rest-list`, `wp-user-enum-rest-single`,
  `wp-user-enum-core-sitemap`, `wp-user-enum-yoast-sitemap` —
  result tag identifies which surface fired
- `wpUserEnumVariant` — one of `rest-list`, `rest-single`,
  `core-sitemap`, `yoast-sitemap`
- `wpUserEnumPath` — the requested path (truncated to 200 chars)

The slugs returned are non-credential filler (`admin`, `editor`,
`webmaster`) and are deliberately fixed across the fleet — see the
flux README's design principle on credentials. The intent is to
feed plausible usernames into the existing `wp-login.php` trap so
the follow-up brute-force POST captures `wpLoginUsername` /
`wpLoginHasPwd` against names the scanner believes are real.

## Configuration

- `HONEYPOT_WP_USER_ENUM_ENABLED` (default: `true`) — master switch

## Why

WordPress's stock REST endpoint exposes every author slug to
unauthenticated clients, and the core sitemap + Yoast plugin
re-export the same slugs as URL paths. A scanner that walks any
of the three surfaces gets a "valid username" list cheaply; the
follow-up step is almost always a `/wp-login.php` POST against
each name. Returning a small plausible fake list lets us observe
that follow-up — which usernames the scanner picks, which
credentials it pairs them with, and whether the same source IP
that probed `/wp-json/wp/v2/users` is the one that brute-forces
`/wp-login.php`.

The trap pairs with the existing `wp-login.php` canary: enumerate
here → brute-force POST there → captured credential. Without
this trap a `404` on the enumeration surface bails the scanner
out before the chain reaches the credential-capture stage.
