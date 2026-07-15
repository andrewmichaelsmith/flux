# `.DS_Store` filesystem-metadata leak trap

macOS Finder writes a `.DS_Store` file into every browsed directory. When
developers on macOS `rsync` a webroot up to production, the whole tree
structure (folder names, file names, sort order, view state) leaks
alongside the site. Directory-hunter scanner dictionaries walk
`/.DS_Store` next to `/adminer.php`, `/whm`, `/.git/config`, and
`/.env`, because a single request enumerates the webroot faster than
any Autoindex fallback.

| Path | Methods | Response |
| --- | --- | --- |
| `/.DS_Store` | `GET`, `HEAD` | `application/octet-stream` body: `.DS_Store` binary (`\x00\x00\x00\x01Bud1` header + `DSDB` master record + one `Iloc` record per entry). HEAD returns the same headers with an empty body. |
| `/.DS_Store/` | `GET`, `HEAD` | Same response — some scanners canonicalise a trailing slash. |

Case-insensitive match on the exact path. Query string is stripped
before comparison. Deep-tree copies (`/wp-content/.DS_Store`,
`/backup/.DS_Store`, …) are not matched by v1 — the scanner
population that actually probes those is small and using an exact
match keeps the trap from swallowing paths a real deployment might
serve.

Response headers pin `Content-Type: application/octet-stream` (the
nginx default for `.DS_Store`), `Cache-Control: no-store`, and a
per-request `ETag: "<uuid4[:16]>"` so `If-None-Match` on later
hits doesn't act as a fleet fingerprint.

The handler logs:

- `result` tag `ds-store`
- `dsStorePath` — the exact request path
- `dsStoreMethod` — HTTP verb
- `dsStoreEntryCount` — number of filenames embedded in the body
- `bytes` — response payload length

Configuration:

- `HONEYPOT_DS_STORE_ENABLED` (default `true`) — master switch.
- `HONEYPOT_DS_STORE_PATHS_CSV` — override the path match set. Defaults
  to `/.ds_store,/.ds_store/`.
- `HONEYPOT_DS_STORE_ENTRY_NAMES_CSV` — override the filenames embedded
  in the returned binary. Defaults to a curated list of paths that
  route back into existing flux handlers when a scraper follows them
  up (`.env`, `.env.production`, `.git`, `.aws`, `backup.zip`,
  `backup.sql`, `admin`, `phpmyadmin`, `wp-admin`, `wp-config.php.bak`,
  `config`, `adminer.php`, `deploy`).

## Why

The purpose of this trap is not credential capture — the file itself
carries no credentials. It's a **discovery-and-followup surface**.
A scraper that runs `strings /path/to/.DS_Store` (or a mac_apt-style
DS_Store parser) extracts the embedded UTF-16BE record names and
hands them to a follow-up crawler. Every default entry name points at
a path that flux already handles (`.env` → env-production canary,
`.git` → fake-git tree, `wp-admin` → WP admin redirect, `adminer.php`
→ adminer login trap, `backup.zip` → backup-archive canary, …). So
the trap's success signal is the follow-on probe volume from the
same source IP within the next few minutes — a scanner that walks
into `/.DS_Store` and then probes three of the advertised paths on
the same TLS connection is materially more interesting than one
that just fetches `.DS_Store` once and moves on.

Real leaked `.DS_Store` files are common in the wild (search GitHub
for `filename:.DS_Store` and the leak surface is millions of repos);
the binary format is stable enough that lightweight parsers
(`ds_store`, `mac_apt`, custom `strings`-based tooling) all handle
the header + record layout the trap emits without bailing. Strict
buddy-allocator parsers may reject the file's free-list — that's a
deliberate trade-off; the loose-parse population is much larger than
the strict-parse population, and the loose parsers are the ones that
translate a `.DS_Store` fetch into follow-up scan traffic.
