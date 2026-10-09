# Embedded-database canary trap

Path-pattern trap that answers requests for an application database
left in the webroot (`<base>.db` / `.sqlite` / `.sqlite3`) with a
real, openable SQLite file carrying a Tracebit AWS canary.

| Paths | Method | Response |
|---|---|---|
| `/<base>.<ext>` where base is a backup/database dictionary name (`database`, `db`, `data`, `dump`, `app`, `prod`, `users`, `sessions`, `main`, `local`, …, plus a trailing index such as `db1`) and ext ∈ {`db`, `sqlite`, `sqlite3`} | `GET` | 200 — real SQLite with `users`, `settings`, `sessions` and `migrations` tables; the AWS canary triple sits in `settings` |
| `/<dir>/<base>.<ext>` where dir is a directory a database really lives in (`db`, `data`, `storage`, `var`, `writable`, `sites/default/files`, …) | `GET` | 200 — same database body |
| `/.config/gcloud/credentials.db` and the undotted / home-directory spellings | `GET` | 200 — real SQLite in gcloud's own schema: a `credentials` table whose `value` blob carries an OAuth refresh token |
| `/.config/gcloud/access_tokens.db` and the same spellings | `GET` | 200 — real SQLite with gcloud's `access_tokens` table and a `ya29.`-prefixed bearer token |

The body is built with `sqlite3.connect(":memory:")` and
`serialize()`, so what ships is a genuine database file rather than a
stub: a client that opens it gets a schema its queries survive.
`Content-Disposition` is set to `attachment; filename="<requested>"`.

The handler runs **after** the exact-path canary-trap lookup, so a
named database with its own renderer — the 1.7+ `/.svn/wc.db` working
copy — keeps it. Disabled if `HONEYPOT_SQLITE_DB_ENABLED=false`.

Log line carries `result: sqlite-db`, `dbFlavour` (the extension, or
`gcloud-credentials` / `gcloud-tokens`), `canaryTypes`, and `bytes`.

## Why

The dictionaries that walk `<base>.<archive ext>` walk the database
column in the same pass, and the database is the more valuable find:
an archive has to be unpacked before it yields anything, while an
embedded database carries the user table and the service credentials
together in a file the harvester can open directly. The base
vocabulary is derived from the archive trap's own list rather than
hand-written, because the two dictionaries are the same dictionary
with a different suffix column — a second hand-list is a second thing
to drift, and a test pins the two together.

The gcloud pair is named explicitly rather than left to the generic
rule. Those two filenames were previously declined on the grounds
that a malformed SQLite is more revealing than a 404. That is true of
a stub, but it stopped being the only option once a route in this
same server began building a genuine working-copy database the same
way; the premise, not the caution, was what had expired. A client
asking for `credentials.db` by name knows which column it wants, so
the schema it finds is gcloud's own.

Every credential-shaped value is per hit: the AWS triple is the
issued canary, and the password hashes, database and SMTP passwords,
application key and OAuth token bodies are freshly random on each
request. A fixed literal would give zero detection on replay and make
one string the same across every host serving the trap.
