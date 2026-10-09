# Backup-archive canary trap

Path-pattern trap that catches scanner enumeration of misplaced
backup archives in the webroot (`<base>.<ext>` cross-product),
including IP-octet- and date-derived filename synthesis.

| Paths | Method | Response |
|---|---|---|
| `/<base>.<ext>` where base is a dictionary name (`backup`, `db`, `www`, `wordpress`, `wp-content`, `htdocs`, `public_html`, `prod`, `secrets`, `src`, `dist`, `mysql`, `postgres`, `schema`, `wwwroot`, …) and ext is a compressed or dump format (`tar.gz`, `tar.bz2`, `tar.xz`, `sql.gz`, `sql.bz2`, `tgz`, `tbz2`, `txz`, `tar`, `sql`, `gz`, `bz2`, `xz`, `zip`, `7z`, `rar`, `zst`, `dump`, `dmp`, `pgsql`, `psql`, `rdb`) | `GET` | 200 — real archive in matching format containing `.env` + `backup.sql` with Tracebit AWS canary creds embedded |
| `/<dir>/<base>.<ext>` where dir is itself a dictionary name (`/sql/db.sql`, `/backup/dump.sql`, `/admin/backup.zip`, `/wp-content/mysql.sql`) | `GET` | 200 — same archive body |
| `/<base>-<backup word>.<ext>` compounds in either order and any separator (`/database-backup.zip`, `/db_dump.sql`, `/backupdb.zip`), optionally carrying a date (`/backup-2026-09.zip`, `/backup-april-2026.zip`) | `GET` | 200 — same archive body |
| `/<ip-octets>.<ext>` (`/84.tar.gz`, `/84.180.zip`, `/65.20.84.180.sql.gz`) — IP-derived synthesis | `GET` | 200 — same archive body |
| `/<host>.<ext>` (`/example.net.zip`, `/example.zip`) — the domain-shaped sibling of the IP synthesis, matched only against the host on the request | `GET` | 200 — same archive body |
| `/<date-or-month>.<ext>` (`/2025.zip`, `/202603.zip`, `/2026-09.zip`, `/apr.zip`, `/april-2026.zip`) — date- and month-derived synthesis | `GET` | 200 — same archive body |

For `.zip` we serve a real zip with `.env` + `backup.sql` members.
For `.tar.gz` / `.tar.bz2` / `.tar.xz` / `.tar` we serve a real tar
in the matching compression. For `.sql.gz` / `.sql.bz2` / `.sql` we
serve a gzipped (or plain) MySQL dump. For `.7z` / `.rar` / `.zst`
we serve a tar.gz body under the claimed Content-Type — credential
harvesters typically grep raw bytes for `AWS_ACCESS_KEY_ID=` and
replay the canary regardless of whether their archive library
could actually extract the file. Content-Disposition is set to
`attachment; filename="<requested>"` so cli download tools name
the file the way they expect.

The handler runs **after** the exact-path canary-trap lookup, so
paths with a dedicated CanaryTrap entry (`/backup.sql` →
`sql-dump`) keep their specific renderer. Disabled if
`HONEYPOT_BACKUP_ARCHIVE_ENABLED=false`.

Two extension families are deliberately **not** claimed here. `.bak`
belongs to the app-config editor-leftover family, which answers it
with the named file's own renderer — serving a tarball for
`/config.php.bak` would replace a correct answer with a wrong one.
`.db` / `.sqlite` / `.sqlite3` belong to the
[embedded-database trap](./sqlite-db.md), which serves a real
database instead of an archive.

Log line carries `result: backup-archive`, `archiveExt: <ext>`,
`canaryTypes`, and `bytes`.

## Why

Backup-archive enumeration is one of the highest-volume scanner
families on the open internet. Across multiple actor populations we
see `<base>.<ext>` paths hit at hundreds-of-events/day cadence with
zero attribution because every probe currently 404s.

Two patterns make a pure path-list approach a bad fit:

1. **Open dictionary horizon.** The base-name list is operator-driven
   — every new actor adds a few names (`wp-backup`, `magento`,
   `joomla`, `dist`, `htdocs`) and the dictionary keeps growing. A
   pattern matcher captures the long tail without an enumeration list
   per actor.

   The shapes a single dictionary actually walks are wider than a
   bare `<base>.<ext>` grid, which is why the matcher states each as
   a rule rather than a table: the same pass asks for the name one
   directory down (`/sql/db.sql`), compounded with a backup word
   (`/database-backup.zip`), decorated with a month or a separated
   date (`/april-2026.zip`, `/backup-2026-09.zip`), and spelled from
   the target's own hostname. Answering part of a pass and 404ing the
   rest splits one sweep across two outcomes for no reason the sender
   can see.
2. **Filename synthesis from target attributes.** Newer scanner tools
   synthesize filenames from the resolved IP (`/<a>.<b>.<c>.<d>.tar.gz`,
   `/<c>.<d>.tar.gz`, `/<d>.tar.gz`), from the target's hostname
   (`/<host>.zip`, `/<first label>.tar.gz`), and from the
   current/recent date (`/2026.tar.gz`, `/202603.zip`). An exact-path
   trap can't enumerate these in advance because they depend on the
   target. The pattern matcher accepts each shape and serves the
   canary. The hostname rule is scoped to the host on the request, so
   it stays a synthesis rule rather than becoming a wildcard on any
   dotted stem.

Per-hit-unique DB password and Azure key keep the archive body from
becoming a cross-sensor fingerprint. The AWS canary triple replays
against AWS STS regardless of which extension was requested.
