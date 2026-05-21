# Backup-archive canary trap

Path-pattern trap that catches scanner enumeration of misplaced
backup archives in the webroot (`<base>.<ext>` cross-product),
including IP-octet- and date-derived filename synthesis.

| Paths | Method | Response |
|---|---|---|
| `/<base>.<ext>` where base ∈ ~95-name dictionary (`backup`, `db`, `www`, `wordpress`, `wp-content`, `htdocs`, `public_html`, `prod`, `production`, `secrets`, `src`, `dist`, `node_modules`, …) and ext ∈ {`tar.gz`, `tar.bz2`, `tar.xz`, `sql.gz`, `sql.bz2`, `tgz`, `tbz2`, `txz`, `tar`, `sql`, `gz`, `bz2`, `xz`, `zip`, `7z`, `rar`, `zst`} | `GET` | 200 — real archive in matching format containing `.env` + `backup.sql` with Tracebit AWS canary creds embedded |
| `/<ip-octets>.<ext>` (`/84.tar.gz`, `/84.180.zip`, `/65.20.84.180.sql.gz`) — IP-derived synthesis | `GET` | 200 — same archive body |
| `/<year-or-yearmonth>.<ext>` (`/2025.zip`, `/2026.tar.gz`, `/202603.zip`, `/20260310.tar.gz`) — date-derived synthesis | `GET` | 200 — same archive body |

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
   pattern matcher with a ~95-name gate captures the long tail
   without an enumeration list per actor.
2. **Filename synthesis from target attributes.** Newer scanner tools
   synthesize filenames from the resolved IP (`/<a>.<b>.<c>.<d>.tar.gz`,
   `/<c>.<d>.tar.gz`, `/<d>.tar.gz`) and from the current/recent date
   (`/2026.tar.gz`, `/202603.zip`). An exact-path trap can't enumerate
   these in advance because they depend on the target's IP. The
   pattern matcher accepts both shapes and serves the canary.

Per-hit-unique DB password and Azure key keep the archive body from
becoming a cross-sensor fingerprint. The AWS canary triple replays
against AWS STS regardless of which extension was requested.
