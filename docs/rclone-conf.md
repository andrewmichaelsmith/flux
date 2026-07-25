# rclone-conf

Fake `rclone.conf` — the per-remote credential store `rclone` writes at
`~/.config/rclone/rclone.conf` (and historically `~/.rclone.conf`).

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/rclone.conf`, `/.rclone.conf`, `/.config/rclone/rclone.conf`, `/root/.config/rclone/rclone.conf` | `200 text/plain` — INI-format config |

The rendered INI has two remote sections:

- `[remote-s3]` — S3 remote configured against `provider = AWS`, with the
  Tracebit AWS canary access-key-id / secret-access-key / session-token
  (session-token line omitted when the issued canary carries no session
  material). `region = us-east-1` and `acl = private` round out the shape.
- `[remote-b2]` — Backblaze B2 remote, `account` + `key` slots holding the
  same AWS canary halves. B2 is a common secondary destination in real
  rclone configs and shows up in most scanner dictionaries.

Both sections parse cleanly with `configparser`; a scanner using rclone's
own `--config` flag against a captured file would see two configured
remotes ready to `rclone ls`.

## Why

Unlike the AI-tool config traps, `rclone.conf` is a genuine one-to-one
fit for the Tracebit AWS canary type: the real file holds S3-shaped
`access_key_id` / `secret_access_key` pairs the scanner can immediately
try against AWS. A mid-July 2026 scanner cohort was walking this path
alongside the AI-tool credential-file dictionary but hitting 404. The
new handler serves a canary-backed INI in the exact shape `rclone` writes,
so a `cat rclone.conf | grep secret_access_key` grep-based harvester and
a replay-through-rclone lift both catch the trap.
