# WordPress plugin readme version probe

Serves `/wp-content/plugins/<slug>/readme.txt` — the packaging metadata a
version-gated exploit reads before it decides to fire.

| Path | Method | Response |
| --- | --- | --- |
| `/wp-content/plugins/<slug>/readme.txt` | GET / HEAD | `text/plain` readme in the documented format, `Stable tag` set low |
| the same, past the per-source cap | GET / HEAD | 404 |

The slug is whatever occupies that one path segment (`[A-Za-z0-9]` then up
to 63 of `[A-Za-z0-9._-]`), matched case-insensitively because the sweeps
are not consistent about case. Nested spellings
(`…/<slug>/lib/readme.txt`), themes, and the webroot `/readme.txt` are not
claimed, and the file-upload trap keeps the one readme it already serves
under its own library directory.

## What it logs

`wp-plugin-readme-probe` with `wpPluginReadmeSlug`, the
`wpPluginReadmeVersion` served, and `wpPluginReadmeDistinct` — the number
of distinct plugins this source has asked about. Past the cap the same
fields are logged under `wp-plugin-readme-capped` with a 404. The slug
column is the measurement: it is a direct read on which plugins the
scanning population currently carries exploits for, ranked by how many
sources ask.

## Why

A readme probe is reconnaissance with a decision attached. The file is the
plugin's own packaging metadata, its `Stable tag:` line is the installed
version, and one unauthenticated GET is enough to tell a scanner whether
the version-gated bug it is carrying is worth firing. A 404 answers that
question "no" — so the request behind it, the one carrying the payload,
never arrives. That makes the 404 expensive in a way its volume does not
suggest.

The version served is drawn from a deliberately low range. A version check
compares against an upper bound — fixed in *x*, so anything below is
vulnerable — and a low number reads as vulnerable against essentially any
such bound without needing to know which bug the sender has. It is derived
by HMAC from the slug and a per-process secret, which makes it stable for a
slug (a scanner that asks twice must not be told two versions) while
differing between hosts, so the fleet cannot be identified by collecting
one readme from each.

The surface is a family rather than a path list on purpose: observed
probing walks dozens of distinct slugs a month and the set turns over
continually, so an enumerated list would be stale the week it shipped.

## The cap, and why it points the other way

A source may be told about `HONEYPOT_WP_PLUGIN_README_MAX_SLUGS`
(default 6) distinct plugins per TTL; beyond that the rest go back to 404.

This is a cap, not a threshold, and the direction is the point. The
shell-jacking sweep gate *withholds* until a source has proved it is
sweeping, because a single unclaimed `.php` name is ambiguous. Here the
first probe is the valuable one — a scanner carrying one plugin's exploit
asks about exactly one plugin, which is the case worth answering
immediately. What has to be bounded is the opposite end: a source that
walks fifty slugs and is told all fifty are installed has learned the host
fabricates responses, and that is worth more to it than any single readme
is to us.

A slug already answered stays answered even once the source is at its cap.
Deciding on the count alone would mean a capped source started getting
404s for readmes it had already been handed, which contradicts the earlier
answer inside one burst — a sharper tell than never having answered. A
source that cannot be identified at all shares one bucket rather than
bypassing the cap, since that is the case where an enumeration oracle is
least affordable.

## Chaining

For the form-builder plugin whose upload action flux also answers, the
three steps now line up end to end: the readme supplies the version check,
the sibling nopriv action mints the nonce that the upload's check wants,
and the upload itself captures the payload. See
[wp-plugin-upload](./wp-plugin-upload.md).

Public context: plugin readmes are a documented WordPress packaging
convention, and version-gated plugin RCEs are exploited at scale — e.g.
CVE-2026-14894, an unauthenticated arbitrary file upload in a form builder
affecting all versions up to 6.3.313 and fixed in 6.3.314.
