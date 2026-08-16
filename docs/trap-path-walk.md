# Trap path walk

Lets an exact-path trap answer the same file when it arrives nested under
a recognised deployment directory.

| Behaviour | Detail |
| --- | --- |
| Env var | `HONEYPOT_TRAP_PATH_WALK_ENABLED` (default on) |
| Max depth | 2 leading segments |
| Gate | every dropped segment must be a known app-layout directory name |
| Log field | `trapWalkDepth`, stamped only when the walk moved |

Resolution order is unchanged for anything that already matched:
`resolve_canary_trap` tries the exact path first, so a path with its own
table entry always keeps its own renderer. Only on a miss does it drop
leading directory segments one at a time and retry the lookup.

```
/admin/aws.json         -> aws-credentials-json, trapWalkDepth 1
/admin/config/aws.json  -> aws-credentials-json, trapWalkDepth 2
/9f2a1c/aws.json        -> 404 (not a layout directory)
/admin/9f2a1c/aws.json  -> 404 (walk stops at the first unknown segment)
```

The vocabulary is `_ENV_WEBROOT_PREFIXES` (already curated for the `.env`
family, so the two cannot drift) plus the app-layout credential prefixes
plus a small observed-layout extra list.

## Why

Secret-dredging dictionaries do not walk a flat list of filenames. They
walk the cross-product of `<layout dir>/<secret filename>`, so the same
`aws.json` / `config.json` / `phpinfo.php` leaf arrives dozens of times
with a different parent each time. Answering only the bare filename means
the overwhelming majority of such a sweep 404s on files the trap table
already knows how to render — the response was written, it just never got
reached.

Replaying two real dictionary sweeps against the matcher put the
before-figure at 11% and 30% of distinct paths answered. The gap is not
missing renderers; it is nesting.

The alternative — enumerating the cross-product as literal table entries
— is thousands of rows that rot independently and still miss the next
layout name. One bounded resolver stays correct as the table grows.

The vocabulary gate is the part that matters for camouflage. `/admin/…`
is a file a real deployment could plausibly have, so answering it looks
like a misconfigured server. Answering *any* parent directory would
instead advertise a host that says yes to everything, which is a far
louder signal than the 404s it replaced. The depth cap is the same
argument: two covers effectively all real nesting, and going deeper
widens the surface for nothing.
