# Trap path walk

Lets an exact-path trap answer the same file when it arrives nested under
a recognised deployment directory.

| Behaviour | Detail |
| --- | --- |
| Env var | `HONEYPOT_TRAP_PATH_WALK_ENABLED` (default on) |
| Max depth | 3 leading segments |
| Gate | every dropped segment must be a known app-layout directory name |
| Home dirs | a leading `/root`, `/home/<account>` or service home is dropped first, then the rest resolves as if it had arrived at the webroot |
| Log field | `trapWalkDepth`, stamped only when the walk moved |

Resolution order is unchanged for anything that already matched:
`resolve_canary_trap` tries the exact path first, so a path with its own
table entry always keeps its own renderer. Only on a miss does it drop
leading directory segments one at a time and retry the lookup.

```
/admin/aws.json                            -> aws-credentials-json, depth 1
/admin/config/aws.json                     -> aws-credentials-json, depth 2
/src/main/resources/application.properties -> application-properties,  depth 3
/home/jenkins/.pulumi/credentials.json     -> pulumi-credentials,      depth 2
/9f2a1c/aws.json                           -> 404 (not a layout directory)
/admin/9f2a1c/aws.json                     -> 404 (stops at the first unknown segment)
/home/ubuntu/9f2a1c/aws.json               -> 404 (the home strip does not relax the gate)
/home/ubuntu                               -> 404 (a directory with no file after it)
```

The vocabulary is `_ENV_WEBROOT_PREFIXES` (already curated for the `.env`
family, so the two cannot drift) plus the app-layout credential prefixes,
an observed-layout extra list, and a set of leading-dot directories
(`.config`, `.github`, `.aws`, `.kube`, …) that appear either because a
repository is checked out into the webroot or because a home directory is
being served as one.

## Home directories

`_CRED_HOME_DIRS` is the account set a credential-dredging sweep walks:
distro cloud-image defaults, CI runner accounts, managed-service and
data/ML accounts, and the service accounts whose home is under
`/var/lib/`. The walk drops a leading match before doing anything else,
so `/home/jenkins/.aws/credentials` and `/.aws/credentials` resolve to
the same renderer.

This is a consistency property, not a coverage one. A handful of traps
used to enumerate `_CRED_HOME_DIRS` as literal table entries and the rest
did not, so the same sweep got a credential file for
`/home/ubuntu/.aws/credentials` and a 404 for the byte-identical
`/home/ubuntu/.pulumi/credentials.json`. No filesystem produces that
difference, so it fingerprints the responder to anyone who walks both —
which is what these dictionaries do, in a single pass. Two parametrized
tests assert the whole set answers, for every layout prefix and every
home directory, so the property cannot rot as the table grows.

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
argument, but the number moved: replaying a window of declined paths back
through the matcher showed the largest single group of leaves the table
already renders but never reached was the JVM build tree, which is three
deep by construction (`src/main/resources/`, `build/resources/main/`,
`target/classes/`). That is not unusual nesting, it is where the file
lives. Depth is not the gate in any case — every segment dropped must
independently be a layout name, so a third segment only widens the
surface where three consecutive layout words appear.
