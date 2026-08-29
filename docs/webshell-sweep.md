# Shell-jacking sweep gate

Serves the fake webshell on *any* unclaimed `*.php` name in a shell-drop
position — webroot, or inside a WordPress asset directory — but only to a
source that has already demonstrated sweep behaviour.

## Matching

| Property | Value |
| --- | --- |
| Shape (webroot) | `^/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.php$` — one root-level segment |
| Shape (nested) | `^/(?:wp-content\|wp-admin\|wp-includes)(?:/<seg>){0,4}/<name>\.php$` — a `.php` leaf under a WordPress asset root, depth-bounded |
| Priority | Last in dispatch, after every exact-path trap has had its turn |
| Never matched | `/index.php`, `/home.php`, `/main.php` (webroot spellings only — there is no front controller inside `/wp-content/`, so the same filename one directory down is a shell hunt, not an innocent request); anything already in the curated `WEBSHELL_PATHS` list; anything another trap claimed |
| Methods | Whatever the webshell handler accepts (GET / POST, command in query, form, cookie or header) |
| Gate | `HONEYPOT_WEBSHELL_SWEEP_MIN_DISTINCT` (default 3) distinct matching names from one source inside `HONEYPOT_WEBSHELL_SWEEP_TTL_SECONDS` (default 3600) |

| Outcome | `result` | Status |
| --- | --- | --- |
| Under the threshold | `webshell-sweep-observed` | 404 `not found\n` |
| Gate open, no command | `webshell-probe` + `webshellSweepDistinct` | 200 |
| Gate open, command sent | `webshell-command` + `webshellSweepDistinct` | 200 |

Because the gate runs last, "unclaimed" is true by construction: every trap
with an opinion about the path has already answered. Requests under the
threshold get the byte-identical body the router's `not-handled` fallback
returns, so the 404 carries no evidence that a gate exists.

`webshellSweepDistinct` is on every gate-opened line and counts the distinct
names that source has asked for in the current window — the width of its
dictionary. Lines tagged `webshell-sweep-observed` record the names probed by
sources that never reached the threshold, so the sweep is measured even when
it is not served.

Config: `HONEYPOT_WEBSHELL_SWEEP_ENABLED` (default on),
`..._MIN_DISTINCT`, `..._TTL_SECONDS`, `..._MAX_SOURCES` (default 4096),
`..._MAX_PATHS_PER_SOURCE` (default 512). The last two bound the tracking
table the same way the canary cache is bounded. The gate also requires
`HONEYPOT_WEBSHELL_ENABLED`, since it hands off to that handler.

## Why

Scanners hunting for a shell somebody else already planted walk a large
dictionary of `.php` filenames. The curated list this trap started
with cannot track it: the dictionary is per-cohort, so a literal list is always
one cohort behind and rots between reviews. Recurring sweeps are observed at
scale across thousands of distinct filenames, the great majority of which no
literal list contains.

A large share of that hunting never touches webroot at all: it walks names
inside WordPress's asset directories instead — `/wp-content/uploads/index.php`,
`/wp-admin/js/index.php`, `/wp-content/plugins/admin.php` and so on, recurring
across many distinct sources. Those directories are the interesting ones
precisely because WordPress ships a *blank* `index.php` in each of them (the
"silence is golden" convention), so a `.php` there that actually does something
is somebody's planted shell. While the gate recognised only root-level names,
that entire family stayed on the 404 path no matter how wide a dictionary a
source walked. The nested shape is fixed to the three WordPress asset roots and
depth-bounded, so it widens what the gate recognises without admitting
arbitrary nesting, and the behavioural gate below is unchanged.

Matching the shape alone would be worse than the gap. A host that answers 200
to any `*.php` can be exposed with a single request for a filename the prober
invented, and that tell would be identical on every host running this code.
Gating on distinct-name count inverts the cost: reaching a 200 requires
performing the enumeration the trap exists to observe, while a one-off or
random probe is indistinguishable from a plain 404.

The gate is also the measurement. A literal-match trap can only report which
of *its* names were asked for; the counter reports how wide the source's own
dictionary is, and the below-threshold tag captures the names of sources that
never commit.
