# Injected path-prefix strip

Normalisation, not a trap. Runs inside `normalize_path` ahead of every
path matcher, so no handler has to know about it.

## What it strips

| Shape | What it actually is |
| --- | --- |
| `/~/…` | A home-directory reference no shell ever expanded, so `~` travelled as a literal path segment |
| `/$(pwd)/…` | Command substitution that was single-quoted, or fed to a tool that invokes no shell, so the substitution text became a segment |
| `/localhost/…` | A host that belonged in the authority component, concatenated into the path instead |
| `/:80/…`, `/:443/…`, `/:8080/…`, `/:8443/…` | The same mistake one component further on: a port, colon included, left in the path |

None of these is a directory any server has. They are path-generator
leakage — a template that was meant to build a URL and pasted in its
surroundings.

## Behaviour

Strips after the percent-decode, because the segment arrives encoded
(`/%24%28pwd%29/.env`) about as often as it arrives literally, and before
the traversal repair, so a stripped path still gets `..` resolved
normally. Bounded at `_INJECTED_PREFIX_MAX_STRIPS` (3) — a sender can
stack the segments, and an unbounded loop over attacker-chosen input is a
cost with no upside.

The raw spelling stays in `rawPath`. The stripped segment is stamped as
`injectedPathPrefix`, present **only** when one fired, so the field's
presence is exactly the signal and every other request keeps its existing
log shape.

## What it deliberately does not strip

- **`/~alice/…`** — `~` matches only as a whole segment, so a real
  per-user webroot is untouched.
- **`/blog/.env`** — a plausible subdirectory keeps whatever routing it
  already had. Only shapes that cannot be directories are stripped.
- **Service ports.** The port form is a closed set of web ports, not a
  `\d{1,5}` range. A colon port in the path is *meaningful* to the traps
  that model an SSRF reach onto a service port — the daemon-API trap
  reads `:2375` as the whole point of the request. Stripping every port
  would delete that signal in order to recover a credential path nobody
  probes on those ports. Add a port to `_INJECTED_WEB_PORTS` only when a
  dictionary is seen carrying it.

## Why

These spellings arrive on credential-file dictionaries, against families
this honeypot has already built. Before the strip, every one of them
404ed: `/~/.aws/credentials`, `/~/.boto`, `/~/.netrc`, `/~/.s3cfg`,
`/~/.git-credentials`, `/$(pwd)/terraform.tfstate`,
`/$(pwd)/docker-compose.yml`, `/$(pwd)/serverless.yml`,
`/$(pwd)/package.json`, `/:8443/wp-config.php`. The same sweep that took a
canary from the unprefixed spelling took nothing from these — so the
prefix, not the trap coverage, decided whether a credential dredge walked
away with something traceable.

The second reason is measurement. Which leak a sweep carries is a
property of its path generator, not of its target list, so
`injectedPathPrefix` separates tooling families that otherwise share a
credential dictionary — and a prefixed request is self-evidently
generated rather than hand-driven.
