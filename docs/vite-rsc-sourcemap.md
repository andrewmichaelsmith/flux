# Vite RSC source-map file read

Answers the React-Server-Components source-map lookup as what scanners
actually use it for: a second arbitrary-file-read primitive on the same
dev surface `/@fs/` exposes.

| Property | Value |
| --- | --- |
| Env var | `HONEYPOT_VITE_RSC_SOURCEMAP_ENABLED` (default on) |
| Path | `/__vite_rsc_findSourceMapURL`, exact, case-insensitive |
| Filename parameter | `filename` (what the plugin itself sends), plus `file`, `url`, `source` |
| Accepted values | `file://<absolute path>`, or a bare absolute path |
| Refused values | any other scheme — `http://`, `https://`, `data:` |
| Resolution | `resolve_fs_read`, the same walk `/@fs/` uses |
| Methods | GET |
| Gate | requires an API key, as every canary-bearing read surface does |

| Outcome | `result` | Status |
| --- | --- | --- |
| Filename resolved to a trap | `vite-rsc-sourcemap-<trap>` | 200 |
| Filename resolved to a system file | `vite-rsc-sourcemap-<tag>` | 200 |
| Filename named a file nothing furnishes | `vite-rsc-sourcemap-miss` | 404 |
| No filename, or a remote scheme | falls through to the rest of dispatch | — |

The requested path, after `file://` strip and traversal collapse, is
logged as `viteRscSourcemapRequestedPath` whether or not anything
answered, with `viteRscSourcemapMatchDepth` recording how many leading
directory segments had to be dropped to find the renderer. Those are the
same two facts the `/@fs/` surface records, so one query answers "what
on-disk layout does this population believe in" across both spellings.

The body is the file, not a source map wrapping it. The endpoint's real
response shape is a source map, but every filename this surface is asked
for is a credential file with no source map to return — a real server
answers those with a 404, so the wrapper would be fidelity to a code path
that is never the one being exercised. What is being probed is whether
the parameter is a read primitive, and a read primitive returns the file.

## Why

Flux already owned this read: `resolve_fs_read` is shared by every
surface that hands out an arbitrary-file-read primitive, precisely so the
same filename cannot resolve on one spelling and 404 on the next. This
endpoint was a surface that walk had never been wired to, and the
consequence showed up in the dispatch log — the four filenames observed
on it are the same four the `/@fs/` dictionary asks for (an application
`.env`, a cloud credential file, an SSH private key, the process
environment), each one answered on the prefix spelling and 404ed on the
query-parameter spelling, by the same sources, often minutes apart.

That cost two things. The credential hand-off was lost on a surface the
population demonstrably trusts, and the host advertised that it furnishes
its read primitives inconsistently — no real passthrough bug resolves a
path one way and not the other, so the mismatch is a tell in a place
where the whole point is not to have one.

Two details are deliberate. A remote scheme is refused rather than
coerced into a filesystem lookup: a client asking this endpoint to fetch
a URL is probing for request forgery, which is a different finding and
has its own surface, and answering it off the file table would both
mislabel the request and claim a read that was never asked for. And a
bare hit with no filename falls through untouched, because a reachability
check is not a read and should not be recorded as a miss against a file
nobody named.

Worth noting for anyone reading the senders on this endpoint: the User
Agent is not usable evidence here. This population rotates declared
AI-crawler identities — a different well-known bot name per request —
while walking a credential dictionary and filesystem traversal
parameters. A sender-identity pass alone would read the traffic as benign
crawler activity; what settles it is what the same addresses ask for on
the surfaces already answering them.
