# Soft-404 control-probe observer

Not a route. An annotation on whichever log line the request was already
going to produce, like the canary-echo and interpolation observers beside
it. **No response byte changes.**

| | |
| --- | --- |
| Paths | none — any path, matched on name shape |
| Methods | all |
| Response | unchanged; whatever would have been served is served |
| Env var | `HONEYPOT_SOFT404_PROBE_ENABLED` (default on) |
| Log tag | rides the answering trap's `result`; adds `soft404Probe*` fields |

## What it recognises

A request whose name says the sender does not expect it to exist.

| shape | example | what it is |
| --- | --- | --- |
| `declared-absent` | `/pscan-<hex>-nonexistent.txt` | a word that states the file is absent — `nonexistent`, `doesnotexist`, `notfound`, `catchall`, `randomstring`. Counts at any depth |
| `wrapped-token` | `/__ss_probe_<32 hex>__` | a token inside a `__…__` wrapper |
| `tagged-hex` | `/<tag><8–40 hex>` | a fixed tool tag plus a per-probe hex token, glued or separated |
| `tagged-counter` | `/<tag><9–16 digits>` | the same with a counter or millisecond clock |
| `bare-hex` / `bare-uuid` / `bare-alnum` | `/<32 hex>`, `/<uuid>`, `/<20 alnum>` | a generated name with no tag at all |
| `hinted` | `…probe…`, `…baseline…`, `…404…` beside a token | a weak word that only counts next to a token, never alone |

Fields: `soft404ProbeShapes`, `soft404ProbeMarker` (the absence word),
`soft404ProbeToken` and `soft404ProbeTokenKind`.

The token value is logged, not just a flag. A per-run random token groups
by nothing; a token hardcoded in a tool groups every address that runs it,
and that is the more useful of the two outcomes — one fixed 32-hex token
has already been seen arriving from unrelated addresses.

## What it deliberately does not recognise

- **Weak words alone.** `/probe`, `/baseline`, `/404.html`, `/test` are
  ordinary route names. They promote only beside a token.
- **Content-hashed build artefacts.** A hashed asset name is the one
  filename that is legitimately high-entropy, so the entropy shapes skip
  `.js` / `.css` / `.map` / image / font extensions — unless an absence
  word is also present, which no build tool emits.
- **Deep high-entropy names.** The entropy shapes require a root-level
  name. An object key, a cache shard and a content-addressed blob all
  live under a prefix, and all three are legitimately random.
- **Short names and plain digit groups.** A hex token must carry a letter
  or run to 16 characters, so an eight-digit order number or a date does
  not read as a token. Measured against recent distinct probe paths the
  observer flags ~2%, and on that sample every flagged name was a
  generated token.

Residual risk: a root-level route ending in a 9+ digit identifier can
still read as `tagged-counter`. That costs a spurious log field on a
request that is answered identically either way, which is why the shape
is reported rather than collapsed into a boolean.

## Why

A scanner that intends to act on a 200 has to know what a miss looks like
first — against a host that answers everything, every hit is worthless. So
it asks once for a name nothing could be serving and keeps the answer as
its baseline.

That request is the most informative one in a sweep and the least visible:
a 404 among 404s, indistinguishable from the rest of the dictionary in any
view keyed on status. Naming it splits the senders who validate their
baseline from the ones who do not — which is the difference between a
sweep whose 200s mean something to its operator and a sweep that would
have recorded our answer the same way whatever we served. The first group
is the one our traps are actually talking to.

Path only, and the response is never consulted. An observer that read the
body would cost a read on every request for a signal the name already
carries; one that changed the answer would let a sender separate this host
from a real one by sending a token and watching what moved.
