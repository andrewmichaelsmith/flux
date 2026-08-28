# Canary-echo observer

Credentials this server hands out sometimes come back to it, inside a
later request, on a path nothing here serves. The observer makes that
countable. It serves no route of its own — it annotates whatever line
the request was already going to produce.

## What it does

| Aspect | Behaviour |
| --- | --- |
| Trigger | An AWS access key id (`AKIA`/`ASIA` + 16 uppercase alphanumerics) anywhere in the request target, the logged header subset, or the head of the body |
| Response | **Unchanged.** No status, header or byte differs from the same request without a key |
| Routes | None. Stamped before dispatch, so the fields ride on whichever trap answers |
| Upstream cost | None. Issues nothing |

Log fields added, when and only when a key id is present:

| Field | Meaning |
| --- | --- |
| `canaryEchoKeyIds` | The key ids found, most interesting first, capped |
| `canaryEchoMatch` | `own`, `account` or `foreign` — the closest relationship any of them has to this server |
| `canaryEchoIn` | Where they were found: `target`, `body`, `header:<name>` |
| `canaryEchoCount` | Distinct key ids found, before the reporting cap |

`own` means this process served that exact key. `account` means the key
came from the account this server issues from but was served elsewhere —
the only available evidence that a harvest is being replayed somewhere
other than where it was taken. `foreign` means somebody else's key:
nothing for us to alert on, but it says the sender is carrying loot from
elsewhere.

## How recognition works

`_aws()` is the single point every renderer reads an AWS canary through,
so registering the key id there covers every trap that embeds one — and
covers a newly written renderer the day it is written, without it having
to opt in. The registry is a bounded, insertion-ordered map of the ids
this process served, plus the account prefixes they imply. Re-serving a
key moves it to the newest position, so a credential still in use is not
the one evicted. Prefixes are never evicted: there are only ever a
handful, and forgetting one would silently downgrade `account` matches
to `foreign` after a busy day.

Nothing about the issuing account is written down in the source. This
repository is public, and a prefix committed here would let anyone test
a credential for canary-ness offline. Everything the observer knows, it
learned at runtime from credentials it actually served.

The key id is logged; the matching secret is neither matched on nor
copied into any field this feature adds. The id is an identifier — it is
what joins a replay back to the issuance that produced it. The secret
has no such use.

## Why

The alerting path for a stolen credential only sees it if the thief
calls the cloud provider with it. Everything else a thief does with a
credential is invisible there: pasting it into a URL, sending it as a
bearer token, posting it to a collector, using it as an identifier in
somebody's API. Those requests do arrive here, and before this they were
indistinguishable from any other 404.

Recognition is deliberately log-side only. A server that answered its
own canaries differently from any other string would be separable from a
real one by sending it a key and watching what changed — which would
cost more than the measurement is worth. The response is identical
either way; only the line written about it differs.

Matching on the request *shape* rather than on a served path is what
makes this durable. A client that improvises its own addresses defeats
every path-matched trap by construction, but it cannot echo a credential
without carrying the credential.

See also [inbound webhook receiver](./webhook-receiver.md), which keeps
the payload such a request arrives inside of.
