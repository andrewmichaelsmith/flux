# Java deployment-descriptor read

Answers the descriptors a Java servlet application keeps under `WEB-INF`
and `META-INF` as what scanners read them for: the product version that
selects the next, version-specific request, and the datasource block that
is where a real descriptor keeps a plaintext credential.

| Property | Value |
| --- | --- |
| Env var | `HONEYPOT_JAVA_DESCRIPTOR_READ_ENABLED` (default on) |
| Anchor | the first `WEB-INF` / `META-INF` segment, case-insensitive |
| Spellings | bare (`/WEB-INF/web.xml`), traversal-prefixed (`/files/../WEB-INF/web.xml`), and servlet path-parameter bypass (`/s/<rotating>/_/;/META-INF/...`) |
| Maven coordinates | `/META-INF/maven/<groupId>/<artifactId>/pom.properties` — coordinates collapse to the leaf, so any pair resolves |
| Methods | GET |
| Gate | requires an API key, as every canary-bearing read surface does |
| Dispatch order | after the normal canary dispatch, deliberately — see below |

| Descriptor | `result` | Carries |
| --- | --- | --- |
| `pom.properties` | `maven-pom-properties` | version + echoed coordinates; no secret |
| `META-INF/MANIFEST.MF` | `java-manifest-mf` | version/build metadata; no secret |
| `META-INF`/`WEB-INF/context.xml` | `tomcat-context-xml` | JDBC datasource, per-hit password + cloud canary |
| `WEB-INF/web.xml` | `java-web-xml` | servlet descriptor, context-params, per-hit password + cloud canary |
| `META-INF/persistence.xml` | `jpa-persistence-xml` | JPA datasource, per-hit password |

The anchored path is logged as `javaDescriptorRequestedPath` whether or
not anything answered, with `javaDescriptorPrefixDropped` recording how
many leading segments the anchor discarded. That count is the evasion
signal: zero is a plain read, non-zero means the request arrived wrapped
in a traversal or path-parameter bypass.

The version is fixed, and deliberately behind current. These descriptors
get read to decide what to send next, so a value that moved between two
reads of the same host would be the tell, and a value at the current
release would end the chain before the interesting request arrived. A
version string is not a credential; the datasource passwords are per-hit
synthetics and the cloud key is issued per request.

## Why

Two things made this family worth wiring up. It was the largest single
block of traffic the dispatch log recorded as unanswered, sustained over
months rather than a burst, and spread across a wide set of sources rather
than concentrated in one. And the request is not a credential grab — it is
a *fingerprinting* step, which means answering it buys an observation
nothing else does: which exploit a scanner picks once it believes it knows
the version. A 404 ends that conversation at the first turn.

The prefix is why a path list could not do the job. Most of this traffic
arrives through a front controller's static-resource route combined with a
path-parameter separator, and the segment in the middle is random per
campaign — enough distinct values have already been observed that any
enumerated list is stale on arrival. The anchor replaces the list: a
request that names `WEB-INF` or `META-INF` has declared where it believes
the application root is, so whatever sits in front of that is the
attacker's evasion attempt rather than a directory layout we would have to
recognise.

That distinction is load-bearing, because the generic layout walk
deliberately refuses to walk past a segment it does not recognise — a host
that answers `/9f2a1c/aws.json` has advertised that it says yes to
anything, which is a worse tell than the 404 it replaced. This surface
does not loosen that gate. It sits *after* the normal dispatch, so every
spelling that dispatch can already resolve is answered there and keeps its
own result tag, and only the spellings it refuses reach here. That is also
what keeps the `java-descriptor-` prefix meaningful: it marks a read that
got in by a spelling the normal path could not resolve, not merely a
member of this family.

Resolution reuses the shared trap table rather than a private one, so a
descriptor directory in front of a file some other trap already serves
lands on that trap instead of 404ing — the same reason the file-read
surfaces share one walk. A descriptor directory with a leaf nothing
furnishes 404s like a real container, and the requested name is still
logged, because what a sweep asked for is intel whether or not we had an
answer for it.

Known gap, left deliberately: the JSF resource-handler spelling
(`...faces.resource.../WEB-INF/web.xml.jsf`) is the same read behind a
third wrapper, and is not yet anchored — it appeared from a single source
and a suffix-stripping rule written for one observation is a guess.
