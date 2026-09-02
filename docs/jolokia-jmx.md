# Jolokia JMX-over-HTTP

Jolokia is a protocol, not a page. `list` publishes the MBean tree; every
useful thing after that is a second request naming something the listing
just handed over. flux served the listing and 404'd the follow-ups, which
ended the exchange exactly one request before the client said what it
wanted.

## Mount points

`/actuator/jolokia`, `/jolokia`, `/manage/jolokia`, `/management/jolokia`,
`/monitoring/jolokia`, `/api/jolokia`, `/app/jolokia`, `/backend/jolokia`,
`/api/actuator/jolokia`, `/app/actuator/jolokia`,
`/backend/actuator/jolokia` — the Spring-mounted spellings and the
standalone-agent ones, plus the usual reverse-proxy prefixes. Matching is
case-insensitive. Every mount serves both the listing and the operations
beneath it; a mount that answered one and not the other would be the
tell.

## Operations

| Request | Method | Answers |
| --- | --- | --- |
| `<mount>` / `<mount>/list` | GET | The MBean tree (exact-path trap, `actuator-jolokia`) |
| `<mount>/list/<domain>[/<props>]` | GET | That subtree |
| `<mount>/version` | GET | Agent + protocol version. No canary |
| `<mount>/search/<pattern>` | GET | ObjectNames matching an `*` glob. No canary |
| `<mount>/read/<mbean>[/<attribute>[/<path>]]` | GET | One attribute, or the whole bean |
| `<mount>/write/<mbean>/<attribute>/<value>` | GET | Previous value, or a not-writable error |
| `<mount>/exec/<mbean>/<operation>[/<args…>]` | GET | The operation's return value |
| `<mount>` | POST | The same operations as a JSON object, or a JSON array for a bulk request (first 20) |

Jolokia's `!/` and `!!` escapes are undone before the path is split, so
an ObjectName containing a slash survives. A path under a mount that does
not name an operation falls through to the ordinary 404 — a prefix that
answered everything beneath it would announce itself.

Failures answer inside an HTTP 200, which is what the agent does: the
protocol carries its own status field
(`javax.management.InstanceNotFoundException`,
`AttributeNotFoundException`, `java.lang.IllegalArgumentException`). That
is worth answering rather than dropping — a client that learns the bridge
is live tries the next bean on its list, and each of those guesses is a
line in the dictionary being collected.

## What it logs

`jolokiaType`, `jolokiaMBean`, `jolokiaAttribute`, `jolokiaOperation`,
`jolokiaArgs`, `jolokiaForm` (`get` / `post`), `jolokiaResolved`, and for
a bulk POST `jolokiaBulkCount` / `jolokiaBulkTypes`.

`jolokiaHouseBean` is the discriminator. It is true when the request names
an MBean domain no real JVM has and no stock dictionary carries — one
whose only source is this server's own output, such as the package names
published under `/actuator/loggers` and `/actuator/mappings`. A client
reading `JMImplementation:type=MBeanServerDelegate` is running the agent
fingerprint every off-the-shelf Jolokia tool fires at every host; a client
naming a house bean parsed what we served it. The response is the same
either way, so the flag is the only place that difference is recorded.

## Where the credentials are

`java.lang:type=Runtime`'s `SystemProperties` and `InputArguments`, the
diagnostic bean's `vmCommandLine` and `vmSystemProperties`, the Spring
`Env` endpoint's `environment` operation, and every attribute of the
application's own config bean. All carry a per-request Tracebit AWS
canary in the `-Daws.accessKeyId` / `-Daws.secretKey` launch flags —
which is where a real misconfigured deployment leaks them. The Hikari
pool's `JdbcUrl` carries a per-hit synthetic DB password inline; nothing
credential-shaped here is a fixed literal.

`version`, `search`, the MBean-server delegate reads and the memory reads
carry nothing and mint nothing, so the agent-fingerprint sweep — which is
most of the traffic — costs no upstream quota.

## Why

Scanners reach the endpoint because `list` names
`com.sun.management:type=DiagnosticCommand`, whose `vmCommandLine` and
`vmSystemProperties` operations print the JVM's launch flags. That is a
credential-disclosure step and, on a real target, the doorway to JMX code
execution — so the request that goes after it is deliberate in a way a
dictionary sweep is not, and it carries the bean, operation and arguments
the client chose.

Two things follow. The follow-up request is the measurement: it is the
only place we learn which of the advertised beans a client considered
worth the second request. And a credential delivered through the JMX
bridge is a second, independent channel from the file-shaped traps — the
same canary reaching a replay from a different disclosure surface says
something the file traps cannot.
