# Fake Tomcat Manager

Answers the operator-console vocabulary — Tomcat's Manager and Host
Manager, and the JBoss consoles the same dictionaries walk beside them —
the way a real deployment does: with a `401` and a Basic challenge rather
than a `404`.

## What it does

| Path | Methods | Response |
| --- | --- | --- |
| `/manager`, `/manager/html`, `/manager/status`, `/manager/status/all`, `/host-manager`, `/host-manager/html`, `/manager/jmxproxy` | `GET`, `HEAD`, `POST` | Unauthenticated: `401` + `WWW-Authenticate: Basic realm="Tomcat Manager Application"` and Tomcat's own 401 page. Authenticated: the Manager application list, including the deploy form |
| `/manager/text/list`, `/manager/text/serverinfo`, `/manager/text/sessions`, `/manager/text/threaddump`, `/manager/text/vminfo`, `/host-manager/text/list` | same | The text API's `OK - …` responses, which is the format tooling parses rather than the HTML |
| `/manager/jmxproxy` | same | The Runtime bean's system properties and environment, carrying a per-request Tracebit AWS canary in `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| `/manager/text/deploy`, `/manager/text/undeploy`, `/manager/text/reload`, `/manager/html/upload`, `/manager/html/deploy`, `/manager/html/undeploy`, `/manager/deploy`, `/manager/upload` | `POST` | Captures the uploaded body and answers `OK - Deployed application at context path [<path>]` |
| `/jmx-console`, `/web-console`, `/admin-console`, `/invoker/JMXInvokerServlet`, `/jmx-console/HtmlAdaptor` | same | Same challenge-then-serve behaviour, so one sweep meets one consistent server |

Matching is exact, case-insensitive, and tolerant of a trailing slash.
Bare `/status` and `/debug` are deliberately **not** claimed: they are
generic enough that surfaces flux already answers better live under them.

The handler logs `tomcatSurface` (`ui` / `text` / `deploy` / `console`),
`tomcatPath`, `tomcatMethod`, and on an authenticated request
`tomcatUsername`, `tomcatPasswordSha256` and `tomcatPasswordLen`. On a
deploy it adds `tomcatDeployBytes`, `tomcatDeploySha256`,
`tomcatDeployIsArchive` and `tomcatDeployPath`.

The password value is never stored. The hash is what groups one
dictionary entry across many senders; the length separates a dictionary
run from a random-blob one.

## Why

`/manager/html` is one of the most-asked-for addresses on the web, and it
was answering `404`. That is the cheapest possible end to an exchange: it
tells a scanner there is nothing here, and nothing further arrives. A
`401` says the opposite — there is something here worth a password — and
the passwords that follow are the measurement. The same reasoning covers
the JBoss consoles and the Host Manager, which the same dictionaries walk
in the same pass; answering some of them and 404ing the rest would be its
own fingerprint.

**Any credential is accepted, deliberately.** A sink that can never
succeed records the dictionary and nothing about what a client does once
it is in — and what it does once it is in is the more valuable half.
Every Tomcat Manager brute exists to deploy a WAR, so the Manager page
serves the real deploy form, naming `/manager/html/upload`, which gives a
client that parses the page a concrete next request instead of requiring
it to know the API. What arrives there is hashed and measured;
`tomcatDeployIsArchive` distinguishes an application that really arrived
from a client merely touching the address.

The **jmxproxy** surface is the one that carries a credential, and it is
the natural place for one: a JVM's environment is where a deployment's
cloud keys actually live, and reading it is precisely why a client asks
the proxy for the Runtime bean rather than any other. Because the value
is a per-request canary, what is read there is measurable if it is ever
used. Nothing else this trap serves is credential-shaped — the
application names and version are ordinary and fixed, because what is
worth faking is a plausible place to deploy into, not a secret.

The whole trap is gated on the issuing key, not just its own switch. Four
of five surfaces need no key, but a deployment answering those four and
404ing the fifth would be a louder tell than answering none.

## Known gap: `PUT /manager/text/deploy`

Tooling deploys with `PUT`, and that never reaches this handler — the
method gate in `handle()` turns away everything outside `GET`/`HEAD`/`POST`
before dispatch. That gate is a deliberate decision whose comment asks for
the blocked-method volume to be measured before it is widened, so this
trap does not quietly reopen it.

The consequence is worth stating plainly: from an automated client this
trap captures the credential but not the payload, because the credential
arrives on a GET and the payload would arrive on a PUT. The POST upload
path — the one this trap's own HTML advertises — captures both. This is
now a second concrete surface arguing for revisiting the gate, alongside
the PUT-delivered CVEs its comment already names.
