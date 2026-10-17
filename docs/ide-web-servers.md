# JetBrains deployment config, and the step out of it

The file a JetBrains IDE writes when a project has a "Remote Host"
deployment target. A project directory committed or rsynced into the
webroot brings its whole `.idea/` with it, which is why credential
dictionaries walk this name.

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/.idea/webServers.xml`, `/.idea/WebServers.xml` | `200 text/xml` — a `WebServers` component with two `<webServer>` entries |
| `GET` | `/.idea/deployment.xml` | same body — the sibling file holding per-server path mappings |
| `GET` | `/idea/webServers.xml`, `/root/.idea/webServers.xml`, … | same body — undotted and home-rooted spellings |

Lookup is case-folded, so the two capitalisations are one table entry;
current IDEs write `webServers.xml` and older ones wrote
`WebServers.xml`.

The document carries two targets. The first is an **SFTP** entry whose
`host` is the hostname the request arrived on, on port 22, with a
`username` of the form `deploy_<8 hex>` and a per-hit random
`password`. The second is an unauthenticated FTP target on an internal
name, which is what makes the first one look like a choice rather than
the only thing in the file.

**No canary is issued.** Both credential-shaped fields are per-hit
synthetics, so the trap spends no issuance quota and has no upstream
dependency — `canary_types` is `()` and a test pins it that way.

## Why

Every other file in the credential table ends at the read. A key is
taken, and unless it is replayed against its issuer we learn nothing
more: the measurement is issuance, and the follow-through is somebody
else's telemetry.

A deployment config is different because it names a *next step* rather
than a secret to grep. It says there is an SFTP account at a particular
host, and here is the account. Acting on it means opening a connection
to the host the file names — and the file names the host it was served
from, for the same reason the MCP configs advertise this server's own
`/mcp` endpoint and the provider dotenvs point at its own `/v1` routes.
So the signal this trap is built for is not the fetch. It is the login
attempt that follows on the same host's SSH surface, carrying a username
of a shape nothing else emits.

That shape is the whole design of the credential fields:

- the **prefix** is fixed (`deploy_`) so an attempt is recognisable as
  "somebody acted on a deployment config served from here", and
  `deploy` is the ordinary name for a deployment account, so the prefix
  costs no plausibility;
- the **suffix** is random per hit, so one attempt traces back to one
  read rather than to the whole population of readers;
- the **password** is random per hit because a fixed literal gives zero
  detection on replay and ships the same string from every host running
  this software, which turns the deployment into a single fingerprint.

Naming the requested host is also what keeps the file plausible. A
config pointing at an unreachable `deploy.internal` is bait anyone can
spot. Behind a reverse proxy that rewrites `Host` the requested name
arrives as a loopback literal, so the host goes through the same
plausibility test and fallback order as `_mcp_self_endpoint` —
publishing `127.0.0.1` would advertise the reader's own machine and,
being identical everywhere this runs, fingerprint the deployment.

One hardening note worth keeping: the host reaches the renderer from a
request header and is interpolated into XML attributes.
`_host_is_externally_plausible` already rejects the quote and the angle
brackets, but it permits `&`, which is enough on its own to make the
document malformed — and a deploy config that does not parse reads as a
trap. The host is therefore escaped for attribute context.
