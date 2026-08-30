# SSRF relay onto the cloud metadata tree

The [cloud metadata trap](./cloud-imds.md) answers requests that put a
metadata path at our webroot. This trap answers the *other* way the same
documents get asked for: a URL-taking parameter on a fetch-style
endpoint, pointed at the link-local metadata address. Same documents,
same canary, different client — and, until now, a flat 404.

The same parameter on the same entry paths is also swept with `file://`
targets in the same burst — the same read primitive aimed at disk instead
of the network — so that leg resolves here too, through the shared
file-read table rather than a second copy of anything.

## Routed paths

The trap fires only when the entry path is one of these **and** some
query parameter names a metadata host. An ordinary request to any of
them falls through to the router's 404.

| Method | Entry path | Fires when | Log tag |
| --- | --- | --- | --- |
| GET / HEAD | `/fetch`, `/api/fetch`, `/v1/fetch`, `/api/v1/fetch`, `/proxy`, `/api/proxy`, `/v1/proxy`, `/render`, `/api/render`, `/preview`, `/api/preview`, `/screenshot`, `/thumbnail`, `/url`, `/api/url`, `/import`, `/api/import`, `/download`, `/api/download`, `/image`, `/api/image`, `/webhook`, `/api/webhook`, `/webhook/test`, `/api/webhook/test` (± trailing slash) | a parameter value resolves to an EC2-layout metadata host | `ssrf-relay-aws-<imdsKind>` |
| GET / HEAD | same | a parameter value resolves to a GCP metadata host | `ssrf-relay-gcp-<index\|sa-index\|email\|token>` |
| GET / HEAD | same | a parameter value resolves to the Azure `/metadata/…` layout | `ssrf-relay-azure-<token\|instance\|versions>` |
| GET / HEAD | same | a parameter value names a `file://` path we furnish | `ssrf-relay-file-<trap>` |
| GET / HEAD | same | a parameter value names a `file://` path we do not | `ssrf-relay-file-miss` (404) |
| GET / HEAD | same | metadata host, document we do not emulate | `ssrf-relay-unmatched` (404) |

### On which spellings are listed

The entry path is matched exactly, so an unlisted spelling is a silent
miss that no amount of parameter-name generality recovers — the
parameter sweep only helps once the path already matched. Sweeps
observed against this surface use `/api/v1/fetch` alongside `/v1/fetch`,
and a bare `/api/webhook` alongside `/api/webhook/test`; both
`/api`-prefixed forms were missing. `/download` and `/image` are the
same bet as `/preview`: the client is guessing the application
dereferences a URL server-side.

`/redirect` is deliberately **not** an entry path. A redirect endpoint
answers with a 302 rather than dereferencing the target, so returning
metadata document content from one would be a shape no real application
produces. A test pins that it stays unmatched.

### On telling Azure from AWS

Azure's metadata service shares the link-local address with EC2's, so the
host cannot discriminate the two — only the layout can. Azure hangs its
tree under `/metadata/`, which never collides with the `/latest/` and
`/v2/` roots the EC2 resolver owns, so the path decides which cloud the
client meant. The Azure check runs **first** on that shared host, and a
test pins that it does not steal EC2-layout targets: an over-broad match
there would silently divert every AWS credential request.

`file://` is checked before either, because a `file://` URL has no
authority to match against the host tables at all. Three spellings
resolve — `file:///etc/…` (empty authority), `file://localhost/etc/…`
(the only authority the scheme allows), and the malformed-but-common
`file:/etc/…`. A real remote authority is not a local read and stays
unmatched.

Metadata hosts recognised: `169.254.169.254`, `169.254.170.2`,
`100.100.100.200` (Alibaba mirrors the EC2 layout), `instance-data`,
`instance-data.ec2.internal`, `metadata.ec2.internal`,
`metadata.google.internal`, `metadata.goog`, `metadata`.

## What the handler does

The target URL is taken from **any** parameter, not a fixed list of
names, and decoded twice — a single decode is what the transport already
did, and double-encoding is a routine filter bypass that a fetcher which
unquotes before dereferencing still resolves. Credentials in the
authority (`http://expected-host@169.254.169.254/`) are stripped, since
that is itself an SSRF filter-bypass idiom.

AWS-layout targets are resolved through `resolve_cloud_imds` — the same
table the direct trap uses, so there is no second path table to drift —
and served by the same renderer, which means the body is byte-identical
to what a direct probe gets and the credential step carries the same
per-request Tracebit `aws` canary. The GCP branch serves the tree
listings and the service-account address as non-secret filler; the token
endpoint mints a **per-hit synthetic** bearer token, because Tracebit
issues no GCP-shaped credential and a fixed literal would be one string
shared across every deployment.

The Azure branch serves the tree listings (`/metadata/instance`,
`/metadata/versions`) as non-secret inventory, and the managed-identity
token endpoint (`/metadata/identity/oauth2/token`) mints a **per-hit
synthetic** JWT-shaped bearer token, for the same reason the GCP branch
does: Tracebit issues no Azure-shaped credential, and a fixed literal
would be one string shared across every deployment. The JWT shape is
load-bearing — a client that actually uses the token parses it first.

`file://` targets resolve through `resolve_fs_read`, the same table that
answers `/@fs/<path>` reads and body-carried traversal, so a credential
file answers a relayed read with the same monitored canary it answers a
direct read with. Replay-side telemetry therefore does not depend on
which surface the attacker used to reach the file.

flux makes **no outbound request** and reads **no real file** on any
branch. A target we do not emulate is logged and refused, never fetched —
the trap must never behave like a working open proxy.

Every line carries `ssrfParam`, `ssrfTarget`, `ssrfHost`,
`ssrfTargetPath` and `ssrfCloud` on top of the usual metadata fields,
plus the `imdsKind` / `imdsRole` pair on the AWS branch, `azureResource`
on an Azure token request, and `ssrfFsRequestedPath` / `ssrfFsMatchDepth`
on the `file://` branch.

## Why

A credential-harvesting client that believes the target is a fetcher does
not know which parameter name the application used, so it sweeps several
spellings against one entry path. That sweep is the signal. Answering it
records the parameter dictionary the tooling is working from, which a 404
throws away — and the dictionary is more durable than any single IP,
because it is a property of the tool rather than of the infrastructure
renting it this week.

The two-step split inherited from the direct trap is what makes the
response worth serving rather than merely worth counting. The listing
step returns a role *name* and no secret; only a client that parses that
name and comes back for it — through the relay — gets a credential. A
`role-list` followed by a `role-credentials` naming the role we just
handed out is a positive identification of a client that implemented the
metadata protocol end-to-end through an SSRF chain, which is a much
narrower population than the one firing the entry path at all.

Separating `ssrf-relay-*` from `cloud-imds-*` matters for the same
reason. The bodies are deliberately identical, so without distinct tags
the indirect population would be silently merged into the direct one
after the fact, and the interesting question — does the client that
reaches metadata through a fetch parameter behave like the one that asks
for it directly? — becomes unanswerable.

Answering all three clouds rather than two removes an asymmetry the
client could read. A sweep that carries an AWS, a GCP and an Azure leg
and gets credentials on two of them has learned something about the
target — and on Azure specifically it is the leg most worth answering,
because Azure has no long-lived credential file to read off disk.
Managed identity is the only route to a token there, which is why the
file-oriented half of the same dictionary has no Azure equivalent and
why a 404 on that endpoint closes the only door.

The audience recorded on a token request is the sharpest statement of
intent in the whole sweep. A token for `management.azure.com` is for
taking over the subscription; one for `vault.azure.net` is for reading
the key vault; one for `storage.azure.com` is for the data. The requests
are otherwise identical, and only that parameter separates the
objectives — and it lives in the *target* URL's query, which path
matching throws away, so it has to be recovered deliberately.

The listing steps issue no canary, so a broad sweep across entry paths
and parameter names costs nothing upstream; only a request that actually
asks for a credential spends one.

Master switch: `HONEYPOT_SSRF_RELAY_ENABLED` (default on). Dispatch also
requires `TRACEBIT_API_KEY` and `HONEYPOT_CLOUD_IMDS_ENABLED`, so a
keyless deployment 404s the whole surface and the relay can never
outlive the tree it relays into.
`HONEYPOT_SSRF_GCP_SERVICE_ACCOUNT` overrides the filler service-account
address; `HONEYPOT_SSRF_AZURE_CLIENT_ID`,
`HONEYPOT_SSRF_AZURE_TENANT_ID` and
`HONEYPOT_SSRF_AZURE_SUBSCRIPTION_ID` override the equivalent Azure
identifiers. None of the four is a secret — they name a principal, they
do not authenticate as one.
