# Cloud instance / container role-credential service

Serves the *ephemeral role credential* branch of the credential-harvester
dictionary: instance-metadata paths, container credential-provider
endpoints, and the webroot-relative spellings of both. The metadata
protocol has two steps, and this trap serves both — which is the point,
because only a client that implements the protocol will take the second
one.

| Method | Path | Response | Log tag |
| --- | --- | --- | --- |
| GET / HEAD | `/latest/meta-data`, `/aws/metadata`, `/.aws/metadata` (± trailing slash) | `200` + metadata key listing, no canary | `cloud-imds-index` |
| GET / HEAD | `<root>/iam` | `200` + `info` / `security-credentials/`, no canary | `cloud-imds-iam-index` |
| GET / HEAD | `<root>/iam/security-credentials` | `200` + the role **name** only, no canary | `cloud-imds-role-list` |
| GET / HEAD | `<root>/iam/security-credentials/<role>` | `200` + `Code`/`Type`/key/secret/`Token`/`Expiration` envelope | `cloud-imds-role-credentials` |
| GET / HEAD | `/v2/credentials`, `/v2/credentials/<id>`, `/ecs/task-credentials[.json]`, `/aws/ecs/task-credentials[.json]`, `/aws/iam/ecs-task-credentials.json`, `/.aws/ecs-task-credentials[.json]`, `/k8s/eks/credentials` | `200` + `RoleArn`/key/secret/`Token`/`Expiration` envelope | `cloud-imds-ecs-credentials` |
| GET / HEAD | `/v2/metadata`, `/v2/task` | `200` + JSON task metadata (cluster, task ARN, container image), no canary | `cloud-imds-ecs-metadata` |

Task metadata is the non-secret sibling of the container credential
endpoint and is swept in the same breath, so it is checked first and
answers as a listing — it is inventory, not secret, and spends no canary.
It is worth answering because it confirms to the client that it really is
talking to a container credential provider, which is the check that
decides whether the credential request is worth making.

Both credential envelopes carry a per-request Tracebit `aws` canary and a
forward-computed `Expiration`. Issuance failure logs
`cloud-imds-<kind>-error` and returns `502`. Every line carries
`imdsKind` and `imdsRole` — the latter is the role segment **as the
client sent it**, so a guessed name is recorded rather than normalised
away.

## Why

The listing endpoint returns a role *name* and nothing else; credentials
require a second request naming that role. That makes the pair a
behavioural discriminator that a single 404 destroys. A dictionary
sweeper fires the listing path because it is in its list, reads a body
with no secret in it, and moves on. A client that actually implements the
metadata protocol — an SSRF chain, a cloud-credential-stealing module —
parses the name and comes back for it. A `role-list` followed by a
`role-credentials` naming the role we just handed out is therefore a
positive identification of the second kind of client, and nothing else
flux serves distinguishes them.

The split also makes the trap cheap. Walking the tree issues no canary at
all, so a broad sweep across every listing path costs nothing upstream;
only the request that asks for a credential spends one.

Two envelope shapes are served because clients key on field names rather
than grepping bytes. The instance-metadata document carries
`Code: Success` with a `Type: AWS-HMAC` marker; the container provider
carries a `RoleArn` and no `Code`. Both name the session token `Token`,
not `SessionToken` — a provider implementation reading the wrong spelling
gets a credential it considers unusable, and the canary never gets
replayed.

These paths arrive at ordinary webroot rather than at the link-local
metadata address, so the scanner is betting the target is a reverse
proxy, an SSRF relay, or an app that mounted the metadata tree under its
own document root. Answering that bet is worth more than answering a
static key file: role credentials imply a live workload, and a harvester
that believes it holds a session token with a short life tends to use it
promptly. The advertised expiry is computed forward on every response for
the same reason — a stale one is the cheapest possible tell that the
envelope was canned.

The role name is fixed non-secret filler (`HONEYPOT_CLOUD_IMDS_ROLE_NAME`).
It must be stable for the chain to be followable, and an IAM role name
authenticates nothing, so a constant is safe here where a constant
*credential* never is.

Master switch: `HONEYPOT_CLOUD_IMDS_ENABLED` (default on); dispatch also
requires `TRACEBIT_API_KEY`, so keyless deployments 404 the whole
surface. `HONEYPOT_CLOUD_IMDS_CREDENTIAL_TTL_S` sets the advertised
lifetime (default 3600, floor 60).
