# CI/CD deploy descriptors

Answers the deploy-pipeline files that secret-dredging dictionaries walk
alongside `.env` and `.aws/credentials`: the Kubernetes Azure
cloud-provider config, the Azure SDK-auth service-principal dump, and the
AWS CodeBuild / CodeDeploy specifications.

## Paths

| Family | Paths | Canary | Result tag |
| --- | --- | --- | --- |
| Kubernetes Azure cloud-provider config | `/azure.json`, `/etc/kubernetes/azure.json`, plus app-layout prefixes | `aws` | `azure-node-json` |
| Azure SDK-auth service principal | `/azure-credentials.json`, `/azure_credentials.json`, plus app-layout prefixes | `aws` | `azure-credentials-json` |
| AWS CodeBuild spec | `/buildspec.yml`, `/buildspec.yaml`, plus app-layout prefixes | `aws` | `codebuild-buildspec` |
| AWS CodeDeploy spec | `/appspec.yml`, `/appspec.yaml`, plus app-layout prefixes | none | `codedeploy-appspec` |

## Response

`azure.json` renders the cloud-provider config an AKS/aks-engine node
carries at `/etc/kubernetes/azure.json`, with the canary in
`aadClientSecret` — the slot that holds a real resource-group-scoped
credential on a live node. `azure-credentials.json` renders the block
`az ad sp create-for-rbac --sdk-auth` emits, canary in `clientSecret`.
Both regenerate their tenant / client / subscription GUIDs per hit.

`buildspec.yml` carries the canary pair under `env/variables`, which is
where the long-standing CodeBuild misconfiguration puts real keys
instead of using `secrets-manager`. `appspec.yml` deliberately carries
no credential and requests no canary: a real CodeDeploy spec has nowhere
to put a secret, so inventing a slot would read as bait to anyone who
knows the format — and issuing a canary for a document that cannot hold
one spends quota for nothing.

## Why

The two specs are the reason this is a separate trap rather than more
rows on the generic CI config family. They are *descriptors*: they name
other files by path. The buildspec references `.env.production` and a
`scripts/` hook, and the appspec references its lifecycle hook scripts —
paths this server already answers.

That makes the response a fork rather than a payload. A client that
greps the body for key material stops at the credential; a client that
parses the document and fetches what it names produces a second,
attributable request. Both outcomes are informative, and neither is
observable while the path returns 404. The credential-bearing files in
the same family keep the trap useful even against clients that never
parse anything.
