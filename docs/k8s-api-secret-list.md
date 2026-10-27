# Kubernetes API Secret / ConfigMap list traps

Flux answers the API-server listing endpoints of an anonymous-read
Kubernetes cluster with a plausible `SecretList` / `ConfigMapList`, each
carrying a Tracebit AWS canary.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/api/v1/namespaces/{default,kube-system}/secrets[/]`, `/api/v1/secrets[/]`, `/kube-system/secrets` | `GET`, `HEAD`, `POST` | `SecretList` JSON — AWS canary **base64-encoded** in an Opaque `aws-credentials` secret, plus a database secret and a service-account token |
| `/api/v1/namespaces/{default,kube-system}/configmaps[/]`, `/api/v1/configmaps[/]`, `/kube-system/configmaps` | `GET`, `HEAD`, `POST` | `ConfigMapList` JSON — AWS canary in **plaintext** in an `app-config` map, beside `kube-root-ca.crt` |

Lookup is case-insensitive and exact; single-object reads
(`/secrets/<name>`), pods and namespaces are not matched. The bare
`/kube-system/{secrets,configmaps}` spellings are not real API paths but
are emitted by sweeping dictionaries beside the real ones.

## What it logs

`result` = `k8s-secret-list` / `k8s-configmap-list`, plus the standard
canary-issuance metadata. The listed namespace echoes the one in the
request path (`default` when none is named).

## Per-hit uniqueness

The AWS key is a per-request canary. Object UIDs, resourceVersions, the
database password (`_fake_db_password()`), the service-account JWT, CA
blobs and creation timestamps are all random per hit.

## Why

Clusters that bind `system:anonymous` to a read role are a documented
initial-access path for cloud-native cryptojacking and credential theft
(MITRE ATT&CK T1552.007, *Container API*). Credential-dredging sweeps
request these listings in the same pass as `.env` and CI-workflow files,
and previously got a 404. The two lists place the canary differently on
purpose: a Secret's value only exists after base64 decoding, a
ConfigMap's is greppable in the clear — so a replay says which kind of
harvester took it, and whether it parses the Kubernetes object model at
all.
