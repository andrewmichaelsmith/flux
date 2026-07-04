# Kubernetes Secret / Deployment manifest canary

Flux serves a multi-document Kubernetes YAML on the paths credential
scanners walk when hunting checked-in cluster secrets. The response is
one Secret + one ConfigMap + one Deployment; the Tracebit AWS canary
appears in both base64-encoded (Secret `data:`) and plaintext (Deployment
`env:`) form so harvesters that filter either way pick it up.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/kubernetes.yaml`, `/kubernetes.yml`                  | `GET`, `HEAD`, `POST` | Secret+ConfigMap+Deployment YAML |
| `/kubernetes/secrets.yaml`, `/kubernetes/secrets.yml`  | same | same |
| `/kubernetes/secret.yaml`, `/kubernetes/secret.yml`    | same | same |
| `/kubernetes/deployment.yaml`, `/kubernetes/deployment.yml` | same | same |
| `/kubernetes/configmap.yaml`, `/kubernetes/configmap.yml`   | same | same |
| `/k8s/secrets.yaml`, `/k8s/secrets.yml`                | same | same |
| `/k8s/secret.yaml`                                     | same | same |
| `/k8s/deployment.yaml`, `/k8s/deployment.yml`          | same | same |

Content-Type: `application/yaml; charset=utf-8`. Case-insensitive exact
matches. Sibling of the existing `kubeconfig` trap
([`docs/kubeconfig.md`](./kubeconfig.md) — the kubectl config file
covers `~/.kube/config` and its home-dir prefix variants).

## Logged fields

Standard request metadata plus:

- `result` = `k8s-secret-manifest`
- Canary issuance metadata (canary id, expiration) recorded against the
  source IP.

## Per-hit uniqueness

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` are
  Tracebit AWS canary values (rotate per Tracebit issuance) and appear
  base64-encoded in the Secret `data:` block and plaintext in the
  Deployment `env:` block.
- `DB_PASSWORD` in the Secret is a per-hit random synthetic
  (`_fake_db_password()`) — a fixed literal would fingerprint the fleet.
- The Deployment / ConfigMap non-credential filler (image name, replica
  count, S3 bucket name, DB host) is fixed plausible — not credential-
  shaped, so no fleet-fingerprint risk.

## Why

Kubernetes Secret / Deployment / ConfigMap manifests get checked into
public git repos with populated credentials often enough that scanner
dictionaries include `/kubernetes/secrets.yaml`, `/k8s/deployment.yaml`,
and the bare `/kubernetes.yaml` alongside the more established
`/.aws/credentials`, `/wp-config.php`, `/.env` targets. Elevated recent
probe volume against these paths — most of it landing on the shipped
`miss` fallback rather than a canary — is the specific evidence that
justified the addition.

The two-form canary embedding (base64 in Secret, plaintext in Deployment)
follows what real leaked manifests look like: teams that use `envFrom:
secretRef` still commonly duplicate a couple of env vars inline in the
Deployment for override convenience. A harvester that only greps for
raw `AKIA*` bytes and skips base64 blobs would miss a bare Secret;
including the Deployment carrying the same values in plaintext closes
that gap.
