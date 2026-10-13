# GPU/HPC cluster-scheduler credential traps

The credential files of an on-prem GPU cluster, as distinct from the
rented-capacity providers
[`inference-cloud-credentials`](./inference-cloud-credentials.md)
covers. That table answers the files holding an API key for somebody
else's GPUs; this one answers the files that grant *access to a
cluster* — the launcher's cloud credentials, the batch scheduler's
accounting-database password, the machine-API client certificate, and
the bootstrap user-data that injects all of it at first boot.

## Routed paths

| Trap name | Paths | Format |
| --- | --- | --- |
| `ray-cluster-config` | `/ray.{yaml,yml}`, `/ray-cluster.{yaml,yml}`, `/ray_cluster.yaml`, `/cluster/ray.yaml`, `/config/ray.yaml`, `/ray_bootstrap_config.json` (+ `/.ray/`, `/root/` prefixes) | YAML — cluster launcher, canary as the `provider` cloud credentials |
| `slurm-config` | `/slurm.conf`, `/slurm/slurm.conf`, `/etc/slurm/slurm.conf`, `/etc/slurm-llnl/slurm.conf` | Text — controller config, no credential (see below) |
| `slurmdbd-config` | `/slurmdbd.conf`, `/slurm/slurmdbd.conf`, `/etc/slurm/slurmdbd.conf`, `/etc/slurm-llnl/slurmdbd.conf` | Text — accounting daemon, per-hit `StoragePass` + canary in the archive credentials |
| `talosconfig` | `/talosconfig`, `/talosconfig.yaml`, `/.talos/config`, `/talos/config` (+ `/root/`, `/home/ubuntu/` prefixes) | YAML — Talos machine-API client config, per-hit cert blobs |
| `cloud-init-user-data` | `/cloud-init.{yaml,yml}`, `/cloud-config.{yaml,yml}`, `/user-data`, `/user_data`, `/userdata`, `/var/lib/cloud/instance/user-data.txt{,.i}` | Text — `#cloud-config`, canary in `write_files` |

Every member also answers its editor/backup sibling set (`.bak`,
`.old`, `.save`, `~`, …) on the same rule as the rest of the
credential-file tables: a scheduler config is exactly the file an
operator copies aside before editing a node list or rotating the
accounting password, and the observed sweeps ask for the sibling in the
same pass as the canonical name.

Three spellings in the same lane are served by traps that already
existed and were extended rather than duplicated: the `kubeconfig`
trap gained `/kubeconfig.json`, the SSH key tables gained the
`/ssh/`-without-the-dot and remaining-algorithm `.pub` spellings plus
the cluster-node key filenames (`/keys/gpu-key.pem`, `/gpu.pem`,
`/keys/ray-key.pem`), and the Kubernetes service-account mount gained
its bare `/serviceaccount/<leaf>` short form.

## What the handler does

Each renderer emits the file in its real on-disk format with the
Tracebit AWS canary in the field a credential extractor reads.

`ray-cluster-config` is the member that sets up a second step. Its head
node's dashboard address is **this host**, and its `ssh_private_key`
names `/keys/gpu-key.pem` — a path this server also answers, with an
issued SSH canary. A reader that parses the file rather than grepping
it therefore has two observable next requests, one of which is the
[Ray job-submission API](./ray-jobs-api.md), where the next thing it
sends is a command line.

`slurm-config` is the one member whose body is byte-stable across
hits, and deliberately so: `slurm.conf` is world-readable by design on
every compute node and holds no secret. It earns an answer because of
what it *names* — the accounting-database host and the `slurmdbd.conf`
beside it, which is the file that does hold a password. Answering it
and 404ing the sibling truncates the walk one request before the
credential. A regression test pins both the stability and the absence
of any secret-shaped field, so a credential added to this body has to
take the stability with it.

`talosconfig` gets no second step. The Talos API is gRPC over mTLS on
its own port, which this server does not answer, so unlike the launcher
config there is nothing a reader can do with the client certificate
that would be visible here. It is served as a static credential file
because the filename is walked in the same breath as the kubeconfig and
a 404 on it is a free negative signal.

## Why

Credential sweeps that used to ask only for web secrets (`/.env`,
`/.git/config`, framework configs) have been observed extending into
infrastructure credentials in a single dictionary pass: Kubernetes
client configs, SSH and deploy keys, and the GPU-cluster scheduling
artefacts above. The shift is from *an API key* to *cluster access*,
and the GPU-scheduling lane in particular asks for files that only
exist on a box with real compute attached — Slurm, Ray and a
`gpu-key.pem` are not generic web loot.

Most of that lane previously 404'd, which is worth more than a missing
response: a dictionary pass that gets a 404 learns the host is not a
cluster, and stops. Answering it keeps the walk alive to the step where
the reader has to send something of its own.
