# Ray dashboard job-submission API

The second step the
[cluster-launcher config](./cluster-scheduler-config.md) sets up, and
the one place in the GPU-cluster lane where the scanner's next action is
to hand us a command line instead of another path from a dictionary.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/api/jobs`, `/api/jobs/` | `GET` | a short list of plausible running GPU jobs |
| `/api/jobs`, `/api/jobs/` | `POST` | `{"submission_id":"raysubmit_…"}` — records `entrypoint` + `runtime_env` |
| `/api/jobs/<id>` | `GET` | that id reported `RUNNING` |
| `/api/jobs/<id>/logs` | `GET` | driver output that does not echo the entrypoint |
| `/api/cluster_status` | `GET` | autoscaler + load-metrics report, 2 GPU workers active |
| `/api/ray/version` | `GET` | `{"version":…,"ray_commit":…}` |
| `/api/serve/applications{,/}` | `GET` | empty Serve app map |

Each also resolves under a **mount prefix of up to two segments**
(`/ray/api/jobs/`, `/dashboard/ray/api/jobs/`), the same rule the
[code-exec surface](./code-exec-api.md) uses: a dashboard put behind a
reverse proxy is routinely mounted under its own name. Deeper than two
is not a mount and does not match.

`/api/version` is deliberately **not** claimed here. Ollama's version
endpoint already answers it on the
[inference surface](./fake-llm-api.md), and the job-submission walk does
not need it.

Content-Type `application/json; charset=utf-8` throughout. The trap
mints no canary, so unlike the canary-backed file traps it answers on a
deployment with no issuing key — a cluster config naming a dashboard
this server 404s is a dead end that gives the game away.

## What the handler records

**Nothing submitted is ever executed.** The handler records and
responds.

From a submission body: `rayEntrypoint` (the submitted command line, in
full to 2 KiB — this is the payload and the reason the trap exists),
`rayWorkingDir` and `rayPipPackages` from `runtime_env` (which is how a
submission that stages a remote archive differs from one that runs an
inline command), the requested and issued submission ids, and the
entrypoint CPU/GPU reservation.

From `runtime_env.env_vars`, **names only**. The values routinely carry
the submitter's own credentials, and those are not ours to retain.

A body that is not JSON still gets a submission id and is still covered
by the global `bodySha256` / `bodyPreview` fields rather than dropped.

A submission that names its own `submission_id` keeps it, because the
CLI polls the id it chose; echoing a different one ends the interaction
one request early. The job-log response deliberately does not quote the
submitted entrypoint back — a reader that sees its own command in the
driver output learns it was not run.

## Why

Ray's job-submission API requires no authentication by default. That is
public and long-documented — tracked as **CVE-2023-48022**, which
Anyscale disputes as intended behaviour, so the default has not changed
— and public reporting has exposed dashboards found this way abused for
compute theft. Scanners consequently treat a reachable Ray dashboard as
directly actionable rather than as something to fingerprint and leave.

That combination is rare and is what makes the endpoint worth serving.
Most of the trap surface answers a *read*: the attacker asks for a path,
and what we learn is which path they asked for. Here the attacker's next
step is a **write** — a job submission carries an entrypoint, a staging
URL and a package list, all chosen by the submitter. A captured
entrypoint is a payload, not a dictionary entry, and it joins back to
the config read that advertised the dashboard in the first place.
