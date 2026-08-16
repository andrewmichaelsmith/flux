# Deploy-sync config trap

Editor-plugin deploy configs, served with an SSH credential that our own
SSH honeypot can recognise on replay.

| Path | Method | Response |
| --- | --- | --- |
| `/remote-sync.json` | GET / HEAD | 200, `application/json` |
| `/ftp-sync.json` | GET / HEAD | 200, `application/json` |
| `/deployment-config.json` | GET / HEAD | 200, `application/json` |
| `/deploy-config.json`, `/deploy.json` | GET / HEAD | 200, `application/json` |
| `/ftpsync.settings`, `/.ftpsync.settings` | GET / HEAD | 200, `application/json` |
| `/.vscode/remote-sync.json`, `/.vscode/deployment-config.json` | GET / HEAD | 200, `application/json` |

All of the above also answer under a recognised app-layout directory
(`/admin/remote-sync.json`, `/config/deploy.json`, …) via the trap path
walk — see [trap-path-walk.md](./trap-path-walk.md).

The body is shaped like the real plugin files: an SFTP target on port 22,
an upload root under the webroot, ignore/watch lists. Three fields are
per-hit:

- **`host`** — the host the request actually arrived for, taken from
  `X-Forwarded-Host` / `Host`. A deploy config found on `example.com`
  that names `deploy.internal` is inert; one that names `example.com:22`
  is both what a single-box deployment really looks like and a target the
  finder can reach.
- **`username`** — `deploy_<first 8 hex of sha256(requestId)>`. Derived
  rather than drawn fresh so it is recoverable from the trap log line
  alone: the log already carries `requestId`, so nothing extra has to be
  written at issue time for a later replay to be tied back to one
  request, one source IP and one instant.
- **`password`** — a per-hit random synthetic.

The trap declares no Tracebit canary types and therefore makes no
upstream call. Tracebit's credential types alert on replay against
Tracebit's own endpoints, which is not where an SSH deploy credential
gets replayed; and having no upstream dependency means an API blip
cannot turn this trap into a 404.

## Why

Credential harvesting over HTTP and credential use over SSH are usually
measured as two separate populations, because nothing links them: the
harvest is observed on one plane and the use on another, with no shared
identifier. Operators that do both are not rare — the same source can run
a config-dredging sweep over HTTPS and a password brute against SSH.

A username that is unique per hit and reproducible from the trap log is
that shared identifier. Every sensor already runs an SSH honeypot that
logs the username on every authentication attempt, successful or failed,
so a harvested credential coming back is recorded without any further
instrumentation. What that yields is the piece HTTP-side telemetry cannot
produce on its own: the address that *used* the credential, which is
frequently not the address that took it.

Correlation is a join on the username shape `^deploy_[0-9a-f]{8}$`
against SSH-honeypot authentication events; a match names the exact trap
request the credential came from.
