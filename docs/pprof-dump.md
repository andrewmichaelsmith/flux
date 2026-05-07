# Go `pprof` debug-endpoint canary trap

Flux serves a plaintext heap-profile-shaped response on the standard
Go `net/http/pprof` debug endpoints, with a Tracebit AWS canary
embedded as if the process had its credentials in env vars and
cmdline args.

## Routed paths

All paths share one renderer; the response body is identical regardless
of which `pprof` sub-endpoint was probed.

| Path                              | Method                | Response |
| ---                               | ---                   | --- |
| `/debug/pprof`                    | `GET`, `HEAD`, `POST` | pprof text dump, AWS canary in env block |
| `/debug/pprof/`                   | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/heap`               | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/cmdline`            | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/goroutine`          | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/profile`            | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/symbol`             | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/trace`              | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/threadcreate`       | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/block`              | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/mutex`              | `GET`, `HEAD`, `POST` | same |
| `/debug/pprof/allocs`             | `GET`, `HEAD`, `POST` | same |
| `/api/debug/pprof[/...]`          | `GET`, `HEAD`, `POST` | same — reverse-proxy-prefixed variants |

## Logged fields

Standard request metadata plus:

- `result` = `pprof-dump`
- canary issuance metadata (canary id, expiration) recorded against the
  source IP

## Per-hit uniqueness

The DB password in the embedded `DATABASE_URL` is `_fake_db_password()`
(per-hit unique). The AWS credentials are minted per request via
Tracebit. Nothing in the response is a fixed fleet-wide literal.

## Tuning

The trap is a `CanaryTrap`, gated on the global `CANARY_TRAPS_ENABLED`
master switch (default: on) and on the presence of `TRACEBIT_API_KEY`.
There is no per-trap env var.

## Why this trap exists

Go's `net/http/pprof` package, imported as
`_ "net/http/pprof"`, registers debug-profiling endpoints under
`/debug/pprof/` on the default mux. A service that imports it without
restricting the route — e.g. a Go binary serving its main HTTP API on
the default mux, with no separate admin port — exposes its memory
profile, goroutine stacks, and command-line arguments to anyone who
asks. Real Go applications doing this is a known pattern (the
[Go security blog](https://www.veracode.com/blog/research/exposed-pprof-go-profiling-package)
covers it; CISA has issued advisories), and scanners hunt the path
family the same way they hunt `.git/config` and `.env.production`.

The valuable part of an exposed pprof endpoint is that a process whose
memory contains live cloud credentials leaks them through the heap
profile — both via the protobuf-encoded heap (which scanners parse)
and via the cmdline endpoint (which is plain NUL-separated text). The
renderer reproduces the latter shape with the canary embedded as if
the operator had passed AWS creds via cmdline args + env vars, which
is the configuration mistake that turns an exposed pprof into a
credential leak.

The 2026-05-06 weekly novelty pass observed the path family in scanner
traffic against our existing `.env`-family tarpit. None of those paths
matched a flux trap before this trap was added — the requests fell
through to a 404, which gives a scanner clear evidence the host
isn't running the misconfigured Go service they were hoping for, and
they move on. Returning a plausible plaintext heap dump turns those
404s into harvested canaries.
