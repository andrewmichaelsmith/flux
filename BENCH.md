# Benchmark

`scripts/bench.py` spins up flux on `127.0.0.1:<random>` in-process, mocks
Tracebit canary issuance so the numbers reflect CPU not network, silences
`append_log` (otherwise we'd be benchmarking disk), and hammers each trap
path with N concurrent clients for D seconds.

```bash
pip install -e '.[dev]'
python scripts/bench.py                     # 32 clients, 3s per case
python scripts/bench.py -c 64 -d 5
python scripts/bench.py --tarpit-only       # concurrent-drip saturation only
python scripts/bench.py --throughput-only   # skip the tarpit saturation test
```

All latency columns are wall-clock ms measured per request via
`time.monotonic()`. `req/s` is the completed-request count divided by
wall-clock elapsed seconds of the run.

Run in the Claude Code web sandbox (Linux, x86_64, 16 logical cores,
Python 3.11.15, aiohttp 3.13.5), 32 concurrent clients, 3 s per case,
Tracebit canary issuance mocked (emulates the always-cached path — real
Tracebit round-trips would dominate the first hit per IP):

| Path                                         | req/s  | p50 (ms) | p95 (ms) | p99 (ms) |
| -------------------------------------------- | -----: | -------: | -------: | -------: |
| `/nope/does-not-exist` (404)                 |  1,173 |    26.72 |    32.40 |    38.08 |
| `/shell.php?cmd=id` (webshell)               |  1,888 |    16.65 |    23.64 |    27.15 |
| `/wp-content/plugins/hellopress/…` (webshell)|  1,996 |    15.45 |    22.35 |    27.10 |
| `/.aws/credentials` (aws INI)                |  2,421 |    13.20 |    16.72 |    18.75 |
| `/wp-config.php` (aws PHP)                   |  2,044 |    15.23 |    21.59 |    26.71 |
| `/backup.sql` (aws SQL)                      |  1,997 |    15.90 |    21.54 |    23.39 |
| `/config.json` (aws JSON)                    |  1,672 |    19.36 |    24.81 |    31.25 |
| `/id_rsa` (ssh PEM)                          |  1,965 |    16.06 |    21.28 |    24.85 |
| `/api/v4/user` (gitlab JSON)                 |  1,691 |    18.58 |    25.20 |    29.58 |
| `/users/sign_in` (gitlab HTML + Set-Cookie)  |  1,706 |    18.95 |    24.79 |    30.43 |

~2k req/s on fast-path traps in this shared sandbox; another run on the
same config returned 3.0–3.6k req/s for the same cases, so expect ±50%
run-to-run noise here. A dedicated single-core VM without noisy
neighbours should sit near the high end. CPU is spent on aiohttp
parse+serialize, not the renderers (small string ops).

Real production throughput is bounded by Tracebit on cache miss —
typically 50–200 ms per issuance at `community.tracebit.com`. The
per-`(IP, canary-type)` TTL cache means a scanner session fanning out
over one trap pays for one canary mint, not one per request.

To simulate real Tracebit latency:

```bash
python scripts/bench.py --simulate-tracebit-latency-ms 100
```

## Tarpit saturation

`TARPIT_MAX_CONNECTIONS` default is 256 (sized for an async event loop,
not a thread pool). With the cap in place:

| Concurrent `/.env.bak` clients | 200 | 503 | wall  |
| -----------------------------: | --: | --: | ----: |
| 64                             |  64 |   0 | 0.08s |
| 128                            | 128 |   0 | 0.16s |
| 256                            | 256 |   0 | 1.20s |
| 512                            | 418 |  94 | 1.52s |
| 1,024                          | 493 | 531 | 3.31s |

Each held drip is ~8 KB of coroutine state (not a thread), so raising
`TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS` another 10× is cheap if a real
burst trips the 256 default.

## What the benchmark doesn't cover

- **Real Tracebit latency.** The mock returns in microseconds;
  production will be tens to hundreds of ms on cache miss.
- **Log disk I/O.** Silenced here. A production sensor writing JSONL
  to local disk will add a few µs per request unless the disk is
  unusually slow.
- **TLS.** Flux runs behind nginx in production; TLS termination is
  nginx's job. This bench is plaintext HTTP.
- **Multi-process.** Single event loop only. Put multiple flux
  instances behind nginx if a single core can't keep up.
- **Network path.** Loopback only — no switch, no Internet latency.
