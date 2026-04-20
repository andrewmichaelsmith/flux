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

## Results

Run in the Claude Code web sandbox (Linux, x86_64, 16 logical cores,
Python 3.11.15, aiohttp 3.13.5), 32 concurrent clients, 3 s per case:

| Path                                         | req/s  | p50 (ms) | p95 (ms) | p99 (ms) |
| -------------------------------------------- | -----: | -------: | -------: | -------: |
| `/nope/does-not-exist` (404)                 |  1,847 |    16.97 |    20.17 |    24.04 |
| `/shell.php?cmd=id` (webshell)               |  3,483 |     9.01 |    10.96 |    12.31 |
| `/wp-content/plugins/hellopress/…` (webshell)|  3,422 |     9.12 |    10.98 |    12.09 |
| `/.aws/credentials` (aws INI)                |  3,626 |     8.63 |    10.28 |    11.07 |
| `/wp-config.php` (aws PHP)                   |  3,542 |     8.83 |    10.58 |    11.92 |
| `/backup.sql` (aws SQL)                      |  3,473 |     9.02 |    10.56 |    12.67 |
| `/config.json` (aws JSON)                    |  3,134 |     9.77 |    12.55 |    20.20 |
| `/id_rsa` (ssh PEM)                          |  3,454 |     8.97 |    11.46 |    13.59 |
| `/api/v4/user` (gitlab JSON)                 |  3,103 |     9.95 |    12.46 |    20.00 |
| `/users/sign_in` (gitlab HTML + Set-Cookie)  |  3,230 |     9.68 |    11.88 |    13.42 |

~3k req/s on fast-path traps, single-threaded Python. That's CPU-bound
on the aiohttp parse+serialize path, not renderer-bound (the renderer
functions are small string ops). The 404 case is noticeably slower in
aiohttp by design — its 404 path allocates a fresh response object and
doesn't benefit from the route match that the other cases follow.

Caching model: the per-`(IP, canary-type)` TTL cache means a scanner
fanning out against the same trap sees one canary mint + 1 h of cheap
re-serves. Real Tracebit round-trips would dominate the first request
per (IP, types) pair and cap real-world throughput at whatever
`community.tracebit.com` returns in — typically 50–200 ms per request.

## Tarpit saturation

`TARPIT_MAX_CONNECTIONS` default is 8. With the cap in place:

| Concurrent `/.env.bak` clients | 200 | 503 |
| -----------------------------: | --: | --: |
| 4                              |   4 |   0 |
| 8                              |   8 |   0 |
| 16                             |   8 |   8 |
| 32                             |   8 |  24 |
| 64                             |   8 |  56 |

Exactly at the cap, as expected. The cap's there to bound memory, not
CPU — each async drip costs ~8 KB of coroutine state, so raising the
cap 10×–100× is usually fine if you're hitting the limit on a live
sensor. Set `TRACEBIT_ENV_TARPIT_MAX_CONNECTIONS=256` (or higher) in
that case.

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
