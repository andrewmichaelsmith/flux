#!/usr/bin/env python3
"""Quick in-process benchmark for flux.

Binds flux to 127.0.0.1:<random>, mocks the Tracebit canary issuance so
we don't need a real key or network, then hammers each trap path with
N concurrent clients for D seconds and reports req/s + latency percentiles.

Usage:
    python scripts/bench.py                     # defaults: 32 clients, 3s per case
    python scripts/bench.py -c 64 -d 5
    python scripts/bench.py --tarpit-only       # concurrent-drip saturation test
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import aiohttp
from aiohttp.test_utils import TestServer

from flux import server


FAKE_TRACEBIT = {
    "aws": {
        "awsAccessKeyId": "AKIABENCHEXAMPLE",
        "awsSecretAccessKey": "benchSecretExampleKey",
        "awsSessionToken": "benchSessionToken",
        "awsExpiration": "2030-01-01T00:00:00Z",
    },
    "ssh": {
        "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nBENCH\n-----END OPENSSH PRIVATE KEY-----",
        "sshPublicKey": "ssh-ed25519 AAAABENCH canary@flux",
        "sshIp": "203.0.113.99",
    },
    "http": {
        "gitlab-username-password": {"credentials": {"username": "bench", "password": "benchpw"}, "hostNames": ["gl.example"]},
        "gitlab-cookie": {"credentials": {"name": "_gitlab_session", "value": "benchcookie"}, "hostNames": ["gl.example"]},
    },
}


def _make_fake_canary(latency_ms: float):
    """Return a mock _get_or_issue_canary that sleeps `latency_ms` per call.

    latency_ms=0 emulates an always-cached path (pure CPU).
    latency_ms=100 emulates a cache-miss against community.tracebit.com
    (typical p50 for a production hit).
    """
    if latency_ms <= 0:
        async def _fake(*_a, **_kw):
            return FAKE_TRACEBIT
    else:
        delay = latency_ms / 1000.0
        async def _fake(*_a, **_kw):
            await asyncio.sleep(delay)
            return FAKE_TRACEBIT
    return _fake


async def _patch_server(tmp_log_path, tracebit_latency_ms: float):
    server.API_KEY = "fake-key"
    server.CANARY_TRAPS_ENABLED = True
    server.TARPIT_ENABLED = True
    server.WEBSHELL_ENABLED = True
    server.FAKE_GIT_ENABLED = False
    server._get_or_issue_canary = _make_fake_canary(tracebit_latency_ms)
    server.LOG_PATH = tmp_log_path
    # Silence logging during bench — otherwise we're benchmarking the disk, not
    # the handler. Real deployments get logs; benchmarks care about CPU.
    server.append_log = lambda _payload: None


async def _worker(session, url, deadline, latencies, client_ip="203.0.113.200"):
    """One client's request loop. Each worker gets its own X-Forwarded-For
    so the per-IP canary cache behaves realistically — same worker = same
    'scanner IP' = cache-hit after the first request."""
    headers = {"X-Forwarded-For": client_ip}
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        async with session.get(url, headers=headers) as resp:
            await resp.read()
        latencies.append(time.monotonic() - t0)


async def _run_case(base_url, path, concurrency, duration):
    latencies: list[float] = []
    connector = aiohttp.TCPConnector(limit=concurrency, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Tiny warmup loop to let the process settle and warm any per-IP
        # caches (cache key is keyed on X-Forwarded-For below).
        for _ in range(min(10, concurrency)):
            async with session.get(
                f"{base_url}{path}", headers={"X-Forwarded-For": "203.0.113.200"},
            ) as r:
                await r.read()
        # Deadline starts *after* warmup so latency-simulating modes don't
        # get their clock eaten by the warmup.
        t_start = time.monotonic()
        deadline = t_start + duration
        tasks = [
            asyncio.create_task(
                _worker(session, f"{base_url}{path}", deadline, latencies, client_ip=f"203.0.113.{i}")
            )
            for i in range(concurrency)
        ]
        await asyncio.gather(*tasks)
        elapsed = time.monotonic() - t_start
    return latencies, elapsed


def _summary(name, latencies, elapsed):
    """All numbers are wall-clock (time.monotonic() deltas).

      n       = total requests completed
      wall    = total elapsed seconds of the test
      req/s   = n / wall
      p50/95/99, mean = per-request wall-clock latency in ms
    """
    if not latencies:
        print(f"{name:36s}  no samples")
        return
    latencies.sort()
    n = len(latencies)
    rps = n / elapsed
    p50 = latencies[n // 2] * 1000
    p95 = latencies[int(n * 0.95)] * 1000
    p99 = latencies[min(int(n * 0.99), n - 1)] * 1000
    mean = statistics.mean(latencies) * 1000
    print(
        f"{name:36s}  n={n:6d}  wall={elapsed:5.2f}s  req/s={rps:7.0f}  "
        f"p50={p50:6.2f}ms  p95={p95:6.2f}ms  p99={p99:6.2f}ms  mean={mean:6.2f}ms"
    )


async def bench_throughput(base_url, concurrency, duration, latency_note=""):
    cases = [
        ("404 (unhandled)",                "/nope/does-not-exist"),
        ("webshell /shell.php",            "/shell.php?cmd=id"),
        ("webshell long-path",             "/wp-content/plugins/hellopress/wp_filemanager.php"),
        ("canary /.aws/credentials",       "/.aws/credentials"),
        ("canary /wp-config.php",          "/wp-config.php"),
        ("canary /backup.sql",             "/backup.sql"),
        ("canary /config.json",            "/config.json"),
        ("canary /id_rsa",                 "/id_rsa"),
        ("canary /api/v4/user",            "/api/v4/user"),
        ("canary /users/sign_in",          "/users/sign_in"),
    ]
    header = f"throughput: concurrency={concurrency}, duration={duration}s per case"
    if latency_note:
        header += f"  [{latency_note}]"
    print(header + "\n")
    for name, path in cases:
        lat, el = await _run_case(base_url, path, concurrency, duration)
        _summary(name, lat, el)


async def bench_tarpit_saturation(base_url):
    """Open N connections to a tarpit path concurrently, count 200 vs 503."""
    cap = server.TARPIT_MAX_CONNECTIONS
    print(f"\ntarpit saturation: open N connections to /.env.bak, count 200 vs 503")
    print(f"  (TARPIT_MAX_CONNECTIONS={cap})")

    async def probe(session, hold_secs):
        t0 = time.monotonic()
        async with session.get(f"{base_url}/.env.bak") as resp:
            try:
                await asyncio.wait_for(resp.content.read(64), timeout=hold_secs)
            except asyncio.TimeoutError:
                pass
        return resp.status, time.monotonic() - t0

    # Probe around the cap so we can see the cliff clearly.
    levels = sorted({max(1, cap // 4), max(1, cap // 2), cap, cap * 2, cap * 4})
    for n in levels:
        connector = aiohttp.TCPConnector(limit=n, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            t0 = time.monotonic()
            results = await asyncio.gather(*[probe(session, 0.5) for _ in range(n)])
            wall = time.monotonic() - t0
        codes = [r[0] for r in results]
        s200 = sum(1 for c in codes if c == 200)
        s503 = sum(1 for c in codes if c == 503)
        print(
            f"  N={n:4d}  200={s200:4d}  503={s503:4d}  "
            f"(other={n - s200 - s503})  wall={wall:5.2f}s"
        )


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--concurrency", type=int, default=32)
    ap.add_argument("-d", "--duration", type=float, default=3.0)
    ap.add_argument(
        "--simulate-tracebit-latency-ms", type=float, default=0.0,
        help="Add this many ms of latency to every (mocked) canary call. "
             "Use 100 to approximate a cache-miss against community.tracebit.com.",
    )
    ap.add_argument(
        "--tarpit-cap", type=int, default=None,
        help="Override TARPIT_MAX_CONNECTIONS for the saturation test "
             "(default: whatever flux.server ships with).",
    )
    ap.add_argument("--tarpit-only", action="store_true")
    ap.add_argument("--throughput-only", action="store_true")
    args = ap.parse_args()

    import tempfile
    tmp = tempfile.NamedTemporaryFile(prefix="flux-bench-", suffix=".jsonl", delete=False)
    tmp.close()
    import pathlib
    await _patch_server(pathlib.Path(tmp.name), args.simulate_tracebit_latency_ms)

    if args.tarpit_cap is not None:
        server.TARPIT_MAX_CONNECTIONS = args.tarpit_cap
    server.TARPIT_INTERVAL_MS = 100  # fast drip for the test
    server.MOD_VARIABLE_DRIP_ENABLED = False
    server.MOD_DNS_CALLBACK_ENABLED = False
    server.MOD_REDIRECT_CHAIN_ENABLED = False
    server.TARPIT_MODULES = []

    app = server.create_app()
    test_server = TestServer(app, host="127.0.0.1", port=0)
    await test_server.start_server()
    base_url = f"http://127.0.0.1:{test_server.port}"
    try:
        if not args.tarpit_only:
            if args.simulate_tracebit_latency_ms > 0:
                note = f"simulated Tracebit latency = {args.simulate_tracebit_latency_ms:.0f} ms / call"
            else:
                note = "Tracebit mock returns instantly (emulates always-cached hit)"
            await bench_throughput(base_url, args.concurrency, args.duration, note)
        if not args.throughput_only:
            await bench_tarpit_saturation(base_url)
    finally:
        await test_server.close()


if __name__ == "__main__":
    asyncio.run(main())
