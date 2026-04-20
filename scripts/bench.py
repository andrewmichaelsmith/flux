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


async def _fake_canary(*_args, **_kwargs):
    return FAKE_TRACEBIT


async def _patch_server(tmp_log_path):
    server.API_KEY = "fake-key"
    server.CANARY_TRAPS_ENABLED = True
    server.TARPIT_ENABLED = True
    server.WEBSHELL_ENABLED = True
    server.FAKE_GIT_ENABLED = False
    server._get_or_issue_canary = _fake_canary
    server.LOG_PATH = tmp_log_path
    # Silence logging during bench — otherwise we're benchmarking the disk, not
    # the handler. Real deployments get logs; benchmarks care about CPU.
    server.append_log = lambda _payload: None


async def _worker(session, url, deadline, latencies):
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        async with session.get(url) as resp:
            await resp.read()
        latencies.append(time.monotonic() - t0)


async def _run_case(base_url, path, concurrency, duration):
    latencies: list[float] = []
    deadline = time.monotonic() + duration
    connector = aiohttp.TCPConnector(limit=concurrency, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Tiny warmup loop to let the process settle.
        for _ in range(min(20, concurrency)):
            async with session.get(f"{base_url}{path}") as r:
                await r.read()
        t_start = time.monotonic()
        tasks = [
            asyncio.create_task(_worker(session, f"{base_url}{path}", deadline, latencies))
            for _ in range(concurrency)
        ]
        await asyncio.gather(*tasks)
        elapsed = time.monotonic() - t_start
    return latencies, elapsed


def _summary(name, latencies, elapsed):
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
    print(f"{name:36s}  rps={rps:8.0f}  p50={p50:6.2f}ms  p95={p95:6.2f}ms  p99={p99:6.2f}ms  mean={mean:6.2f}ms  n={n}")


async def bench_throughput(base_url, concurrency, duration):
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
    print(f"throughput: concurrency={concurrency}, duration={duration}s per case\n")
    for name, path in cases:
        lat, el = await _run_case(base_url, path, concurrency, duration)
        _summary(name, lat, el)


async def bench_tarpit_saturation(base_url):
    """Open N connections to a tarpit path concurrently, count 200 vs 503."""
    print("\ntarpit saturation: open N connections to /.env.bak, count 200 vs 503")
    print(f"  (TARPIT_MAX_CONNECTIONS={server.TARPIT_MAX_CONNECTIONS})")

    async def probe(session, hold_secs):
        t0 = time.monotonic()
        async with session.get(f"{base_url}/.env.bak") as resp:
            # Read a small amount then let the semaphore hold.
            got_bytes = 0
            try:
                chunk = await asyncio.wait_for(resp.content.read(64), timeout=hold_secs)
                got_bytes = len(chunk)
            except asyncio.TimeoutError:
                pass
        return resp.status, got_bytes, time.monotonic() - t0

    for n in [4, 8, 16, 32, 64]:
        connector = aiohttp.TCPConnector(limit=n, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(*[probe(session, 0.5) for _ in range(n)])
        codes = [r[0] for r in results]
        s200 = sum(1 for c in codes if c == 200)
        s503 = sum(1 for c in codes if c == 503)
        print(f"  N={n:3d}  200={s200:3d}  503={s503:3d}  (other={n - s200 - s503})")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--concurrency", type=int, default=32)
    ap.add_argument("-d", "--duration", type=float, default=3.0)
    ap.add_argument("--tarpit-only", action="store_true")
    ap.add_argument("--throughput-only", action="store_true")
    args = ap.parse_args()

    import tempfile
    tmp = tempfile.NamedTemporaryFile(prefix="flux-bench-", suffix=".jsonl", delete=False)
    tmp.close()
    import pathlib
    await _patch_server(pathlib.Path(tmp.name))

    # Pick a reasonable MAX_CONNECTIONS cap for the tarpit test (so the
    # comparison is against the default, not whatever env vars were set).
    server.TARPIT_MAX_CONNECTIONS = 8
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
            await bench_throughput(base_url, args.concurrency, args.duration)
        if not args.throughput_only:
            await bench_tarpit_saturation(base_url)
    finally:
        await test_server.close()


if __name__ == "__main__":
    asyncio.run(main())
