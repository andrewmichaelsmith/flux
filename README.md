# flux

A small, single-binary HTTP honeypot intended to run behind nginx on a public
sensor. Pure stdlib Python (3.11+), no external dependencies at runtime.

Four layered traps, each independently toggleable via env var:

1. **Fake `/.env` canary issuer** — on a hit, mints a per-request Tracebit
   Community canary credential and returns it as a `.env`-style payload.
   Requires `TRACEBIT_API_KEY`; if unset, `/.env` is disabled and returns 404.
2. **Fake `/.git/` repository** — on a hit, mints a Tracebit canary and
   serves a loose-object git tree whose `config/secrets.yml` embeds the
   canary. Per-IP cached so `git-dumper`-style scanners see a consistent
   tree across their request fan-out. Also requires `TRACEBIT_API_KEY`.
3. **Fake webshell** — matches known webshell probe paths
   (e.g. `/wp-content/plugins/hellopress/wp_filemanager.php`, `/shell.php`,
   short-named `*.php` shells) and returns a plausible File Manager-ish
   page that invites follow-up commands. Simulates output for `id`,
   `whoami`, `uname -a`, `cat /etc/passwd`, etc. No Tracebit key required.
4. **Modular tarpit** — on `.env` variants (`.env.bak`, `*/.env.prod`,
   etc.), streams a slow-drip response. Pluggable modules:
   - DNS callback (redirect to `<uuid>.<your-domain>` to fingerprint DNS)
   - Cookie tracking (detects persistent cookie jars / cross-IP reuse)
   - Redirect chain (measure follow-depth)
   - Variable drip rate (fingerprint client timeout resolution)
   - Content-Length mismatch (claim large CL, drip slowly)
   - ETag / conditional-request probe

   No Tracebit key required.

All traps log one JSON line per event to the configured log path, suitable
for tailing into a log shipper.

## Install

```bash
pip install .
```

Or run in place:

```bash
python -m flux
```

## Run

Flux listens on `127.0.0.1:18081` by default. The expected deployment puts
nginx in front and proxies a set of trap paths (e.g. `/.env`, `/.git/*`,
`/shell.php`, etc.) to it; nginx handles TLS, `X-Forwarded-*` headers, and
all non-trap routing.

```bash
export TRACEBIT_ENV_HOSTS_CSV=trap-sensor.example.com   # which Host headers are "trap sensors"
export TRACEBIT_API_KEY=...                             # optional — enables /.env and /.git/
python -m flux
```

See [`CONFIG.md`](./CONFIG.md) for the full env var list.

## Tests

```bash
python -m pytest
```

## Why a fake webshell on a sensor that never had a real shell?

Because post-compromise scanners — e.g. the Azure WP Webshell Checker family
observed probing our sensors in April 2026 — walk a list of PHP shell paths
looking for "is my planted shell still here". They don't care whether your
site ever ran WordPress. A plausible response makes them send their *next*
command, which is the actual intel we want: the argument they pass, their
cookie jar, their user-agent rotation, whether they escalate.

The simulated command outputs are deliberately boring (`www-data`, a stock
`/etc/passwd`, a Linux 5.15 `uname`) and the form reflects whatever the
scanner submits. Unknown commands return empty output — the same thing a
real shell would produce for `cd foo` or a variable assignment — rather
than a canned "command not found" that outs the trap on the first probe.

## License

MIT. See [LICENSE](./LICENSE).
