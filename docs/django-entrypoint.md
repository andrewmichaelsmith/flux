# Django / Flask entry-point module chain

Flux answers the modules a Python deployment is *started* from —
`manage.py`, `wsgi.py`, `asgi.py`, `app.py`, `environment.py` — and the
`/<project>/settings.py` those modules name. The pair is a chain, not two
files: the entry point's only valuable content is the
`DJANGO_SETTINGS_MODULE` line, because a deployment's project package name
is written down nowhere else, and a dredge that reads it learns where the
credential file actually lives.

The entry points carry **no credential and mint nothing**, so the family is
keyless and spends no issuance quota. Only the settings module issues,
through the same renderer the fixed-prefix `settings.py` table entry uses.

## Routed paths

| Path | Method | Response |
| --- | --- | --- |
| `/manage.py` | `GET`, `HEAD`, `POST` | Django management script; `os.environ.setdefault('DJANGO_SETTINGS_MODULE', '<project>.settings')` |
| `/wsgi.py` | same | WSGI config calling `get_wsgi_application()` |
| `/asgi.py` | same | ASGI config calling `get_asgi_application()` |
| `/app.py` | same | Flask application factory; names the module via `app.config.from_object('<project>.settings')` |
| `/environment.py` | same | hand-rolled environment-selection shim mapping each environment to `<project>.settings` |
| `<layout>/{manage,wsgi,asgi,app,environment}.py` | same | same renderers, across the app-layout prefixes (`app`, `storage`, `backend`, `backup`, `public`, `public_html`, `www`, `htdocs`) |
| `/<project>/settings.py` | same | the settings module the entry point named — AWS canary, byte-identical to the `app-config-python` body |

Content-Type: `text/plain; charset=utf-8`.

Each leaf renders **its own shape** — a `wsgi.py` whose body is a
`manage.py` is a tell to anything that reads past the first line.

## The per-client project name

`<project>` is an HMAC of the calling address over a 48-name vocabulary of
realistic `django-admin startproject` package names, under a secret
generated per process. So the name is:

- **stable** for one caller across connections, so a client that reads the
  module over one connection and asks for the settings file over another
  agrees with itself;
- **different** between callers, and different between deployments;
- **in no wordlist**, so it cannot be reached by enumeration;
- **stateless** — the server holds no per-client map a fan-out could grow.

The vocabulary is deliberately disjoint from the layout prefixes the
`app-config-python` table already owns (`app`, `core`, `backend`, `src`,
`project`, `config`, `instance`), so the chain can only ever add a route,
never move one.

## Logged fields

Standard request metadata plus:

- `result` = `django-entrypoint` for the module reads
- `result` = `django-settings-named` — the caller asked for the package
  *this process named to this address*. A path in no wordlist, unreachable
  by enumeration, so the request is evidence the module was **parsed**.
- `result` = `django-settings-foreign` — a vocabulary name this address was
  never given: the cross-deployment-replay shape, and also what sweeping
  the vocabulary looks like.
- `djangoProjectRequested` / `djangoProjectIssued` on both settings tags,
  so the pairing is auditable after the fact.

## Per-hit uniqueness

The entry points emit no credential-shaped field at all. The settings
module goes through `render_python_settings`, which mints a per-hit
`SECRET_KEY` and `DB_PASSWORD` and embeds the per-request Tracebit AWS
canary — two adjacent reads of the same route produce different bytes.

## Tuning

`HONEYPOT_DJANGO_ENTRYPOINT_ENABLED` (default: **on**) gates the family at
the single `find_canary_trap` lookup seam, so the switch covers the layout
walk and every other caller rather than only the exact-match route. The
settings chain additionally requires `CANARY_TRAPS_ENABLED`.

## Why this trap exists

The credential-file table already answered `settings.py` and `config.py`
across a fixed prefix set. The modules a Python deployment is *started*
from answered nothing — so a sweep got a miss on its first step and a hit
on its second.

Demand for the entry points is episodic rather than continuous: sweeps land
every few days from scripted clients, not from a steady crawl. The family
was selected on **the chain it enables, not on volume** — on volume alone
it would lose to generic crawler noise.

What the chain buys is a discriminator no fixed-prefix table entry can
produce. Naming a next step that *only the caller which received it* could
know separates a client that **parses** the surface from one replaying a
path list. That distinction is otherwise invisible: both populations
request the same paths and both get the same bodies.
