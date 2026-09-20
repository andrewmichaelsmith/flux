"""Tests for the non-Node dependency-manifest traps.

Flux already answered the Node set (`package.json`, `package-lock.json`,
`yarn.lock`, `.yarnrc*`) and 404'd every other ecosystem's equivalent, while
harvesters walking a config/secret dictionary ask for all of them in the same
pass. Two things were wrong with that: the reads were simply lost, and a
server that hands over a Node lockfile but insists it has no `composer.lock`
describes a stack that does not exist — a tell available to anyone who asks
for both.

These tests pin that each ecosystem answers in its own native format, that the
private-registry credential each format carries is the canary (so a replay is
attributable), and that nothing credential-shaped is ever a fixed literal.
"""
from __future__ import annotations

import json
from urllib.parse import quote

import pytest
import pytest_asyncio

from flux import server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary  # noqa: F401

CANARY_USER = "deploybot42"
CANARY_PASS = "p@ssCanaryValue"
# Inside a URL the password is percent-encoded, which is what makes it
# recoverable rather than a parse error at the other end. Either spelling
# counts as "the canary is present"; a synthetic fallback would be neither.
CANARY_PASS_URL = quote(CANARY_PASS, safe="")


def carries_canary(body: str) -> bool:
    return CANARY_PASS in body or CANARY_PASS_URL in body


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def log_lines(path):
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


async def get(client, path, ip="203.0.113.40"):
    return await client.get(path, headers={"X-Forwarded-For": ip})


# --------------------------------------------------------------------------
# Routing — every spelling reaches the right renderer
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected_result", [
    ("/composer.json", "composer-json"),
    ("/composer.lock", "composer-lock"),
    ("/Gemfile", "gemfile"),
    ("/Gemfile.lock", "gemfile-lock"),
    ("/requirements.txt", "requirements-txt"),
    ("/requirements-dev.txt", "requirements-txt"),
    ("/requirements/base.txt", "requirements-txt"),
    ("/Pipfile", "pipfile"),
    # Editor-backup spellings. These matter for the same structural reason
    # the phpinfo family needed them: the webshell sweep gate only claims
    # names ending in `.php`, so a backup suffix puts the name permanently
    # out of its reach — only an entry can answer it.
    ("/composer.json.bak", "composer-json"),
    ("/composer.json.old", "composer-json"),
    ("/composer.json.save", "composer-json"),
    ("/composer.lock.bak", "composer-lock"),
    ("/Gemfile.lock.old", "gemfile-lock"),
    ("/requirements.txt.bak", "requirements-txt"),
    # `_TRAP_BY_PATH` lookups are case-folded, and the manifests are the
    # mixed-case names in this set (`Gemfile`, `Pipfile`), so the folding
    # is doing real work here rather than guarding a hypothetical.
    ("/gemfile", "gemfile"),
    ("/GEMFILE.LOCK", "gemfile-lock"),
    ("/pipfile", "pipfile"),
    ("/PIPFILE", "pipfile"),
    ("/COMPOSER.JSON", "composer-json"),
])
async def test_manifest_paths_route_to_their_renderer(
    flux_client, path, expected_result,
):
    resp = await get(flux_client, path)
    assert resp.status == 200, f"{path} must answer"
    entry = log_lines(flux_client.log_path)[-1]
    assert entry["result"] == expected_result


async def test_pipfile_lock_is_not_claimed(flux_client):
    """`Pipfile.lock` is JSON. Answering a JSON filename with the TOML
    `Pipfile` body would be a worse tell than the 404 it replaced, so it is
    deliberately left unclaimed."""
    resp = await get(flux_client, "/Pipfile.lock")
    assert resp.status != 200 or b"[[source]]" not in await resp.read()


# --------------------------------------------------------------------------
# Format fidelity — each answer has to parse as what it claims to be
# --------------------------------------------------------------------------

async def test_composer_json_is_valid_json_with_the_canary_in_http_basic(flux_client):
    body = await (await get(flux_client, "/composer.json")).read()
    doc = json.loads(body)
    assert "require" in doc and "repositories" in doc
    basic = doc["config"]["http-basic"]
    host = next(iter(basic))
    assert basic[host]["username"] == CANARY_USER
    assert basic[host]["password"] == CANARY_PASS, (
        "the replayable credential must be the canary, not a synthetic"
    )


async def test_composer_lock_is_valid_json_and_pins_every_package(flux_client):
    doc = json.loads(await (await get(flux_client, "/composer.lock")).read())
    assert doc["packages"], "a lockfile with no packages is not a lockfile"
    for pkg in doc["packages"]:
        assert pkg["source"]["reference"], "each package pins a commit"
        assert carries_canary(pkg["dist"]["url"]) or carries_canary(pkg["source"]["url"])


async def test_gemfile_and_lock_carry_the_canary_in_the_source_url(flux_client):
    gemfile = (await (await get(flux_client, "/Gemfile")).read()).decode()
    assert 'source "https://rubygems.org"' in gemfile
    assert CANARY_USER in gemfile and carries_canary(gemfile)

    lock = (await (await get(flux_client, "/Gemfile.lock")).read()).decode()
    # Bundler's own section order — a lockfile missing these reads as fake
    # to anything that actually parses it.
    for section in ("GEM\n", "PLATFORMS\n", "DEPENDENCIES\n", "BUNDLED WITH\n"):
        assert section in lock, f"{section.strip()} section missing"
    assert carries_canary(lock)


async def test_requirements_txt_uses_the_extra_index_url_spelling(flux_client):
    body = (await (await get(flux_client, "/requirements.txt")).read()).decode()
    assert "--extra-index-url" in body, "pip's own private-index spelling"
    assert CANARY_USER in body and carries_canary(body)
    assert "--hash=sha256:" in body


async def test_pipfile_is_toml_shaped_with_two_sources(flux_client):
    body = (await (await get(flux_client, "/Pipfile")).read()).decode()
    assert body.count("[[source]]") == 2, "public index plus the internal one"
    assert "[packages]" in body and "[requires]" in body
    assert carries_canary(body)


# --------------------------------------------------------------------------
# The invariant that matters most: nothing secret-shaped is ever fixed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/composer.json", "/composer.lock", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile",
])
async def test_credential_is_the_canary_not_a_fleet_wide_literal(flux_client, path):
    """Two different clients must not be served the same secret.

    A hardcoded credential provides zero detection on replay and ships the
    same string from every sensor running this software, which turns the
    fleet into a single fingerprint.
    """
    body = (await (await get(flux_client, path, ip="203.0.113.41")).read()).decode()
    assert carries_canary(body), "the canary is what makes a replay attributable"


@pytest.mark.parametrize("renderer,marker", [
    ("render_composer_lock", "reference"),
    ("render_gemfile_lock", "sha256="),
    ("render_requirements_txt", "--hash=sha256:"),
])
def test_per_hit_digests_are_not_constants(renderer, marker):
    """The integrity/commit pins are per-hit random, so two sensors serving
    the same manifest do not ship byte-identical lockfiles."""
    render = getattr(tbenv, renderer)
    first, second = render(FAKE_TRACEBIT), render(FAKE_TRACEBIT)
    assert marker in first.decode(), f"{renderer} lost its {marker} pin"
    assert first != second, (
        f"{renderer} is byte-identical across calls — its digests are fixed"
    )


def test_issuance_failure_still_avoids_a_fixed_literal():
    """When the canary issuance fails the password falls back to a per-hit
    synthetic — never a constant, which is the one outcome that would be
    worse than 404ing."""
    empty: dict[str, object] = {}
    first = tbenv.render_composer_json(empty).decode()
    second = tbenv.render_composer_json(empty).decode()
    assert first != second, "an issuance failure must not ship a fixed password"


# --------------------------------------------------------------------------
# Disable switch
# --------------------------------------------------------------------------

async def test_disabled_canary_traps_do_not_answer(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    resp = await get(flux_client, "/composer.lock", ip="203.0.113.42")
    assert resp.status == 404
