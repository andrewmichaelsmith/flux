"""SPA build manifest, and the config chunk it names.

The build manifest is the only trap here whose payoff is not in its own
body. It carries no credential; what it carries is a reference to a
chunk whose filename the client could not have obtained any other way.
Fetching that chunk is therefore evidence the client parsed the
response rather than merely receiving it, and these tests are mostly
about keeping that property true: the hash has to be unguessable, it has
to be stable enough for a sweep to follow, and the two outcomes have to
stay separately readable.
"""
import json

import pytest

import flux.server as tbenv
from tests.test_server import FAKE_TRACEBIT


AWS_KEY_ID = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
AWS_SECRET = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]


# --- path dispatch ------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/.vite/manifest.json",
    "/dist/.vite/manifest.json",
    "/build/.vite/manifest.json",
    "/public/.vite/manifest.json",
    "/static/.vite/manifest.json",
    "/dist/manifest.json",
    "/build/manifest.json",
    "/static/manifest.json",
    "/assets/manifest.json",
    "/manifest.webmanifest",
    "/dist/manifest.webmanifest",
    "/build/manifest.webmanifest",
    "/site.webmanifest",
])
def test_manifest_paths_match(path):
    assert tbenv.is_spa_build_manifest_path(path)


@pytest.mark.parametrize("path", [
    "/assets/env-config-deadbeef.js",
    "/dist/assets/env-config-deadbeef.js",
    "/build/assets/env-config-deadbeef.js",
    "/public/assets/env-config-deadbeef.js",
    "/static/assets/env-config-0123456789abcdef.js",
])
def test_chunk_paths_match(path):
    assert tbenv.is_spa_build_manifest_path(path)


@pytest.mark.parametrize("path", [
    # Bare `manifest.json` at the webroot is a PWA manifest on countless
    # ordinary sites; claiming it would answer far past the sweep.
    "/manifest.json",
    # The webapp-config-bundle table owns the un-hashed spelling with a
    # closer-fitting body — this trap must not take it.
    "/assets/env-config.js",
    "/env-config.js",
    # Wrong shape for a build hash.
    "/assets/env-config-.js",
    "/assets/env-config-ZZZZZZZZ.js",
    "/assets/env-config-deadbeef.mjs",
    "/assets/env-config-deadbeef.js.map",
    # Right leaf, wrong directory.
    "/vendor/assets/env-config-deadbeef.js",
    "/manifest.json.bak",
    "/.vite/manifest.json.bak",
])
def test_near_miss_paths_do_not_match(path):
    assert not tbenv.is_spa_build_manifest_path(path)


def test_no_manifest_path_is_also_claimed_by_the_canary_trap_table():
    """This trap dispatches by predicate, not by table entry, so the
    existing duplicate-path guard cannot see it — that one compares
    table entries against each other.

    Whichever of the two is consulted first silently wins, so a future
    table entry for (say) `/dist/manifest.json` would shadow this trap
    with no test failing anywhere. Pin it from this side.
    """
    clashes = {
        p: tbenv._TRAP_BY_PATH[p].name
        for p in (tbenv._SPA_MANIFEST_PATHS | tbenv._SPA_WEBMANIFEST_PATHS)
        if p in tbenv._TRAP_BY_PATH
    }
    assert not clashes, f"also claimed by the CanaryTrap table: {clashes}"


def test_chunk_regex_does_not_shadow_a_canary_trap_path():
    shadowed = [p for p in tbenv._TRAP_BY_PATH if tbenv._SPA_CHUNK_RE.match(p)]
    assert not shadowed, f"chunk regex swallows table paths: {shadowed}"


def test_query_string_is_stripped():
    assert tbenv.is_spa_build_manifest_path("/.vite/manifest.json?v=2")
    assert tbenv.is_spa_build_manifest_path("/assets/env-config-deadbeef.js?t=1")


def test_disabled_switch_stops_matching(monkeypatch):
    monkeypatch.setattr(tbenv, "SPA_BUILD_MANIFEST_ENABLED", False)
    assert not tbenv.is_spa_build_manifest_path("/.vite/manifest.json")
    assert not tbenv.is_spa_build_manifest_path("/assets/env-config-deadbeef.js")


# --- the chunk hash -----------------------------------------------------

def test_chunk_hash_is_stable_per_address():
    """A sweep fetches the manifest and the chunk over separate
    connections; they have to agree or the reference is worthless."""
    assert tbenv._spa_chunk_hash("198.51.100.7") == tbenv._spa_chunk_hash("198.51.100.7")


def test_chunk_hash_differs_between_addresses():
    assert tbenv._spa_chunk_hash("198.51.100.7") != tbenv._spa_chunk_hash("198.51.100.8")


def test_chunk_hash_looks_like_a_build_hash():
    h = tbenv._spa_chunk_hash("198.51.100.7")
    assert len(h) == tbenv._SPA_CHUNK_HASH_LEN == 8
    assert all(c in "0123456789abcdef" for c in h)


def test_chunk_hash_depends_on_the_process_secret(monkeypatch):
    """The hash must not be derivable from the address alone, or it
    would be guessable and the same across every deployment."""
    before = tbenv._spa_chunk_hash("198.51.100.7")
    monkeypatch.setattr(tbenv, "_SPA_MANIFEST_SECRET", b"\x01" * 32)
    assert tbenv._spa_chunk_hash("198.51.100.7") != before


def test_empty_address_does_not_raise():
    assert len(tbenv._spa_chunk_hash("")) == tbenv._SPA_CHUNK_HASH_LEN


# --- the manifest body --------------------------------------------------

def test_manifest_names_the_chunk():
    body = json.loads(tbenv.render_spa_build_manifest("deadbeef"))
    entry = body["src/env-config.ts"]
    assert entry["file"] == "assets/env-config-deadbeef.js"
    # The named file must be reachable, or the reference is a dead end
    # and a parsing client learns we are lying.
    assert tbenv.is_spa_build_manifest_path("/" + entry["file"])


def test_manifest_is_shaped_like_vite_output():
    body = json.loads(tbenv.render_spa_build_manifest("deadbeef"))
    assert body["index.html"]["isEntry"] is True
    assert body["index.html"]["css"]
    assert "src/env-config.ts" in body["index.html"]["imports"]


def test_manifest_carries_no_credential():
    """A manifest that held a secret would not be a manifest, and the
    point of this trap is that the reward is one request further on."""
    raw = tbenv.render_spa_build_manifest("deadbeef").decode()
    assert AWS_KEY_ID not in raw
    assert AWS_SECRET not in raw
    assert "AKIA" not in raw


def test_manifest_filler_hashes_are_per_hit():
    a = json.loads(tbenv.render_spa_build_manifest("deadbeef"))
    b = json.loads(tbenv.render_spa_build_manifest("deadbeef"))
    assert a["_vendor.js"]["file"] != b["_vendor.js"]["file"]


# --- the webmanifest ----------------------------------------------------

def test_webmanifest_is_valid_and_credential_free():
    body = json.loads(tbenv.render_spa_webmanifest("shop.example.com"))
    assert body["name"] == "shop.example.com"
    assert body["start_url"] == "/"
    assert body["icons"]
    raw = tbenv.render_spa_webmanifest("shop.example.com").decode()
    assert AWS_KEY_ID not in raw and "AKIA" not in raw


def test_webmanifest_drops_the_port_from_the_host():
    body = json.loads(tbenv.render_spa_webmanifest("shop.example.com:8443"))
    assert body["name"] == "shop.example.com"


@pytest.mark.parametrize("bad_host", ["127.0.0.1", "localhost", "10.0.0.5", ""])
def test_webmanifest_never_names_a_proxy_substituted_host(bad_host, monkeypatch):
    """Behind a proxy that rewrites `Host` the value that arrives is a
    loopback literal. A manifest naming the app `127.0.0.1` is both
    implausible and identical from every deployment — a fingerprint,
    not a cosmetic slip."""
    monkeypatch.setattr(tbenv, "SITE_HOST", "")
    body = json.loads(tbenv.render_spa_webmanifest(bad_host))
    assert body["name"] == "app"
    assert body["short_name"]


# --- the chunk body -----------------------------------------------------

def test_chunk_carries_the_canary_in_the_runtime_slots():
    raw = tbenv.render_spa_config_chunk(FAKE_TRACEBIT).decode()
    assert "window.__RUNTIME_CONFIG__" in raw
    for slot in (
        "REACT_APP_AWS_ACCESS_KEY_ID",
        "VITE_AWS_ACCESS_KEY_ID",
        "NEXT_PUBLIC_AWS_ACCESS_KEY_ID",
    ):
        assert slot in raw
    assert AWS_KEY_ID in raw
    assert AWS_SECRET in raw


def test_chunk_without_a_canary_leaves_the_slot_empty():
    """No baked-in fallback: an upstream failure must not ship a fixed
    literal that every deployment would share."""
    raw = tbenv.render_spa_config_chunk({}).decode()
    assert "AKIA" not in raw
    assert '"REACT_APP_AWS_ACCESS_KEY_ID":""' in raw.replace(" ", "")


def test_chunk_synthetic_filler_is_per_hit():
    a = tbenv.render_spa_config_chunk(FAKE_TRACEBIT).decode()
    b = tbenv.render_spa_config_chunk(FAKE_TRACEBIT).decode()
    assert a != b, "Sentry/Firebase/Stripe filler must regenerate per hit"


# --- the two outcomes stay separable ------------------------------------

def test_referenced_and_foreign_traps_are_distinct_tags():
    assert (
        tbenv._SPA_CONFIG_CHUNK_TRAP_REFERENCED.name
        != tbenv._SPA_CONFIG_CHUNK_TRAP_FOREIGN.name
    )
    for trap in (
        tbenv._SPA_CONFIG_CHUNK_TRAP_REFERENCED,
        tbenv._SPA_CONFIG_CHUNK_TRAP_FOREIGN,
    ):
        assert trap.canary_types == ("aws",)
        # Same body on both branches — rewarding the parsing client
        # differently would advertise that we are measuring the fork.
        assert trap.render is tbenv.render_spa_config_chunk


# --- the leaf expansion on the existing bundle trap ----------------------

@pytest.mark.parametrize("path", [
    "/env-config.js",
    "/environment.js",
    "/runtime.js",
    "/config.json.js",
    "/credentials.js",
    "/aws_creds.js",
    "/assets/env-config.js",
    "/static/js/runtime.js",
    "/dist/environment.js",
])
def test_observed_bundle_spellings_now_dispatch(path):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == "webapp-config-bundle-js", (
        f"{path!r} should dispatch to webapp-config-bundle-js, "
        f"got {trap and trap.name!r}"
    )
