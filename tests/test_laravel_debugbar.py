"""Laravel Debugbar stored-request browser.

The trap's whole reason to exist is the two-step chain: the listing names
ids, and only a client that read the listing can name one back. These
tests pin the step split, the canary placement, the discriminator, and
the per-hit rule for everything credential-shaped.
"""
from __future__ import annotations

import json

import pytest

from flux import server as tbenv


HOST = "sensor.example"

FAKE_AWS = {"aws": {
    "awsAccessKeyId": "AKIATESTDEBUGBAR",
    "awsSecretAccessKey": "testSecretDebugbar",
    "awsSessionToken": "testSessionDebugbar",
    "awsExpiration": "2030-01-01T00:00:00Z",
}}


def _resolve(path, qs="", host=HOST):
    return tbenv.resolve_laravel_debugbar(path, qs, host)


# --- routing -----------------------------------------------------------

@pytest.mark.parametrize("path,kind", [
    ("/_debugbar", "index"),
    ("/_debugbar/", "index"),
    ("/_debugbar/open", "open-list"),
    ("/_debugbar/open/", "open-list"),
    ("/_debugbar/assets/javascript", "asset-js"),
    ("/_debugbar/assets/stylesheets", "asset-css"),
    ("/_debugbar/clockwork", "clockwork"),
])
def test_known_steps_resolve(path, kind):
    dbg = _resolve(path)
    assert dbg is not None and dbg.kind == kind


@pytest.mark.parametrize("path", [
    "/_debugbar/nope",
    "/_debugbar/assets/other",
    "/debugbar/open",
    "/_debug",
    "/",
    "/telescope/requests",
])
def test_unrelated_paths_do_not_resolve(path):
    assert _resolve(path) is None


def test_case_insensitive():
    assert _resolve("/_DebugBar/Open").kind == "open-list"


# --- the two-step split ------------------------------------------------

def test_listing_does_not_spend_a_canary():
    assert _resolve("/_debugbar/open").issues_canary is False
    assert _resolve("/_debugbar").issues_canary is False
    assert _resolve("/_debugbar/assets/javascript").issues_canary is False


def test_only_op_get_spends_a_canary():
    ids = tbenv._debugbar_stored_ids(HOST)
    dbg = _resolve("/_debugbar/open", f"op=get&id={ids[0]}")
    assert dbg.kind == "open-get" and dbg.issues_canary is True


def test_op_list_is_the_listing():
    assert _resolve("/_debugbar/open", "op=list").kind == "open-list"


def test_op_get_without_id_is_still_step_two():
    """The client knows the protocol even if it did not read the listing."""
    dbg = _resolve("/_debugbar/open", "op=get")
    assert dbg.kind == "open-get"
    assert dbg.stored_id == ""
    assert dbg.id_known is False


# --- the discriminator -------------------------------------------------

def test_advertised_id_is_recognised():
    ids = tbenv._debugbar_stored_ids(HOST)
    for sid in ids:
        assert _resolve("/_debugbar/open", f"op=get&id={sid}").id_known is True


def test_guessed_id_is_not_recognised():
    for sid in ("Xdeadbeef", "1", "../../etc/passwd", "X" + "0" * 32):
        assert _resolve("/_debugbar/open", f"op=get&id={sid}").id_known is False


def test_ids_are_stable_per_host():
    assert tbenv._debugbar_stored_ids(HOST) == tbenv._debugbar_stored_ids(HOST)
    assert tbenv._debugbar_stored_ids("SENSOR.EXAMPLE") == tbenv._debugbar_stored_ids(HOST)


def test_ids_differ_between_hosts():
    assert tbenv._debugbar_stored_ids("a.example") != tbenv._debugbar_stored_ids("b.example")


def test_an_id_from_one_host_is_not_known_at_another():
    other = tbenv._debugbar_stored_ids("other.example")[0]
    assert _resolve("/_debugbar/open", f"op=get&id={other}", host=HOST).id_known is False


def test_listing_advertises_exactly_the_recognised_ids():
    listing = json.loads(render_listing())
    assert [e["id"] for e in listing] == list(tbenv._debugbar_stored_ids(HOST))


def render_listing():
    return tbenv.render_debugbar_listing(HOST).decode()


# --- listing content ---------------------------------------------------

def test_listing_carries_no_secret():
    body = render_listing()
    for marker in ("AWS_", "AKIA", "password", "PASSWORD", "secret", "APP_KEY"):
        assert marker not in body, f"listing must not carry {marker}"


def test_listing_entry_shape():
    entry = json.loads(render_listing())[0]
    assert set(entry) == {"id", "datetime", "utime", "method", "uri", "ip"}
    assert len(json.loads(render_listing())) == tbenv.LARAVEL_DEBUGBAR_STORED_REQUESTS


# --- payload content ---------------------------------------------------

def _payload(index=0):
    sid = tbenv._debugbar_stored_ids(HOST)[index]
    return json.loads(
        tbenv.render_debugbar_stored_request(FAKE_AWS, HOST, sid, index)
    )


def test_payload_carries_canary_in_env():
    env = _payload()["request"]["env"]
    assert env["AWS_ACCESS_KEY_ID"] == FAKE_AWS["aws"]["awsAccessKeyId"]
    assert env["AWS_SECRET_ACCESS_KEY"] == FAKE_AWS["aws"]["awsSecretAccessKey"]
    assert env["AWS_SESSION_TOKEN"] == FAKE_AWS["aws"]["awsSessionToken"]


def test_payload_repeats_canary_in_a_query_binding():
    bindings = _payload()["queries"]["statements"][1]["bindings"]
    assert FAKE_AWS["aws"]["awsAccessKeyId"] in bindings
    assert FAKE_AWS["aws"]["awsSecretAccessKey"] in bindings


def test_payload_metadata_matches_the_listing_entry():
    listing = json.loads(render_listing())
    for i, entry in enumerate(listing):
        meta = _payload(i)["__meta"]
        assert meta == entry, "a fetched id must describe the request the listing named"


def test_every_credential_shaped_field_is_per_hit():
    """No fixed literals: two renders of the same id must differ in every
    synthetic secret, while the non-secret metadata stays put."""
    a, b = _payload(), _payload()
    ea, eb = a["request"]["env"], b["request"]["env"]
    for field in ("APP_KEY", "DB_PASSWORD", "REDIS_PASSWORD", "MAIL_PASSWORD"):
        assert ea[field] != eb[field], f"{field} must be per-hit"
    for field in ("_token", "login_web"):
        assert a["request"]["session_attributes"][field] != \
            b["request"]["session_attributes"][field]
    assert a["__meta"] == b["__meta"]


def test_no_empty_credential_fields_when_canary_missing():
    """A canary-less response would ship blank AWS values; the handler
    never reaches the renderer in that case, but pin the shape anyway."""
    payload = json.loads(
        tbenv.render_debugbar_stored_request({}, HOST, "Xabc", 0)
    )
    assert payload["request"]["env"]["AWS_ACCESS_KEY_ID"] == ""


def test_app_debug_is_true_in_the_payload():
    """The dump is only reachable on a misconfigured app; a payload
    claiming APP_DEBUG=false would contradict its own existence."""
    assert _payload()["request"]["env"]["APP_DEBUG"] == "true"


def test_payload_app_url_names_the_requested_host():
    assert _payload()["request"]["env"]["APP_URL"] == f"https://{HOST}"


# --- switches ----------------------------------------------------------

def test_default_on():
    assert tbenv.LARAVEL_DEBUGBAR_ENABLED


def test_assets_carry_no_secret():
    for blob in (tbenv._DEBUGBAR_JS, tbenv._DEBUGBAR_CSS):
        text = blob.decode()
        for marker in ("AKIA", "AWS_", "password", "APP_KEY"):
            assert marker not in text
