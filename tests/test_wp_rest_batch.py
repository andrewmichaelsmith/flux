"""Tests for the WP-REST query alias (`?rest_route=`) and the WordPress
core Batch API trap.

Two separate concerns share a file because they share a cause: a REST
route on a WordPress install is reachable at two addresses, and tooling
that wants to slip past literal-matching WAF rules uses the one flux did
not match. The alias tests assert that both addresses now reach the same
handler; the batch tests assert what the endpoint at the end of that
route does with the sub-request array it is handed.
"""

import hashlib
import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- `?rest_route=` alias resolution (pure) ----------------------------


@pytest.mark.parametrize("path,query,expected", [
    # The two front controllers WordPress honours the alias on.
    ("/", "rest_route=/wp/v2/users", "/wp-json/wp/v2/users"),
    ("/index.php", "rest_route=/wp/v2/users", "/wp-json/wp/v2/users"),
    # Trailing slash on the route survives — the user-enum matcher accepts
    # both spellings and should not depend on which one arrived.
    ("/", "rest_route=/wp/v2/users/", "/wp-json/wp/v2/users/"),
    # `%2F`-encoded separators: the WAF-evasion spelling.
    ("/", "rest_route=%2Fwp%2Fv2%2Fusers", "/wp-json/wp/v2/users"),
    ("/index.php", "rest_route=%2Fbatch%2Fv1", "/wp-json/batch/v1"),
    # Install subdirectories, both front controllers.
    ("/blog/", "rest_route=/batch/v1", "/wp-json/batch/v1"),
    ("/wordpress/index.php", "rest_route=/batch/v1", "/wp-json/batch/v1"),
    ("/staging/", "rest_route=/batch/v1", "/wp-json/batch/v1"),
    # Extra query parameters ride along; only `rest_route` steers.
    ("/", "rest_route=/gravitysmtp/v1/config&page=gravitysmtp-settings",
     "/wp-json/gravitysmtp/v1/config"),
    # A generated doubled separator still resolves.
    ("/", "rest_route=//wp/v2/users", "/wp-json/wp/v2/users"),
    # `rest_route=/` is the REST index's query-form address — the one a
    # client uses when permalinks are off. It used to resolve to nothing
    # because nothing was served there; the index trap changed that.
    ("/", "rest_route=/", "/wp-json/"),
    ("/index.php", "rest_route=%2F", "/wp-json/"),
])
def test_alias_resolves_to_the_canonical_rest_path(path, query, expected):
    assert tbenv.wp_rest_route_alias(path, query) == expected


@pytest.mark.parametrize("path,query", [
    # No alias present at all.
    ("/", "per_page=100"),
    ("/", ""),
    # Relative routes are not what WordPress accepts.
    ("/", "rest_route=wp/v2/users"),
    # Wrong front controller: an unrelated app that happens to take a
    # `rest_route` parameter must not be re-pointed at a trap.
    ("/app/api", "rest_route=/wp/v2/users"),
    ("/wp-json/wp/v2/users", "rest_route=/batch/v1"),
    ("/admin/index.php", "rest_route=/wp/v2/users"),
    # A route may not climb out of the REST namespace.
    ("/", "rest_route=/../../etc/passwd"),
    # Near-misses on the parameter name. The cheap implementation of this
    # resolver is a substring search over the query string, and each of
    # these would rewrite under one: `rest_route` as another parameter's
    # value, as a prefix, or as a suffix.
    ("/", "x=rest_route"),
    ("/", "note=rest_route=/wp/v2/users"),
    ("/", "rest_routex=/wp/v2/users"),
    ("/", "xrest_route=/batch/v1"),
])
def test_alias_declines_everything_else(path, query):
    assert tbenv.wp_rest_route_alias(path, query) is None


def test_alias_takes_the_first_value_like_php_does():
    """PHP's `$_GET` is first-wins for repeated scalars. A tool that
    appends a second `rest_route` to steer a normaliser that took the
    last value would get the first one instead."""
    assert tbenv.wp_rest_route_alias(
        "/", "rest_route=/wp/v2/users&rest_route=/batch/v1",
    ) == "/wp-json/wp/v2/users"


def test_alias_reaches_the_traps_that_were_bypassed():
    """The point of the rewrite: the shipped WP-REST traps match the
    alias form once it has been resolved."""
    assert tbenv.is_wp_user_enum_path(
        tbenv.wp_rest_route_alias("/", "rest_route=/wp/v2/users/"))
    assert tbenv.is_gravity_smtp_path(
        tbenv.wp_rest_route_alias("/", "rest_route=/gravitysmtp/v1/config"))
    assert tbenv.is_wp_batch_path(
        tbenv.wp_rest_route_alias("/index.php", "rest_route=/batch/v1"))


def test_alias_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_REST_ROUTE_ALIAS_ENABLED", False)
    assert tbenv.wp_rest_route_alias("/", "rest_route=/wp/v2/users") is None


# --- Prefix-less REST address naming (pure) ----------------------------
#
# Naming only. The prefix-less spelling deliberately stays a 404 — a real
# install serves REST under exactly one `rest_url_prefix`, so answering
# both spellings would be a fleet-wide tell. These tests pin the route
# extraction that makes the spelling countable in the log.


@pytest.mark.parametrize("path,expected", [
    # The collections an injection-testing run walks.
    ("/wp/v2/posts", "/wp/v2/posts"),
    ("/wp/v2/pages", "/wp/v2/pages"),
    ("/wp/v2/users", "/wp/v2/users"),
    ("/wp/v2/media", "/wp/v2/media"),
    ("/wp/v2/categories", "/wp/v2/categories"),
    ("/wp/v2/tags", "/wp/v2/tags"),
    # An indexed single, which is the spelling the observed payloads carry.
    ("/wp/v2/posts/999999", "/wp/v2/posts/999999"),
    # Trailing slash collapses, as it does in `wp_rest_route_of`.
    ("/wp/v2/posts/", "/wp/v2/posts"),
    # The namespace root itself.
    ("/wp/v2", "/wp/v2"),
    # Install subdirectories collapse onto the canonical route.
    ("/blog/wp/v2/posts", "/wp/v2/posts"),
    ("/wordpress/wp/v2/users", "/wp/v2/users"),
    ("/staging/wp/v2/posts/2", "/wp/v2/posts/2"),
    # Case-insensitive, like every other WP matcher here.
    ("/WP/V2/Posts", "/wp/v2/posts"),
    # A query string never steers route resolution.
    ("/wp/v2/posts/999999?author_exclude=1", "/wp/v2/posts/999999"),
])
def test_prefixless_route_is_named(path, expected):
    assert tbenv.wp_rest_prefixless_route(path) == expected


@pytest.mark.parametrize("path", [
    # Already canonical — that address has its own extractor.
    "/wp-json/wp/v2/posts",
    "/blog/wp-json/wp/v2/posts",
    # Other namespaces are too short and generic to claim prefix-less: an
    # unrelated application may legitimately own these paths.
    "/batch/v1",
    "/oembed/1.0/embed",
    "/gravitysmtp/v1/config",
    # Near-misses on the namespace itself.
    "/wp/v3/posts",
    "/wp/v2x/posts",
    "/wpv2/posts",
    "/wp-admin/v2/posts",
    "/api/wp/v2/posts",
    # A subdirectory outside the dictionary is not an install root.
    "/random/wp/v2/posts",
    # No climbing out of the namespace.
    "/wp/v2/../../etc/passwd",
    "/",
    "",
])
def test_prefixless_route_declines_everything_else(path):
    assert tbenv.wp_rest_prefixless_route(path) is None


# --- Batch path matching (pure) ---------------------------------------


@pytest.mark.parametrize("path", [
    "/wp-json/batch/v1",
    "/wp-json/batch/v1/",
    "/WP-JSON/Batch/V1",
    "/blog/wp-json/batch/v1",
    "/wordpress/wp-json/batch/v1/",
    "/old/wp-json/batch/v1",
    "/wp-json/batch/v1?foo=bar",
])
def test_batch_paths_match(path):
    assert tbenv.is_wp_batch_path(path)


@pytest.mark.parametrize("path", [
    "/wp-json/batch/v2",
    "/wp-json/batch",
    # Core registers nothing below the endpoint; a deeper path is left to
    # fall through rather than answered on a guess.
    "/wp-json/batch/v1/run",
    "/batch/v1",
    "/wp-json/wp/v2/users",
    "/",
])
def test_batch_paths_do_not_match(path):
    assert not tbenv.is_wp_batch_path(path)


def test_batch_disabled_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_BATCH_API_ENABLED", False)
    assert not tbenv.is_wp_batch_path("/wp-json/batch/v1")


# --- Batch body parsing (pure) ----------------------------------------


def test_parse_extracts_the_sub_request_array():
    parsed = tbenv.extract_wp_batch_requests(json.dumps({
        "validation": "require-all-validate",
        "requests": [
            {"method": "POST", "path": "/wp/v2/users",
             "body": {"log": "admin", "pwd": "hunter2"}},
            {"method": "GET", "path": "/wp/v2/posts"},
        ],
    }).encode())
    assert parsed["ok"] is True
    assert parsed["validation"] == "require-all-validate"
    assert len(parsed["requests"]) == 2


@pytest.mark.parametrize("body,error", [
    (b"", "invalid-json"),
    (b"not json at all", "invalid-json"),
    (b'["requests"]', "invalid-json"),
    (b"{}", "missing-requests"),
    (b'{"requests": []}', "missing-requests"),
    (b'{"requests": "nope"}', "missing-requests"),
])
def test_parse_rejects_malformed_bodies(body, error):
    parsed = tbenv.extract_wp_batch_requests(body)
    assert parsed["ok"] is False
    assert parsed["error"] == error


def test_parse_enforces_the_core_batch_cap():
    over = {"requests": [{"path": "/wp/v2/posts"}] * (tbenv.WP_BATCH_MAX_REQUESTS + 1)}
    parsed = tbenv.extract_wp_batch_requests(json.dumps(over).encode())
    assert parsed["ok"] is False
    assert parsed["error"] == "too-large"
    assert parsed["count"] == tbenv.WP_BATCH_MAX_REQUESTS + 1


@pytest.mark.parametrize("raw,expected", [
    ("/wp/v2/users", "/wp/v2/users"),
    ("/wp-json/wp/v2/users", "/wp/v2/users"),
    ("/wp/v2/users?per_page=100", "/wp/v2/users"),
    ("/WP/V2/Users", "/wp/v2/users"),
    (None, ""),
    (42, ""),
])
def test_sub_route_normalisation(raw, expected):
    assert tbenv._wp_batch_normalise_subroute(raw) == expected


@pytest.mark.parametrize("body,expected", [
    ({"log": "admin", "pwd": "s3cret"}, ("admin", "s3cret")),
    ({"username": "root", "password": "toor"}, ("root", "toor")),
    ({"user_login": "wp", "user_pass": "x"}, ("wp", "x")),
    ({"title": "hello"}, ("", "")),
    ("not a dict", ("", "")),
    ({"pwd": 42}, ("", "")),
])
def test_credential_scan(body, expected):
    assert tbenv._wp_batch_scan_credentials(body) == expected


# --- Live dispatch ------------------------------------------------------


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "WP_BATCH_API_ENABLED", True)
    monkeypatch.setattr(tbenv, "WP_REST_ROUTE_ALIAS_ENABLED", True)
    monkeypatch.setattr(tbenv, "WP_USER_ENUM_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_get_returns_the_post_only_route_envelope(flux_client):
    """Core registers `batch/v1` for POST only, so a GET gets
    `rest_no_route` — which still tells the prober a live WP-REST server
    is here, the thing it was actually checking."""
    resp = await flux_client.get("/wp-json/batch/v1")
    assert resp.status == 404
    assert (await resp.json())["code"] == "rest_no_route"
    assert _log_entries(flux_client.log_path)[-1]["result"] == "wp-batch-probe"


async def test_post_multiplexes_and_logs_the_whole_plan(flux_client):
    resp = await flux_client.post("/wp-json/batch/v1", json={
        "validation": "require-all-validate",
        "requests": [
            {"method": "GET", "path": "/wp/v2/users"},
            {"method": "POST", "path": "/wp/v2/posts", "body": {"title": "x"}},
        ],
    })
    assert resp.status == 207
    payload = await resp.json()
    assert payload["failed"] is False
    assert len(payload["responses"]) == 2

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-batch-multiplex"
    assert entry["wpBatchRequestCount"] == 2
    assert entry["wpBatchRoutes"] == ["/wp/v2/users", "/wp/v2/posts"]
    assert entry["wpBatchMethods"] == ["GET", "POST"]
    assert entry["wpBatchValidation"] == "require-all-validate"


async def test_user_enumeration_through_the_batch_feeds_the_login_trap(flux_client):
    """A sub-request enumerating users gets the same fake author roster
    the standalone trap serves — the usernames are what make a follow-up
    brute-force run against the login trap worth the operator's time."""
    resp = await flux_client.post("/wp-json/batch/v1", json={
        "requests": [{"method": "GET", "path": "/wp/v2/users"}],
    })
    sub = (await resp.json())["responses"][0]
    assert sub["status"] == 200
    assert {u["slug"] for u in sub["body"]} == {"admin", "editor", "webmaster"}


async def test_unknown_sub_routes_get_the_stock_wp_envelope(flux_client):
    resp = await flux_client.post("/wp-json/batch/v1", json={
        "requests": [{"method": "GET", "path": "/wp/v2/definitely-not-a-route"}],
    })
    sub = (await resp.json())["responses"][0]
    assert sub["status"] == 404
    assert sub["body"]["code"] == "rest_no_route"


async def test_credentials_in_a_batch_are_captured(flux_client):
    """A batch carrying credentials is a rate-limit-amplified brute-force
    run, and the whole run is visible in one row. Each attempt gets a
    hash so a dictionary is correlatable across rows, IPs and sensors
    without re-parsing bodies."""
    resp = await flux_client.post("/wp-json/batch/v1", json={
        "requests": [
            {"method": "POST", "path": "/wp/v2/users",
             "body": {"log": "admin", "pwd": "correcthorse"}},
            {"method": "POST", "path": "/wp/v2/users",
             "body": {"username": "editor", "password": "batterystaple"}},
        ],
    })
    assert resp.status == 207
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["wpBatchUsernames"] == ["admin", "editor"]
    assert entry["wpBatchCredentialCount"] == 2
    assert len(entry["wpBatchPasswordSha256"]) == 2
    assert entry["wpBatchPasswordLens"] == [12, 13]
    assert entry["wpBatchPasswordSha256"][0] == hashlib.sha256(
        b"correcthorse").hexdigest()
    # Distinct attempts must not collapse onto one hash — a brute-force
    # run that logged a single value per batch would be unreadable.
    assert len(set(entry["wpBatchPasswordSha256"])) == 2


async def test_oversized_batch_gets_the_core_rejection(flux_client):
    resp = await flux_client.post("/wp-json/batch/v1", json={
        "requests": [{"path": "/wp/v2/posts"}] * (tbenv.WP_BATCH_MAX_REQUESTS + 1),
    })
    assert resp.status == 400
    assert (await resp.json())["code"] == "rest_invalid_param"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-batch-rejected"
    assert entry["wpBatchError"] == "too-large"


async def test_malformed_json_gets_the_core_rejection(flux_client):
    resp = await flux_client.post(
        "/wp-json/batch/v1", data=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 400
    assert (await resp.json())["code"] == "rest_invalid_json"
    assert _log_entries(flux_client.log_path)[-1]["wpBatchError"] == "invalid-json"


async def test_alias_form_reaches_the_batch_handler(flux_client):
    """The whole reason the alias exists: the query-string spelling the
    evasion tooling uses lands on the same handler as the path form."""
    resp = await flux_client.post(
        "/index.php?rest_route=%2Fbatch%2Fv1",
        json={"requests": [{"method": "GET", "path": "/wp/v2/users"}]},
    )
    assert resp.status == 207
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-batch-multiplex"
    # The request is logged as it arrived; the rewrite is recorded beside it.
    assert entry["path"] == "/index.php"
    assert entry["wpRestRouteAliasFrom"] == "/index.php"
    assert entry["wpRestRoutePath"] == "/wp-json/batch/v1"


async def test_alias_form_reaches_the_user_enum_trap(flux_client):
    """The bypass this fixes: a shipped trap that the query spelling used
    to walk straight past."""
    resp = await flux_client.get("/?rest_route=/wp/v2/users/")
    assert resp.status == 200
    assert {u["slug"] for u in await resp.json()} == {"admin", "editor", "webmaster"}
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "wp-user-enum-rest-list"
    assert entry["wpRestRoutePath"] == "/wp-json/wp/v2/users/"


async def test_prefixless_address_is_named_but_still_404s(flux_client):
    """The contract in one test: the response is the 404 it always was —
    answering would be a fleet-wide tell — and the log line now names the
    REST route that was asked for."""
    canonical = await flux_client.get("/wp-json/wp/v2/nope-not-a-route")
    baseline = await canonical.read()

    resp = await flux_client.get("/wp/v2/users")
    assert resp.status == 404
    assert await resp.read() == baseline
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"
    assert entry["path"] == "/wp/v2/users"
    assert entry["wpRestPrefixlessRoute"] == "/wp/v2/users"
    # The rewrite fields belong to the `?rest_route=` alias; naming a
    # prefix-less address must not claim them, or alias counts inflate.
    assert "wpRestRoutePath" not in entry


async def test_prefixless_injection_probe_is_captured_with_its_route(flux_client):
    """The traffic this names: an injection-testing run walking a payload
    ladder over a collection's query parameters. The query was always
    captured; the route it was aimed at was not."""
    resp = await flux_client.get(
        "/wp/v2/posts/999999?author_exclude=0%29+OR+1--+-&orderby=none",
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["wpRestPrefixlessRoute"] == "/wp/v2/posts/999999"
    assert "author_exclude" in entry["query"]


async def test_foreign_namespaces_are_not_named(flux_client):
    """A short generic namespace is not claimed prefix-less; an unrelated
    application that owns `/batch/v1` keeps an unannotated 404."""
    resp = await flux_client.get("/batch/v1")
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert "wpRestPrefixlessRoute" not in entry
