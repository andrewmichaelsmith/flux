"""Path-parameter traversal (`/..;/`) resolution.

A servlet container strips `;name=value` off a path segment before it
resolves the segment, so `..;` is a path-up token there. That is the
whole basis of the bypass: a fronting proxy that gates on a URL prefix
sees an ordinary directory name and forwards, and the container then
walks up out of the gated prefix.

flux resolved `..` but not `..;`, so a read spelled this way stayed
unresolved and 404ed even where the file it named had a renderer. These
tests pin the fix at the level it was made -- normalisation, so the whole
trap table gains the spelling at once -- and pin the two things that must
survive it: the bypass shape stays visible in the log, and the two
handlers that had been matching the raw `..;` shape keep their routes.
"""
import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


# --- Normalisation ---


@pytest.mark.parametrize("raw,expected", [
    # The shapes observed asking for files already in the table.
    ("/static/..;/..;/..;/..;/proc/self/environ", "/proc/self/environ"),
    ("/assets/..;/../var/www/html/wp-config.php", "/var/www/html/wp-config.php"),
    ("/..;/wp-config.php", "/wp-config.php"),
    ("/static/..;/.env", "/.env"),
    ("/app/..;/.env", "/.env"),
    # A named path parameter, not just the bare `;`.
    ("/x/..;jsessionid=0123456789abcdef/.env", "/.env"),
    ("/x/..;a=1;b=2/.env", "/.env"),
    # Double-encoded: the decode runs to a fixed point first, so the
    # fold sees `..;` however many layers it arrived under.
    ("/static/%2e%2e;/.env", "/.env"),
    ("/static/%252e%252e;/.env", "/.env"),
    # Mixed with the plain spelling in one path.
    ("/a/..;/b/../.env", "/.env"),
])
def test_path_param_traversal_resolves(raw, expected):
    assert tbenv.normalize_path(raw) == expected


@pytest.mark.parametrize("raw", [
    # A parameter on an ordinary segment is not a traversal token. The
    # session id in it is worth keeping in the path the handler sees.
    "/admin;jsessionid=0123456789abcdef/index.jsp",
    "/a;b=1/.env",
    # A single dot with a parameter is not a path-up token either.
    "/a/.;/.env",
    # `..` without a parameter is the pre-existing case and must keep
    # resolving exactly as before.
    "/static/../.env",
])
def test_unrelated_path_parameters_are_left_alone(raw):
    assert "..;" not in tbenv.normalize_path(raw)


def test_ordinary_segment_parameter_survives_normalisation():
    assert tbenv.normalize_path("/admin;jsessionid=abc/x.jsp") == (
        "/admin;jsessionid=abc/x.jsp"
    )


# --- The counter that keeps the signal ---


@pytest.mark.parametrize("raw,count", [
    ("/static/..;/..;/..;/..;/proc/self/environ", 4),
    ("/..;/wp-config.php", 1),
    ("/x/..;jsessionid=1/.env", 1),
    ("/static/%2e%2e;/.env", 1),
    # Ordinary requests must not stamp the field at all.
    ("/.env", 0),
    ("/static/../.env", 0),
    ("/admin;jsessionid=abc/x.jsp", 0),
    ("", 0),
])
def test_path_param_traversal_is_counted(raw, count):
    assert tbenv._path_param_traversal_of(raw) == count


# --- Dispatch: the read now lands on the owning trap ---


@pytest.mark.asyncio
async def test_bypass_spelled_read_reaches_the_owning_trap(flux_client, monkeypatch):
    """`/static/..;/..;/..;/..;/proc/self/environ` is a read of a file the
    table owns. Before the fold it was a 404."""
    resp = await flux_client.get(
        "/static/..;/..;/..;/..;/proc/self/environ",
        headers={"X-Forwarded-For": "203.0.113.41"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] != "not-handled"
    assert entry["path"] == "/proc/self/environ"
    # The evasion attempt is still on the record.
    assert entry["rawPath"] == "/static/..;/..;/..;/..;/proc/self/environ"
    assert entry["pathParamTraversal"] == 4


@pytest.mark.asyncio
async def test_ordinary_request_does_not_stamp_the_field(flux_client):
    resp = await flux_client.get(
        "/.env", headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert "pathParamTraversal" not in entry


# --- The two handlers that were matching the raw shape keep their routes ---


@pytest.mark.asyncio
async def test_env_js_bypass_keeps_its_own_result_tag(flux_client):
    """The dedicated handler exists to separate a bypass-shaped env-file
    harvest from a plain one. Folding the segment must not collapse it
    into the generic env route."""
    resp = await flux_client.get(
        "/..;/env.prod.js", headers={"X-Forwarded-For": "203.0.113.43"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "tomcat-path-bypass-env"
    assert entry["pathParamTraversal"] == 1


def test_env_js_predicate_reads_parameters_from_the_raw_path():
    # Normalized path alone no longer carries the shape...
    assert not tbenv.is_tomcat_path_bypass_path("/env.prod.js")
    # ...so the raw path is what the predicate is given at dispatch.
    assert tbenv.is_tomcat_path_bypass_path("/env.prod.js", raw_path="/..;/env.prod.js")
    # A raw path with no bypass segment must not match.
    assert not tbenv.is_tomcat_path_bypass_path("/env.prod.js", raw_path="/env.prod.js")


def test_appliance_file_read_keeps_its_route_after_folding():
    """The appliance's own CVE payload is written with `..;`. The
    normalized destination keeps both `/tmui/` segments, because the `..`
    cancels `login.jsp` and the payload names the directory twice."""
    probe = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp"
    assert tbenv.normalize_path(probe) == (
        "/tmui/tmui/locallb/workspace/fileRead.jsp"
    )
    assert tbenv.is_f5_bigip_path(tbenv.normalize_path(probe))


# --- Read primitives that name their own target ---
#
# The fold above covers a target named in the *path*. These endpoints name
# it in a *parameter* instead, which normalisation cannot reach -- so they
# are the other half of the same miss, and they are answered by being
# admitted to the fetch-relay entry table rather than by a new handler.


@pytest.mark.parametrize("entry", [
    "/userfiles", "/userfiles/x", "/_next/image",
])
def test_added_read_primitives_are_entry_paths(entry):
    assert entry in tbenv._SSRF_RELAY_ENTRY_PATHS


@pytest.mark.parametrize("path,query,target", [
    # Traversal out of a file-manager upload directory.
    ("/userfiles", "path=../../.env", "../../.env"),
    ("/userfiles/x", "path=../../../../proc/self/environ",
     "../../../../proc/self/environ"),
    # The image optimiser's real address, pointed at link-local metadata.
    ("/_next/image", "url=http://169.254.169.254/latest/meta-data/",
     "http://169.254.169.254/latest/meta-data/"),
    # Trailing slash is the same entry.
    ("/_next/image/", "url=http://169.254.169.254/latest/meta-data/",
     "http://169.254.169.254/latest/meta-data/"),
])
def test_added_read_primitives_resolve_their_target(path, query, target):
    resolved = tbenv.resolve_ssrf_relay(path, query)
    assert resolved is not None
    assert resolved.target == target


def test_added_read_primitives_still_refuse_an_unnamed_target():
    """Admission to the entry table must not make these behave like an
    open proxy: a parameter that names neither a metadata host nor a
    local file is still not claimed."""
    assert tbenv.resolve_ssrf_relay("/userfiles", "path=player:player/data") is None
    assert tbenv.resolve_ssrf_relay("/_next/image", "url=https://example.com/a.png") is None
    assert tbenv.resolve_ssrf_relay("/userfiles", "") is None
