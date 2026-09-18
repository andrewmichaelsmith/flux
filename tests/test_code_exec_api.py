"""Tests for the code-execution / file-read API surface.

A distributed fleet walks low-code-platform and web-IDE endpoints that
take their argument in a POST body — a command, source to validate, a
template to render, a path to read — while presenting itself as a
rotating set of AI-assistant and search-bot user agents. Every one of
those addresses used to 404, and a 404 is answered before the body is
looked at, so the payload was the one thing not recorded.

These tests pin that the argument is recovered from all three places the
probes put it, and that the template endpoint answers the arithmetic an
injection probe is made of without anything being evaluated as code.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def log_lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def last_of(path, result_prefix="code-exec-api"):
    rows = [
        line for line in log_lines(path)
        if str(line.get("result", "")).startswith(result_prefix)
    ]
    return rows[-1] if rows else None


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,family", [
    ("/api/fs/exec", "exec"),
    ("/api/v1/validate/code", "validate"),
    ("/api/templates/preview", "template"),
    ("/api/designer/v1/file-content", "read"),
    ("/read-document", "read"),
    ("/lib/terminal-xhr.php", "exec"),
    ("/icecoder/lib/terminal-xhr.php", "exec"),
    ("/editor/ide/lib/terminal-xhr.php", "exec"),
    # Trailing slash and case are the scanner's choice, not ours.
    ("/api/fs/exec/", "exec"),
    ("/API/Templates/Preview", "template"),
])
def test_observed_addresses_match(path, family):
    assert tbenv.code_exec_api_family(path) == family
    assert tbenv.is_code_exec_api_path(path)


@pytest.mark.parametrize("path", [
    "/api/fs", "/api/exec", "/api/v1/validate", "/api/templates",
    "/terminal-xhr.php", "/lib/terminal.php", "/read", "/",
    "/api/designer/v1/file-content/extra",
])
def test_neighbouring_addresses_are_not_claimed(path):
    assert not tbenv.is_code_exec_api_path(path)


def test_disabled_when_env_off(monkeypatch):
    monkeypatch.setattr(tbenv, "CODE_EXEC_API_ENABLED", False)
    assert not tbenv.is_code_exec_api_path("/api/fs/exec")


def test_code_exec_api_default_on():
    assert tbenv.CODE_EXEC_API_ENABLED


# --------------------------------------------------------------------------
# Recovering the argument
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_argument_recovered_from_json_body(flux_client):
    resp = await flux_client.post(
        "/api/fs/exec", data=json.dumps({"cmd": "id"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert "www-data" in payload["stdout"]
    entry = last_of(flux_client.log_path)
    assert entry["codeExecApiArgument"] == "id"
    assert entry["result"] == "code-exec-api-exec"


@pytest.mark.asyncio
async def test_argument_recovered_from_form_body(flux_client):
    resp = await flux_client.post("/api/fs/exec", data={"command": "whoami"})
    assert resp.status == 200
    assert last_of(flux_client.log_path)["codeExecApiArgument"] == "whoami"


@pytest.mark.asyncio
async def test_argument_recovered_from_query_string(flux_client):
    resp = await flux_client.get("/api/fs/exec?cmd=hostname")
    assert resp.status == 200
    assert last_of(flux_client.log_path)["codeExecApiArgument"] == "hostname"


@pytest.mark.asyncio
async def test_unrecognised_shape_still_records_the_body(flux_client):
    """The payload is the point of the request; an unparsed body is still
    recorded rather than dropped."""
    raw = "<<<not json, not a form>>>"
    resp = await flux_client.post(
        "/api/v1/validate/code", data=raw,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status == 200
    entry = last_of(flux_client.log_path)
    assert raw in entry["codeExecApiArgument"] or raw in entry["bodyPreview"]


@pytest.mark.asyncio
async def test_terminal_endpoint_answers_raw_not_json(flux_client):
    resp = await flux_client.post("/icecoder/lib/terminal-xhr.php", data={"cmd": "id"})
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    assert "www-data" in await resp.text()


@pytest.mark.asyncio
async def test_unknown_command_returns_empty_output_not_an_error(flux_client):
    """Same reasoning the shell traps use: a canned error message outs the
    trap on the first probe, an empty result is what a real shell gives."""
    resp = await flux_client.post("/api/fs/exec", data={"cmd": "totally-not-a-binary"})
    payload = await resp.json()
    assert payload["stdout"] == ""
    assert payload["exitCode"] == 0


@pytest.mark.asyncio
async def test_read_endpoint_records_the_requested_path(flux_client):
    resp = await flux_client.post(
        "/api/designer/v1/file-content",
        data=json.dumps({"path": "../../../../etc/passwd"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 200
    entry = last_of(flux_client.log_path)
    assert entry["codeExecApiRequestedPath"] == "../../../../etc/passwd"
    assert entry["result"] == "code-exec-api-read"


# --------------------------------------------------------------------------
# The template-injection oracle
# --------------------------------------------------------------------------

@pytest.mark.parametrize("probe,expected", [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{ 1337 + 1 }}", "1338"),
    ("${100-58}", "42"),
    ("{{84/2}}", "42"),
    ("prefix {{7*7}} suffix", "prefix 49 suffix"),
    ("{{7*7}}{{2*3}}", "496"),
])
def test_arithmetic_probes_are_answered(probe, expected):
    rendered, evaluated = tbenv.code_exec_api_render_template(probe)
    assert rendered == expected
    assert evaluated is True


@pytest.mark.parametrize("probe", [
    # Not the arithmetic shape — an engine that did not interpolate emits
    # these unchanged, and nothing here evaluates code.
    "{{config.items()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{7*'7'}}",
    "plain text with no markers",
    "{{7/0}}",
    "{{1234567*2}}",
    # Mismatched wrappers stay literal rather than being guessed at.
    "{{7*7}",
    "${7*7}}",
])
def test_non_arithmetic_templates_are_left_alone(probe):
    rendered, evaluated = tbenv.code_exec_api_render_template(probe)
    assert rendered == probe
    assert evaluated is False


def test_empty_template_is_not_evaluated():
    assert tbenv.code_exec_api_render_template("") == ("", False)


def test_substitution_count_is_bounded():
    probe = "{{2*2}}" * 40
    rendered, evaluated = tbenv.code_exec_api_render_template(probe)
    assert evaluated is True
    # Past the cap the remaining probes are returned as they arrived.
    assert rendered.count("{{2*2}}") == 40 - 8


@pytest.mark.asyncio
async def test_template_endpoint_reports_whether_it_evaluated(flux_client):
    resp = await flux_client.post(
        "/api/templates/preview", data=json.dumps({"template": "{{7*7}}"}),
        headers={"Content-Type": "application/json"},
    )
    payload = await resp.json()
    assert payload["rendered"] == "49"
    entry = last_of(flux_client.log_path)
    assert entry["codeExecApiTemplateEvaluated"] is True
    assert entry["codeExecApiArgument"] == "{{7*7}}"

    resp = await flux_client.post(
        "/api/templates/preview", data=json.dumps({"template": "no markers"}),
        headers={"Content-Type": "application/json"},
    )
    assert (await resp.json())["rendered"] == "no markers"
    assert last_of(flux_client.log_path)["codeExecApiTemplateEvaluated"] is False


@pytest.mark.asyncio
async def test_validate_endpoint_accepts_so_the_next_payload_arrives(flux_client):
    resp = await flux_client.post(
        "/api/v1/validate/code", data=json.dumps({"code": "require('child_process')"}),
        headers={"Content-Type": "application/json"},
    )
    payload = await resp.json()
    assert payload["valid"] is True and payload["errors"] == []
    assert last_of(flux_client.log_path)["codeExecApiArgument"] == "require('child_process')"


@pytest.mark.asyncio
async def test_no_credential_shaped_literal_in_any_response(flux_client):
    """Nothing here mints a secret, so nothing here may look like one."""
    for path, data in [
        ("/api/fs/exec", {"cmd": "id"}),
        ("/api/v1/validate/code", {"code": "x"}),
        ("/api/templates/preview", {"template": "{{7*7}}"}),
        ("/read-document", {"path": "notes.md"}),
    ]:
        text = (await (await flux_client.post(path, data=data)).text()).lower()
        for marker in ("password", "secret", "api_key", "apikey", "aws_", "token"):
            assert marker not in text, f"{path} response contains {marker!r}"
