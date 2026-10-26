"""Tests for the fake Jenkins Groovy script console trap.

`/script` is Jenkins' built-in Groovy REPL. On an instance whose
authorization is misconfigured it is a straight unauthenticated
remote-code-execution surface, so scanners walk it constantly: a GET on the
console path fingerprints it, and a `POST script=<groovy>` executes.

Three properties carry this family and each is tested below:

* **Matching is exact, never a prefix.** `/scripts/.env`, `/script/<asset>`
  and the `/scriptResource/...` static tree are a different population
  already served by the canary/tarpit modules; a prefix match here would
  steal that traffic and retag it as RCE, so the must-not-match cases are
  load-bearing.

* **The console answers without a prior login.** That is the bug: a
  misconfigured instance serves the console to anonymous. Gating it behind
  an invented login would make the trap less realistic than the
  vulnerability and would drop the POST body -- the only request carrying
  attacker-authored content.

* **The `script` extractor has to survive a real form-urlencoded Groovy
  body**, including a `%2B`-encoded `+` operator, which a naive splitter
  would corrupt.
"""

import json
from urllib.parse import quote_plus

import pytest
import pytest_asyncio

from flux import server as tbenv


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_rows(client):
    if not client.log_path.exists():
        return []
    return [
        json.loads(line)
        for line in client.log_path.read_text().splitlines()
        if line.strip()
    ]


# --- registration / path matching --------------------------------------

def test_jenkins_script_enabled_by_default():
    assert tbenv.JENKINS_SCRIPT_ENABLED


MUST_MATCH_HTML = [
    "/script",
    "/script/",
    "/jenkins/script",
    "/.jenkins/script",
    "/computer/(master)/script",
    "/computer/(built-in)/script",
    "/computer/agent-07/script",
    "/jenkins/computer/(master)/script",
    "/SCRIPT",
]
MUST_MATCH_TEXT = [
    "/scriptText",
    "/jenkins/scriptText",
    "/computer/(master)/scriptText",
    "/scripttext",
]
MUST_NOT_MATCH = [
    "/scripts/.env",
    "/script/.env",
    "/scriptResource/foo.js",
    "/scripts/info.php",
    "/jenkins/login",
    "/jenkins/api/json",
    "/computer/script",          # no node segment
    "/computer/(master)/api/json",
    "/descriptorByName/script",
    "/",
]


def test_must_match_sets_are_nonempty():
    # Guard the premise: a helper that derived these from an empty tree
    # would make every parametrised case below pass vacuously.
    assert MUST_MATCH_HTML and MUST_MATCH_TEXT and MUST_NOT_MATCH


@pytest.mark.parametrize("path", MUST_MATCH_HTML)
def test_html_paths_match(path):
    assert tbenv.is_jenkins_script_path(path)
    assert tbenv._jenkins_script_family(path) == "html"


@pytest.mark.parametrize("path", MUST_MATCH_TEXT)
def test_text_paths_match(path):
    assert tbenv.is_jenkins_script_path(path)
    assert tbenv._jenkins_script_family(path) == "text"


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_non_console_paths_do_not_match(path):
    assert not tbenv.is_jenkins_script_path(path)
    assert tbenv._jenkins_script_family(path) == ""


def test_disable_flag(monkeypatch):
    monkeypatch.setattr(tbenv, "JENKINS_SCRIPT_ENABLED", False)
    assert not tbenv.is_jenkins_script_path("/script")


# --- the `script` extractor, against a real urlencoded Groovy body ------

def test_source_roundtrips_real_groovy_with_plus_operator():
    # `"a" + "b"` form-urlencoded: spaces are `+`, the literal plus is
    # `%2B`. A splitter that forgot url-decoding, or decoded `+` as a plus
    # instead of a space, would corrupt this.
    groovy = '"out=" + "ab".execute().text'
    body = ("script=" + quote_plus(groovy)).encode("utf-8")
    got = tbenv.jenkins_script_source(body, "application/x-www-form-urlencoded")
    assert got == groovy
    assert " + " in got  # the %2B survived as a literal plus with spaces


def test_source_empty_when_no_script_field():
    assert tbenv.jenkins_script_source(b"", "") == ""
    assert tbenv.jenkins_script_source(b"foo=bar", "application/x-www-form-urlencoded") == ""


# --- served behaviour ---------------------------------------------------

async def test_get_console_serves_textarea_and_logs_probe(flux_client):
    resp = await flux_client.get("/script")
    assert resp.status == 200
    body = await resp.text()
    assert 'name="script"' in body
    assert "Script Console" in body
    rows = [r for r in _log_rows(flux_client) if r.get("jenkinsScriptPath") == "/script"]
    assert rows and rows[-1]["result"] == "jenkins-script-console-probe"


async def test_get_crumb_is_per_request(flux_client):
    import re
    b1 = await (await flux_client.get("/script")).text()
    b2 = await (await flux_client.get("/script")).text()
    c1 = re.search(r'Jenkins-Crumb" value="([0-9a-f]+)"', b1).group(1)
    c2 = re.search(r'Jenkins-Crumb" value="([0-9a-f]+)"', b2).group(1)
    assert c1 != c2  # never a fixed credential-shaped literal


async def test_post_script_captures_groovy_and_flags_exec(flux_client):
    groovy = 'def p = ["/bin/sh","-c","id"].execute(); println p.text'
    body = "script=" + quote_plus(groovy)
    resp = await flux_client.post(
        "/script", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    rows = [r for r in _log_rows(flux_client) if r.get("result") == "jenkins-script-exec"]
    assert rows
    row = rows[-1]
    assert row["jenkinsScriptSource"] == groovy
    assert row["jenkinsScriptHasExec"] is True
    assert row["jenkinsScriptLen"] == len(groovy)


async def test_post_flags_credential_access(flux_client):
    groovy = (
        "import com.cloudbees.plugins.credentials.CredentialsProvider; "
        "println hudson.util.Secret.decrypt('x')"
    )
    body = "script=" + quote_plus(groovy)
    await flux_client.post(
        "/script", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    row = [r for r in _log_rows(flux_client) if r.get("result") == "jenkins-script-exec"][-1]
    assert row["jenkinsScriptHasCredentialAccess"] is True


async def test_scripttext_returns_plaintext(flux_client):
    resp = await flux_client.post(
        "/scriptText", data="script=" + quote_plus("println 1"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    row = [r for r in _log_rows(flux_client) if r.get("jenkinsScriptFamily") == "text"][-1]
    assert row["result"] == "jenkins-script-exec"


async def test_frontend_dredge_paths_fall_through(flux_client):
    # `/scripts/.env` must NOT be answered as a Jenkins console -- it is
    # credential dredging handled elsewhere. The guarantee here is only
    # that this trap does not claim it.
    assert not tbenv.is_jenkins_script_path("/scripts/.env")
