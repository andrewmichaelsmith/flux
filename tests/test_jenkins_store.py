"""Tests for the Jenkins build-server state files and the CI-runner home
spellings that ship with them.

Two defects motivated this file, and both are the same shape: a file we
answer under one spelling and 404 under another. A host that serves
`/@fs/home/runner/.aws/credentials` but 404s
`/home/gitlab-runner/.aws/credentials`, or serves `/Jenkinsfile` but 404s
the credential store the pipeline draws from, is not a host — it is this
software's routing table showing through.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- Coverage of the spellings -------------------------------------------


@pytest.mark.parametrize("path", [
    "/credentials.xml",
    "/jenkins/credentials.xml",
    "/.jenkins/credentials.xml",
    "/jenkins_home/credentials.xml",
    "/var/jenkins_home/credentials.xml",
    "/var/lib/jenkins/credentials.xml",
])
def test_credential_store_spellings_all_resolve(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is not None
    assert trap.name == "jenkins-credentials-xml"


@pytest.mark.parametrize("path", [
    "/jenkins/secrets/master.key",
    "/var/jenkins_home/secrets/master.key",
    "/var/lib/jenkins/secrets/master.key",
])
def test_master_key_spellings_all_resolve(path):
    assert tbenv.find_canary_trap(path).name == "jenkins-master-key"


@pytest.mark.parametrize("path", [
    "/jenkins/config.xml",
    "/jenkins/config.xml.bak",
    "/.jenkins/config.xml",
    "/config/jenkins.xml",
    "/var/jenkins_home/config.xml",
])
def test_root_config_spellings_all_resolve(path):
    assert tbenv.find_canary_trap(path).name == "jenkins-config-xml"


def test_absolute_spellings_also_answer_through_the_read_primitive():
    """The defect this closes in the other direction: these absolute
    paths arrived on the dev-server read surface and missed, while the
    webroot spelling of the same file would have answered."""
    for suffix in (
        "/var/jenkins_home/credentials.xml",
        "/var/lib/jenkins/credentials.xml",
    ):
        resolution = tbenv.resolve_vite_fs("/@fs" + suffix)
        assert resolution.resolved
        assert resolution.trap.name == "jenkins-credentials-xml"


# --- CI-runner home spellings --------------------------------------------


def test_every_runner_home_file_answers_under_every_runner_name():
    """Derived, not hand-listed: a file added to one CI home must not be
    missing from the others."""
    runner_paths = [
        p for p in tbenv._TRAP_BY_PATH if p.startswith("/home/runner/")
    ]
    assert runner_paths, "expected the GitHub Actions home to be populated"
    for path in runner_paths:
        leaf = path[len("/home/runner/"):]
        for alias in ("gitlab-runner", "circleci"):
            alias_path = f"/home/{alias}/{leaf}"
            assert tbenv.find_canary_trap(alias_path) is not None, alias_path
            assert (
                tbenv.find_canary_trap(alias_path)
                is tbenv.find_canary_trap(path)
            ), alias_path


def test_gitconfig_keeps_the_same_spellings():
    """`.gitconfig` lives in its own path set rather than the trap table,
    so the derived alias loop does not reach it."""
    for alias in ("runner", "gitlab-runner", "circleci"):
        assert f"/home/{alias}/.gitconfig" in tbenv.GIT_DOTFILE_PATHS


# --- Credential hygiene ---------------------------------------------------


def _render(name):
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    return trap.render({
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "fakeSecretExample01",
            "awsSessionToken": "fakeSessionExample01",
        },
    })


def test_credential_store_carries_the_issued_canary():
    """The one credential in the file a harvester can act on has to be
    the replay-detectable one — otherwise the trap is decorative."""
    body = _render("jenkins-credentials-xml")
    assert b"AKIAFAKEEXAMPLE01" in body
    assert b"fakeSecretExample01" in body


def test_ciphertext_fields_are_per_hit():
    """Everything else in the file is secret-shaped, so none of it may be
    a fixed literal shared across deployments."""
    first = _render("jenkins-credentials-xml")
    second = _render("jenkins-credentials-xml")
    assert first != second
    assert b"<password>{" in first


def test_master_key_is_minted_per_hit():
    first = _render("jenkins-master-key")
    second = _render("jenkins-master-key")
    assert first != second
    assert len(first.strip()) == 256


def test_root_config_carries_no_credential_material():
    body = _render("jenkins-config-xml").lower()
    for marker in (b"akia", b"password>", b"secret", b"begin "):
        assert marker not in body


def test_master_key_and_root_config_spend_no_canary():
    """Neither file contains a credential, so neither should burn upstream
    quota to render one."""
    for name in ("jenkins-master-key", "jenkins-config-xml"):
        trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
        assert trap.canary_types == ()


# --- End-to-end dispatch --------------------------------------------------


async def _fake_canary(*_args, **_kwargs):
    return {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "fakeSecretExample01",
            "awsSessionToken": "fakeSessionExample01",
        },
    }


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_dispatch_serves_the_credential_store(flux_client):
    resp = await flux_client.get(
        "/jenkins/credentials.xml", headers={"X-Forwarded-For": "203.0.113.60"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "jenkins-credentials-xml"


async def test_dispatch_serves_the_ci_runner_home_spelling(flux_client):
    resp = await flux_client.get(
        "/home/gitlab-runner/.aws/credentials",
        headers={"X-Forwarded-For": "203.0.113.61"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()


async def test_credential_store_reachable_through_the_appliance_read(flux_client):
    """All three read surfaces land on one document — the webroot, the
    dev-server primitive and the appliance body traversal."""
    resp = await flux_client.post(
        "/clients/MyCRL",
        data="aCSHELL/../../../../../../../var/jenkins_home/credentials.xml",
        headers={"X-Forwarded-For": "203.0.113.62"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "checkpoint-read-jenkins-credentials-xml"
    assert entry["checkpointReadPath"] == "/var/jenkins_home/credentials.xml"
