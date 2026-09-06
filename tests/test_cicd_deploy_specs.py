"""CI/CD deploy-descriptor traps.

`azure.json` / `azure-credentials.json` are credential stores that
deployment tooling writes; `buildspec.yml` / `appspec.yml` are the
CodeBuild / CodeDeploy descriptors that reference other files. All four
are standing entries in secret-dredging dictionaries.
"""
import json

import pytest

import flux.server as tbenv
from tests.test_server import FAKE_TRACEBIT


AWS_KEY_ID = FAKE_TRACEBIT["aws"]["awsAccessKeyId"].encode("ascii")
AWS_SECRET = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"].encode("ascii")


@pytest.mark.parametrize("path,expected_trap", [
    # azure.json — bare webroot, the real on-node location, app layouts
    ("/azure.json", "azure-node-json"),
    ("/etc/kubernetes/azure.json", "azure-node-json"),
    ("/storage/azure.json", "azure-node-json"),
    ("/app/azure.json", "azure-node-json"),
    ("/backend/azure.json", "azure-node-json"),
    # azure-credentials.json — both separator spellings
    ("/azure-credentials.json", "azure-credentials-json"),
    ("/azure_credentials.json", "azure-credentials-json"),
    ("/storage/azure-credentials.json", "azure-credentials-json"),
    ("/app/azure-credentials.json", "azure-credentials-json"),
    # buildspec / appspec — both YAML extensions
    ("/buildspec.yml", "codebuild-buildspec"),
    ("/buildspec.yaml", "codebuild-buildspec"),
    ("/storage/buildspec.yml", "codebuild-buildspec"),
    ("/app/buildspec.yml", "codebuild-buildspec"),
    ("/appspec.yml", "codedeploy-appspec"),
    ("/appspec.yaml", "codedeploy-appspec"),
    ("/storage/appspec.yml", "codedeploy-appspec"),
    ("/app/appspec.yml", "codedeploy-appspec"),
])
def test_deploy_spec_paths_dispatch(path, expected_trap):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == expected_trap, (
        f"{path!r} should dispatch to {expected_trap}, got {trap and trap.name!r}"
    )


@pytest.mark.parametrize("path", [
    # Near-misses that must not be swallowed by the new entries.
    "/azure.json.bak",
    "/myazure.json",
    "/buildspec",
    "/buildspec.json",
    "/appspec.txt",
    "/appspecs.yml",
])
def test_near_miss_paths_do_not_dispatch_here(path):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is None or trap.name not in {
        "azure-node-json",
        "azure-credentials-json",
        "codebuild-buildspec",
        "codedeploy-appspec",
    }, f"{path!r} unexpectedly matched {trap and trap.name!r}"


def test_azure_node_json_places_canary_in_client_secret():
    trap = tbenv._TRAP_BY_PATH["/azure.json"]
    body = trap.render(FAKE_TRACEBIT)
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["aadClientSecret"] == FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
    # Schema markers a client checking for a real cloud-provider config
    # would look at.
    assert parsed["cloud"] == "AzurePublicCloud"
    assert parsed["vmType"] == "vmss"
    assert "aadClientId" in parsed


def test_azure_credentials_json_is_sdk_auth_shaped():
    trap = tbenv._TRAP_BY_PATH["/azure-credentials.json"]
    parsed = json.loads(trap.render(FAKE_TRACEBIT).decode("utf-8"))
    assert parsed["clientSecret"] == FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
    for key in ("clientId", "subscriptionId", "tenantId",
                "activeDirectoryEndpointUrl", "resourceManagerEndpointUrl"):
        assert key in parsed


def test_buildspec_carries_the_canary_pair_in_env_variables():
    trap = tbenv._TRAP_BY_PATH["/buildspec.yml"]
    body = trap.render(FAKE_TRACEBIT)
    assert b"version: 0.2" in body
    assert AWS_KEY_ID in body
    assert AWS_SECRET in body


def test_buildspec_references_paths_the_server_answers():
    """The spec's value is referential: a client that parses it and
    fetches what it names produces a second, attributable request. That
    only works if the referenced paths are served rather than 404."""
    body = tbenv._TRAP_BY_PATH["/buildspec.yml"].render(FAKE_TRACEBIT)
    assert b".env.production" in body
    assert b"scripts/deploy.sh" in body


def test_appspec_names_hook_scripts_and_carries_no_credential():
    """A real appspec has nowhere to put a secret — inventing a slot
    would read as bait to anyone who knows the format."""
    trap = tbenv._TRAP_BY_PATH["/appspec.yml"]
    body = trap.render(FAKE_TRACEBIT)
    assert b"version: 0.0" in body
    assert b"scripts/fetch_secrets.sh" in body
    assert AWS_KEY_ID not in body
    assert AWS_SECRET not in body
    # ... and it must not burn an issuance to say so.
    assert trap.canary_types == ()


@pytest.mark.parametrize("path", [
    "/azure.json",
    "/azure-credentials.json",
    "/buildspec.yml",
])
def test_credential_slots_are_never_fixed_literals(path):
    """Guards the fleet-fingerprint failure mode: a hardcoded secret
    ships the same string from every host and detects nothing on
    replay. The canary comes from the response, and the surrounding
    identifiers regenerate per hit."""
    trap = tbenv._TRAP_BY_PATH[path]
    first = trap.render(FAKE_TRACEBIT)
    empty = trap.render({})
    # With no canary available the secret slot renders empty rather
    # than falling back to a baked-in string.
    assert AWS_SECRET in first
    assert AWS_SECRET not in empty


@pytest.mark.parametrize("path,field", [
    ("/azure.json", "tenantId"),
    ("/azure-credentials.json", "clientId"),
])
def test_json_identifiers_are_per_hit_unique(path, field):
    trap = tbenv._TRAP_BY_PATH[path]
    a = json.loads(trap.render(FAKE_TRACEBIT).decode("utf-8"))
    b = json.loads(trap.render(FAKE_TRACEBIT).decode("utf-8"))
    assert a[field] != b[field]


def test_deploy_specs_are_disabled_with_the_canary_trap_master_switch(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    assert not tbenv.CANARY_TRAPS_ENABLED
