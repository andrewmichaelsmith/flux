"""Cloud instance / container role-credential service.

The point of this trap is not that it answers more paths — it is that the
metadata protocol has two steps and only the second one hands over a
credential. These tests pin that split: the listing steps must stay
canary-free and canary-cheap, the credential steps must carry the canary
in the exact field names a real client parses, and the log line must make
the two-request chain reconstructable.
"""
import json

import pytest
import pytest_asyncio

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


# --- Path resolution ---


@pytest.mark.parametrize("path,kind", [
    ("/latest/meta-data", "index"),
    ("/latest/meta-data/", "index"),
    ("/latest/meta-data/iam", "iam-index"),
    ("/latest/meta-data/iam/", "iam-index"),
    ("/latest/meta-data/iam/security-credentials", "role-list"),
    ("/latest/meta-data/iam/security-credentials/", "role-list"),
    ("/aws/metadata/iam/security-credentials/", "role-list"),
    ("/.aws/metadata/iam/security-credentials/", "role-list"),
    ("/latest/meta-data/iam/security-credentials/some-role", "role-credentials"),
    ("/aws/metadata/iam/security-credentials/some-role", "role-credentials"),
    ("/ecs/task-credentials", "ecs-credentials"),
    ("/ecs/task-credentials.json", "ecs-credentials"),
    ("/aws/ecs/task-credentials", "ecs-credentials"),
    ("/.aws/ecs-task-credentials", "ecs-credentials"),
    ("/k8s/eks/credentials", "ecs-credentials"),
    ("/v2/credentials", "ecs-credentials"),
    ("/v2/credentials/2a1b3c4d-5e6f-7081-92a3-b4c5d6e7f809", "ecs-credentials"),
])
def test_resolve_cloud_imds_matches(path, kind):
    resolved = tbenv.resolve_cloud_imds(path)
    assert resolved is not None, f"expected a match for {path}"
    assert resolved.kind == kind


@pytest.mark.parametrize("path", [
    "/",
    "/latest",
    "/latest/user-data",
    "/latest/meta-data-backup",
    "/iam/security-credentials/",
    "/metadata",
    "/v2/credential",
    "/ecs/task-credentials.bak",
    "/.env",
    "/.aws/credentials",
])
def test_resolve_cloud_imds_rejects(path):
    assert tbenv.resolve_cloud_imds(path) is None, f"unexpected match for {path}"


def test_role_is_taken_verbatim_from_the_request():
    """The role the client guessed is intel, so it is logged as sent
    rather than normalised against the one we advertise."""
    resolved = tbenv.resolve_cloud_imds(
        "/latest/meta-data/iam/security-credentials/InventedRoleName",
    )
    assert resolved.role == "InventedRoleName"


def test_only_credential_steps_spend_a_canary():
    """Walking the tree has to be free — otherwise a broad sweep burns
    issuance quota on responses that contain no secret."""
    for kind in ("index", "iam-index", "role-list"):
        assert not tbenv.CloudImdsRequest(kind).issues_canary
    for kind in ("role-credentials", "ecs-credentials"):
        assert tbenv.CloudImdsRequest(kind).issues_canary


# --- Renderers ---


def test_instance_envelope_uses_the_metadata_field_names():
    body = json.loads(tbenv.render_imds_role_credentials(FAKE_TRACEBIT))
    assert body["Code"] == "Success"
    assert body["Type"] == "AWS-HMAC"
    assert body["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert body["SecretAccessKey"].startswith("wJalrXUtnFEMI")
    # `Token`, not `SessionToken` — clients implementing the metadata
    # provider key on this name and silently ignore the other spelling.
    assert body["Token"] == "FwoGZXIvYXdzEXAMPLEFAKE="
    assert "SessionToken" not in body


def test_container_envelope_uses_the_container_field_names():
    body = json.loads(tbenv.render_ecs_task_credentials(FAKE_TRACEBIT))
    assert body["RoleArn"].startswith("arn:aws:iam::")
    assert body["RoleArn"].endswith(f":role/{tbenv.CLOUD_IMDS_ROLE_NAME}")
    assert body["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert body["Token"] == "FwoGZXIvYXdzEXAMPLEFAKE="
    # The container provider carries no `Code`/`Type` header pair.
    assert "Code" not in body


def test_expiration_is_computed_forward_not_canned():
    """A stale expiry is the cheapest tell that the envelope is canned,
    so it must move with the clock rather than being a literal."""
    from datetime import UTC, datetime

    body = json.loads(tbenv.render_imds_role_credentials(FAKE_TRACEBIT))
    expiry = datetime.strptime(body["Expiration"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert expiry > datetime.now(UTC)


def test_renderers_emit_no_fixed_credential_literal():
    """Every secret-shaped field must come from the issued canary. A
    literal would give zero detection on replay and fingerprint the
    whole fleet with one shared string."""
    empty: dict[str, object] = {}
    for render in (tbenv.render_imds_role_credentials, tbenv.render_ecs_task_credentials):
        body = json.loads(render(empty))
        assert body["AccessKeyId"] == ""
        assert body["SecretAccessKey"] == ""
        assert body["Token"] == ""


# --- Dispatch ---


async def test_role_listing_returns_only_a_name_and_issues_nothing(flux_client, monkeypatch):
    """Step one is the discriminator: it must return a role name, no
    secret, and must not call out to the issuing API at all."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)

    async def _explode(*args, **kwargs):
        raise AssertionError("listing step must not issue a canary")

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _explode)

    resp = await flux_client.get(
        "/latest/meta-data/iam/security-credentials/",
        headers={"X-Forwarded-For": "203.0.113.70"},
    )
    assert resp.status == 200
    body = (await resp.read()).decode()
    assert body.strip() == tbenv.CLOUD_IMDS_ROLE_NAME
    assert "AKIA" not in body

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cloud-imds-role-list"
    assert entry["imdsRole"] == ""
    assert "canaryTypes" not in entry


async def test_credential_step_serves_the_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        f"/latest/meta-data/iam/security-credentials/{tbenv.CLOUD_IMDS_ROLE_NAME}",
        headers={"X-Forwarded-For": "203.0.113.71"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/json"
    body = json.loads(await resp.read())
    assert body["AccessKeyId"] == "AKIAFAKEEXAMPLE01"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cloud-imds-role-credentials"
    # The role the client came back for is what links step two to step
    # one, so it has to survive into the log line.
    assert entry["imdsRole"] == tbenv.CLOUD_IMDS_ROLE_NAME
    assert "aws" in entry["canaryTypes"]


async def test_container_endpoint_serves_the_canary(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/ecs/task-credentials",
        headers={"X-Forwarded-For": "203.0.113.72"},
    )
    assert resp.status == 200
    body = json.loads(await resp.read())
    assert body["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert "RoleArn" in body

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cloud-imds-ecs-credentials"


async def test_issuance_failure_is_logged_not_crashed(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)

    async def _no_canary(*args, **kwargs):
        return None

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _no_canary)

    resp = await flux_client.get(
        "/ecs/task-credentials",
        headers={"X-Forwarded-For": "203.0.113.73"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "cloud-imds-ecs-credentials-error"


async def test_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", False)

    resp = await flux_client.get(
        "/latest/meta-data/iam/security-credentials/",
        headers={"X-Forwarded-For": "203.0.113.74"},
    )
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[-1]["result"] == "not-handled"


async def test_without_api_key_returns_404(flux_client, monkeypatch):
    """Keyless deployments 404 the whole canary-backed surface, and the
    credential steps here are part of it."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)

    resp = await flux_client.get(
        "/ecs/task-credentials",
        headers={"X-Forwarded-For": "203.0.113.75"},
    )
    assert resp.status == 404


async def test_head_keeps_the_length_the_get_will_return(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    head = await flux_client.head(
        "/latest/meta-data/iam/security-credentials/",
        headers={"X-Forwarded-For": "203.0.113.76"},
    )
    assert head.status == 200
    assert await head.read() == b""
    assert int(head.headers["Content-Length"]) == len(tbenv.CLOUD_IMDS_ROLE_NAME) + 1


@pytest.mark.parametrize("path", [
    "/aws/credentials",
    "/aws/iam/temporary-credentials",
    "/internal/aws/credentials",
    "/admin/.aws/credentials",
])
async def test_flat_ini_aliases_route_to_the_ini_renderer(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.77"})
    assert resp.status == 200
    assert b"aws_access_key_id = AKIAFAKEEXAMPLE01" in await resp.read()
    assert _log_entries(flux_client.log_path)[-1]["result"] == "aws-credentials-file"


@pytest.mark.parametrize("path", [
    "/aws/iam/temp-creds.json",
    "/api/v1/aws/credentials",
    "/secrets/aws.json",
    "/.well-known/credentials.json",
])
async def test_flat_json_aliases_route_to_the_json_renderer(flux_client, monkeypatch, path):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.78"})
    assert resp.status == 200
    body = json.loads(await resp.read())
    assert body["Credentials"]["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert _log_entries(flux_client.log_path)[-1]["result"] == "aws-credentials-json"


@pytest.mark.parametrize("path", ["/.gcloud/credentials", "/secrets/gcp.json"])
async def test_gcloud_aliases_route_to_the_service_account_renderer(
    flux_client, monkeypatch, path,
):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.79"})
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["result"] == "gcp-credentials-json"
