"""Kubernetes API Secret / ConfigMap list traps (anonymous-read cluster)."""

from __future__ import annotations

import base64
import json

import pytest

from flux import server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, flux_client  # noqa: F401

AWS = FAKE_TRACEBIT["aws"]

SECRET_PATHS = (
    "/api/v1/namespaces/default/secrets",
    "/api/v1/namespaces/kube-system/secrets",
    "/api/v1/namespaces/kube-system/secrets/",
    "/api/v1/secrets",
    "/kube-system/secrets",
    "/API/V1/Namespaces/Default/Secrets",
)
CONFIGMAP_PATHS = (
    "/api/v1/namespaces/default/configmaps",
    "/api/v1/namespaces/kube-system/configmaps",
    "/api/v1/configmaps",
    "/kube-system/configmaps",
)
MUST_NOT_MATCH = (
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/namespaces/default/pods",
    "/api/v1/namespaces/default/secrets/aws-credentials",
    "/secrets",
    "/kubernetes/secrets.yaml",
)


def _render(fn, path):
    return json.loads(fn({**FAKE_TRACEBIT, "_requestPath": path}))


@pytest.mark.parametrize("path", SECRET_PATHS)
def test_secret_list_paths_resolve(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is not None and trap.name == "k8s-secret-list"


@pytest.mark.parametrize("path", CONFIGMAP_PATHS)
def test_configmap_list_paths_resolve(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is not None and trap.name == "k8s-configmap-list"


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_non_list_paths_do_not_resolve_to_the_list_traps(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is None or trap.name not in {"k8s-secret-list", "k8s-configmap-list"}


def test_secret_list_carries_the_canary_only_base64_encoded():
    """Secret `data` is base64 as the API serves it: the key must
    round-trip through a real b64decode and must NOT appear in the clear,
    or a replay could not separate decoding readers from greppers."""
    raw = tbenv.render_k8s_secret_list({**FAKE_TRACEBIT, "_requestPath": "/api/v1/secrets"})
    assert AWS["awsAccessKeyId"].encode() not in raw
    body = json.loads(raw)
    assert body["kind"] == "SecretList" and body["apiVersion"] == "v1"
    items = body["items"]
    assert items, "premise: the list must not be empty"
    for item in items:
        for value in item["data"].values():
            base64.b64decode(value, validate=True)
    cloud = next(i for i in items if i["metadata"]["name"] == "aws-credentials")
    data = {k: base64.b64decode(v).decode() for k, v in cloud["data"].items()}
    assert data["AWS_ACCESS_KEY_ID"] == AWS["awsAccessKeyId"]
    # The real secret key contains `/` and `+`-adjacent characters; it must
    # survive the encoding byte-for-byte.
    assert data["AWS_SECRET_ACCESS_KEY"] == AWS["awsSecretAccessKey"]
    assert data["AWS_SESSION_TOKEN"] == AWS["awsSessionToken"]


def test_secret_list_echoes_the_requested_namespace():
    for path, ns in (
        ("/api/v1/namespaces/kube-system/secrets", "kube-system"),
        ("/kube-system/secrets", "kube-system"),
        ("/api/v1/namespaces/default/secrets", "default"),
        ("/api/v1/secrets", "default"),
    ):
        body = _render(tbenv.render_k8s_secret_list, path)
        assert {i["metadata"]["namespace"] for i in body["items"]} == {ns}


def test_secret_list_has_no_fixed_secret_material():
    a = _render(tbenv.render_k8s_secret_list, "/api/v1/secrets")
    b = _render(tbenv.render_k8s_secret_list, "/api/v1/secrets")

    def by_name(body, prefix):
        return next(i for i in body["items"] if i["metadata"]["name"].startswith(prefix))

    assert by_name(a, "postgres")["data"]["POSTGRES_PASSWORD"] != by_name(b, "postgres")["data"]["POSTGRES_PASSWORD"]
    assert by_name(a, "default-token")["data"]["token"] != by_name(b, "default-token")["data"]["token"]
    assert by_name(a, "aws")["metadata"]["uid"] != by_name(b, "aws")["metadata"]["uid"]


def test_configmap_list_carries_the_canary_in_plaintext():
    body = _render(tbenv.render_k8s_configmap_list, "/api/v1/namespaces/kube-system/configmaps")
    assert body["kind"] == "ConfigMapList"
    assert body["items"], "premise: the list must not be empty"
    assert {i["metadata"]["namespace"] for i in body["items"]} == {"kube-system"}
    app = next(i for i in body["items"] if i["metadata"]["name"] == "app-config")
    env = app["data"]["app.env"]
    assert f"AWS_ACCESS_KEY_ID={AWS['awsAccessKeyId']}\n" in env
    assert f"AWS_SECRET_ACCESS_KEY={AWS['awsSecretAccessKey']}\n" in env


@pytest.fixture
def canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


async def test_served_secret_list_is_json_and_logged(flux_client, canary):  # noqa: F811
    resp = await flux_client.get("/api/v1/namespaces/default/secrets")
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    body = json.loads(await resp.read())
    assert body["kind"] == "SecretList"
    rows = [json.loads(line) for line in flux_client.log_path.read_text().splitlines()]
    assert any(r.get("result") == "k8s-secret-list" for r in rows)


async def test_served_configmap_list(flux_client, canary):  # noqa: F811
    resp = await flux_client.get("/kube-system/configmaps")
    assert resp.status == 200
    body = json.loads(await resp.read())
    assert body["kind"] == "ConfigMapList"


def test_canary_master_switch_disables_the_list_traps(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    assert tbenv.find_canary_trap("/api/v1/secrets") is None
