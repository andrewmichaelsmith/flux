"""Config-file names that were falling through to a 404.

Each of these arrives inside a sweep the trap table already answers most
of — the `.vscode/` sweep, the Firebase sweep, the `config/` sweep — so
the miss was splitting one dictionary across two outcomes rather than
representing a population we weren't seeing. These tests pin the routing
and the per-hit-unique rule.
"""
import json

import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


@pytest.mark.parametrize("path,trap_name", [
    ("/.vscode/launch.json", "vscode-launch-json"),
    ("/.vscode/tasks.json", "vscode-launch-json"),
    ("/app/.vscode/launch.json", "vscode-launch-json"),
    ("/__/firebase/init.json", "firebase-init-json"),
    ("/__/firebase/init.js", "firebase-init-js"),
    ("/config/runtime.exs", "elixir-config-exs"),
    ("/config/prod.exs", "elixir-config-exs"),
    ("/config/releases.exs", "elixir-config-exs"),
    ("/.hermes/auth.json", "composer-auth-json"),
])
def test_paths_route_to_the_expected_trap(path, trap_name):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == trap_name, f"{path} routed to {trap.name}"


def test_existing_owners_are_not_stolen():
    """`.vscode/sftp.json` and the service-account `firebase-*.json`
    family keep their own renderers — these additions sit beside them."""
    assert tbenv._TRAP_BY_PATH["/.vscode/sftp.json"].name == "sftp-config"
    assert tbenv._TRAP_BY_PATH["/firebase.json"].name == "firebase-json"
    assert tbenv._TRAP_BY_PATH["/auth.json"].name == "composer-auth-json"
    assert tbenv._TRAP_BY_PATH["/.hermes/config.yaml"].name == "app-config-yaml"


def test_launch_json_puts_the_canary_where_a_debug_run_reads_it():
    payload = json.loads(tbenv.render_vscode_launch_json(FAKE_TRACEBIT))
    env = payload["configurations"][0]["env"]
    assert env["AWS_ACCESS_KEY_ID"] == "AKIAFAKEEXAMPLE01"
    assert env["AWS_SECRET_ACCESS_KEY"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert env["AWS_SESSION_TOKEN"] == "FwoGZXIvYXdzEXAMPLEFAKE="


def test_firebase_init_json_and_js_agree():
    """The JS spelling wraps the same config object — a client that
    fetches both must not see two different projects."""
    payload = json.loads(tbenv.render_firebase_init_json(FAKE_TRACEBIT))
    script = tbenv.render_firebase_init_js(FAKE_TRACEBIT).decode()
    assert payload["apiKey"] == "AKIAFAKEEXAMPLE01"
    assert payload["projectId"] in script
    assert "firebase.initializeApp(" in script
    assert payload["apiKey"] in script


def test_elixir_runtime_exs_is_plausible_elixir_carrying_the_canary():
    body = tbenv.render_elixir_config_exs(FAKE_TRACEBIT).decode()
    assert body.startswith("import Config\n")
    assert 'access_key_id: "AKIAFAKEEXAMPLE01"' in body
    assert "secret_access_key: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"" in body
    # The System.get_env-with-literal-fallback shape is the actual reason
    # secrets end up in this file; keep it.
    assert 'System.get_env("DATABASE_URL") ||' in body


def test_elixir_secrets_are_per_hit():
    """secret_key_base and the database password are synthetics, not
    canaries — so they must differ between hits rather than shipping one
    shared literal to every deployment."""
    first = tbenv.render_elixir_config_exs(FAKE_TRACEBIT).decode()
    second = tbenv.render_elixir_config_exs(FAKE_TRACEBIT).decode()

    def _field(body, marker):
        line = next(line for line in body.splitlines() if marker in line)
        return line.strip()

    assert _field(first, "secret_key_base") != _field(second, "secret_key_base")
    assert _field(first, "ecto://") != _field(second, "ecto://")


async def test_dispatch_serves_launch_json(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/.vscode/launch.json", headers={"X-Forwarded-For": "203.0.113.31"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in await resp.read()
    assert _log_entries(flux_client.log_path)[-1]["result"] == "vscode-launch-json"


async def test_dispatch_serves_elixir_runtime_config(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/config/runtime.exs", headers={"X-Forwarded-For": "203.0.113.32"},
    )
    assert resp.status == 200
    assert (await resp.read()).startswith(b"import Config\n")
    assert _log_entries(flux_client.log_path)[-1]["result"] == "elixir-config-exs"


async def test_dispatch_serves_firebase_init(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/__/firebase/init.json", headers={"X-Forwarded-For": "203.0.113.33"},
    )
    assert resp.status == 200
    assert json.loads(await resp.read())["apiKey"] == "AKIAFAKEEXAMPLE01"
    assert _log_entries(flux_client.log_path)[-1]["result"] == "firebase-init-json"
