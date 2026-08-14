"""Shell rc files as a credential surface.

`~/.bashrc` and its siblings are asked for by the same sweep that walks
`.env` and `.aws/credentials`, and for the same reason: an `export
AWS_ACCESS_KEY_ID=` line in an rc file is the documented workaround for
a CLI that cannot see the credentials file, so it is a place credentials
genuinely survive.

These tests pin the routing, the canary placement, and the rule that
matters most — nothing secret-shaped in the file may be a fixed literal.
"""
import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


@pytest.mark.parametrize("path", [
    "/.bashrc",
    "/.bash_profile",
    "/.bash_login",
    "/.profile",
    "/.zshrc",
    "/.zprofile",
    "/.zshenv",
    "/.kshrc",
    "/.cshrc",
    "/root/.bashrc",
    "/root/.profile",
    "/home/ubuntu/.bashrc",
    "/app/.bashrc",
    "/storage/.profile",
])
def test_shell_rc_paths_route_to_the_trap(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == "shell-rc", f"{path} routed to {trap.name}"


@pytest.mark.parametrize("path", [
    "/.bash_history",   # history file, not an rc — different renderer's job
    "/bashrc",          # no leading dot
    "/.bashrc.swp",
    "/.env",
])
def test_neighbouring_names_are_not_claimed(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is None or trap.name != "shell-rc"


def test_rc_file_carries_the_canary_in_export_lines():
    """A harvester greps raw bytes for the AKIA/secret pair, so the
    credential has to sit in the file as a shell export rather than in
    any structured wrapper."""
    body = tbenv.render_shell_rc(FAKE_TRACEBIT).decode()
    assert "export AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01\n" in body
    assert "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI" in body
    assert "export AWS_SESSION_TOKEN=FwoGZXIvYXdzEXAMPLEFAKE=\n" in body


def test_rc_file_reads_like_a_real_one():
    """The export block is only believable inside ordinary interactive
    boilerplate; a file containing nothing but credentials is a tell."""
    body = tbenv.render_shell_rc(FAKE_TRACEBIT).decode()
    for marker in ("HISTCONTROL=", "shopt -s histappend", "alias ll=", "export EDITOR="):
        assert marker in body, marker


def test_no_fixed_credential_literal_survives_an_empty_canary():
    """Every secret-shaped field must come from the issued canary — an
    empty response must leave empty values, never a baked-in fallback."""
    body = tbenv.render_shell_rc({}).decode()
    assert "export AWS_ACCESS_KEY_ID=\n" in body
    assert "export AWS_SECRET_ACCESS_KEY=\n" in body
    assert "export AWS_SESSION_TOKEN=\n" in body
    assert "AKIA" not in body


def test_registry_token_is_minted_per_hit():
    """The one non-canary secret in the file. It cannot be monitored, so
    uniqueness is the only thing keeping it from becoming a single
    string shared across every deployment."""
    tokens = set()
    for _ in range(3):
        for line in tbenv.render_shell_rc(FAKE_TRACEBIT).decode().splitlines():
            if line.startswith("export REGISTRY_TOKEN="):
                tokens.add(line.split("=", 1)[1])
    assert len(tokens) == 3


async def test_dispatch_serves_the_rc_file(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get("/.bashrc", headers={"X-Forwarded-For": "203.0.113.95"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "text/plain; charset=utf-8"
    body = (await resp.read()).decode()
    assert "AKIAFAKEEXAMPLE01" in body

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "shell-rc"
    assert "aws" in entry["canaryTypes"]


async def test_fs_walk_reaches_the_rc_file(flux_client, monkeypatch):
    """The `/@fs/` read primitive resolves through the same trap table,
    so the absolute-path spelling has to land on the same renderer —
    that is the whole reason the home-dir paths are enumerated."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "VITE_FS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get("/@fs/root/.bashrc")
    assert resp.status == 200
    assert "AKIAFAKEEXAMPLE01" in (await resp.read()).decode()
