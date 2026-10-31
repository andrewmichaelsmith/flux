"""Agent-instruction breadcrumb: CLAUDE.md / AGENTS.md name a per-hit
session-context link, and a fetch of it is logged as a follow-up that joins
to the issuing hit."""

from __future__ import annotations

import json
import re

import pytest

from flux import server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401

AWS = FAKE_TRACEBIT["aws"]
LINK_RE = re.compile(r"(/internal/agent/sessions/[0-9a-f-]{36}/context)")
CRUMB = "/internal/agent/sessions/0b468c68-68c0-4bad-b9ed-3ea6c71f73a4/context"


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    tbenv._AGENT_BREADCRUMBS.clear()


@pytest.mark.parametrize("path", ["/CLAUDE.md", "/claude.md", "/AGENTS.md", "/.claude/CLAUDE.md"])
def test_instruction_files_resolve_to_agents_md(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is not None and trap.name == "agents-md"


@pytest.mark.parametrize("path", ["/.windsurf/mcp.json", "/.junie/mcp.json", "/.amazonq/mcp.json"])
async def test_ai_editor_mcp_dirs_reach_mcp_config(flux_client, keyed, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.70"})
    assert resp.status == 200
    assert "mcpServers" in json.loads(await resp.text())
    assert _log_entries(flux_client.log_path)[-1]["result"] == "mcp-config"


def test_breadcrumb_matcher():
    assert tbenv.is_agent_breadcrumb_path(CRUMB)
    assert tbenv.is_agent_breadcrumb_path(CRUMB.rsplit("/", 1)[0])
    assert tbenv.is_agent_breadcrumb_path(CRUMB.upper().replace("/INTERNAL/AGENT/SESSIONS/", "/internal/agent/sessions/"))
    for miss in (
        "/internal/agent/sessions/",
        "/internal/agent/sessions/not-a-uuid/context",
        "/internal/agent/deploy",
        "/internal/aws/credentials",
        CRUMB + "/../../etc/passwd",
    ):
        assert not tbenv.is_agent_breadcrumb_path(miss), miss


def test_claude_md_is_titled_after_the_file():
    body = tbenv.render_agents_md({**FAKE_TRACEBIT, "_requestPath": "/CLAUDE.md", "_requestId": "x"}).decode()
    assert body.startswith("# CLAUDE.md\n")
    body = tbenv.render_agents_md({**FAKE_TRACEBIT, "_requestPath": "/AGENTS.md", "_requestId": "x"}).decode()
    assert body.startswith("# AGENTS.md\n")
    # The canary sits under names that match its shape.
    assert f"AWS_ACCESS_KEY_ID={AWS['awsAccessKeyId']}" in body
    assert f"AWS_SECRET_ACCESS_KEY={AWS['awsSecretAccessKey']}" in body


async def test_followup_joins_to_the_issuing_hit(flux_client, keyed):
    ip = "203.0.113.71"
    resp = await flux_client.get("/CLAUDE.md", headers={"X-Forwarded-For": ip})
    assert resp.status == 200
    body = await resp.text()
    links = LINK_RE.findall(body)
    assert len(links) == 1, body
    issued = _log_entries(flux_client.log_path)[-1]
    assert issued["result"] == "agents-md"
    # The link carries the issuing hit's requestId — the offline join key.
    assert issued["requestId"] in links[0]

    resp = await flux_client.get(links[0], headers={"X-Forwarded-For": ip})
    assert resp.status == 200
    ctx = json.loads(await resp.text())
    assert ctx["credentials"]["AccessKeyId"] == AWS["awsAccessKeyId"]
    assert ctx["credentials"]["SecretAccessKey"] == AWS["awsSecretAccessKey"]
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "agent-session-context-referenced"
    assert entry["agentBreadcrumbId"] == issued["requestId"]
    assert entry["agentBreadcrumbKnown"] is True
    assert entry["agentBreadcrumbSameIp"] is True
    assert entry["agentBreadcrumbIssuedPath"].lower() == "/claude.md"
    assert entry["agentBreadcrumbAgeSeconds"] >= 0


async def test_followup_from_another_address_is_still_ours(flux_client, keyed):
    await flux_client.get("/AGENTS.md", headers={"X-Forwarded-For": "203.0.113.72"})
    issued = _log_entries(flux_client.log_path)[-1]
    link = f"/internal/agent/sessions/{issued['requestId']}/context"
    resp = await flux_client.get(link, headers={"X-Forwarded-For": "198.51.100.9"})
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "agent-session-context-referenced"
    assert entry["agentBreadcrumbSameIp"] is False


async def test_unknown_id_is_foreign_with_the_same_body(flux_client, keyed):
    resp = await flux_client.get(CRUMB, headers={"X-Forwarded-For": "203.0.113.73"})
    assert resp.status == 200
    assert "SecretAccessKey" in await resp.text()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "agent-session-context-foreign"
    assert entry["agentBreadcrumbKnown"] is False


async def test_history_jsonl_names_the_same_link(flux_client, keyed):
    resp = await flux_client.get("/.claude/history.jsonl", headers={"X-Forwarded-For": "203.0.113.74"})
    rows = [json.loads(l) for l in (await resp.text()).splitlines()]
    assert len(rows) == 2
    assert LINK_RE.search(rows[1]["message"])
    assert "staging.internal.lan" not in rows[1]["message"]


async def test_disabled_drops_link_and_route(flux_client, keyed, monkeypatch):
    monkeypatch.setattr(tbenv, "AGENT_BREADCRUMB_ENABLED", False)
    resp = await flux_client.get("/CLAUDE.md", headers={"X-Forwarded-For": "203.0.113.75"})
    assert resp.status == 200
    assert not LINK_RE.search(await resp.text())
    resp = await flux_client.get(CRUMB, headers={"X-Forwarded-For": "203.0.113.75"})
    assert resp.status == 404


async def test_keyless_does_not_serve_the_followup(flux_client, keyed, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(CRUMB, headers={"X-Forwarded-For": "203.0.113.76"})
    assert resp.status == 404


def test_registry_is_bounded(monkeypatch):
    tbenv._AGENT_BREADCRUMBS.clear()
    monkeypatch.setattr(tbenv, "_AGENT_BREADCRUMB_MAX", 3)
    for i in range(10):
        tbenv._agent_breadcrumb_url({"_requestId": f"id-{i}", "_clientIp": "x"})
    assert list(tbenv._AGENT_BREADCRUMBS) == ["id-7", "id-8", "id-9"]
