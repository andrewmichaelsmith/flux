"""Fake `/.git/` tree: directory spellings, the two missing repo entries,
and the drip cap no longer refusing a file.

Repo dumpers walk directories as well as files. Every directory in this tree
was reachable only by its slash-terminated spelling, so `refs/heads`,
`objects/pack`, `hooks` and `branches` asked for bare came back as misses for
directories the tree does have — the same gap the working-copy tree had, and
the same fix.
"""
import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


@pytest.fixture
def repo():
    files, _meta = tbenv._build_fake_repo("SECRET_KEY=x\n", FAKE_TRACEBIT)
    return files


# --- entries the tree was missing --------------------------------------

def test_branches_directory_exists(repo):
    """`branches/` is the legacy remote shorthand dir. Modern git still
    creates it and leaves it empty, so an empty autoindex is faithful."""
    assert "/.git/branches/" in repo


def test_remotes_origin_head_exists(repo):
    """Written by `clone` and by `remote set-head` — a symref, not a sha."""
    body = repo.get("/.git/remotes/origin/head")
    assert body is not None
    assert body.startswith(b"ref: refs/remotes/origin/")


def test_remotes_origin_head_is_a_symref_not_a_raw_sha(repo):
    body = repo["/.git/remotes/origin/head"]
    assert b"ref: " in body
    assert len(body.strip()) != 40


# --- bare directory spellings redirect ---------------------------------

@pytest.mark.parametrize("path,location", [
    ("/.git/hooks", "/.git/hooks/"),
    ("/.git/refs/heads", "/.git/refs/heads/"),
    ("/.git/objects/pack", "/.git/objects/pack/"),
    ("/.git/branches", "/.git/branches/"),
])
async def test_bare_directory_redirects(flux_client, monkeypatch, path, location):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    resp = await flux_client.get(
        path, headers={"X-Forwarded-For": "203.0.113.31"}, allow_redirects=False,
    )
    assert resp.status == 301
    assert resp.headers["Location"] == location
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fake-git-redirect"
    assert entry["location"] == location


async def test_redirect_keeps_the_clients_own_prefix(flux_client, monkeypatch):
    """`Location` is built from the request path, not the canonical lookup
    key, so a repo probed under a subpath is redirected inside its prefix."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    resp = await flux_client.get(
        "/app/.git/refs/heads",
        headers={"X-Forwarded-For": "203.0.113.32"}, allow_redirects=False,
    )
    assert resp.status == 301
    assert resp.headers["Location"] == "/app/.git/refs/heads/"


async def test_a_real_miss_is_still_a_miss(flux_client, monkeypatch):
    """The redirect must not turn every unknown path into a 301."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    resp = await flux_client.get(
        "/.git/no/such/thing",
        headers={"X-Forwarded-For": "203.0.113.33"}, allow_redirects=False,
    )
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[-1]["result"] == "fake-git-miss"


async def test_all_zero_object_sha_stays_a_miss(flux_client, monkeypatch):
    """Scanners probe an all-zero object sha as a sentinel — that object
    genuinely cannot exist, so answering it would be the tell."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    resp = await flux_client.get(
        "/.git/objects/00/" + "0" * 38,
        headers={"X-Forwarded-For": "203.0.113.34"}, allow_redirects=False,
    )
    assert resp.status == 404


# --- The all-zero object id must keep 404ing --------------------------
# `0000000000000000000000000000000000000000` is git's null object id: a
# sentinel the reflog uses for "no commit yet", never a real entry in an
# object store. A genuinely exposed `.git` therefore 404s it, and a
# server that fabricates object responses answers it — which makes the
# request a cheap test of whether the host is making its tree up.
#
# So the 404 here is the *correct* response and the whole point of
# serving a convincing tree. It is pinned as a test because it reads
# like a coverage gap in the miss log: the path arrives under `.git`,
# gets classified a fake-git miss, and sits near the top of any
# ranking of unanswered git paths by source count. Answering it to
# close that apparent gap would hand every sender a reliable
# this-is-not-a-real-repo signal.
@pytest.mark.parametrize("prefix", ["", "/app", "/api", "/wp-content"])
async def test_null_object_id_is_not_served(flux_client, monkeypatch, prefix):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    null_sha = "0" * 40
    resp = await flux_client.get(
        f"{prefix}/.git/objects/{null_sha[:2]}/{null_sha[2:]}",
        headers={"X-Forwarded-For": "203.0.113.41"}, allow_redirects=False,
    )
    assert resp.status == 404


async def test_a_real_object_path_still_resolves(flux_client, monkeypatch):
    """Guards the test above against passing because object serving is
    broken outright rather than because the null id is special-cased.

    The object ids depend on the canary minted for the caller, so the
    probe is derived by following the ref the server itself served
    rather than by rebuilding the repo here.
    """
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()

    caller = {"X-Forwarded-For": "203.0.113.42"}
    ref = await flux_client.get(
        "/.git/refs/heads/main", headers=caller, allow_redirects=False,
    )
    assert ref.status == 200
    sha = (await ref.text()).strip()
    assert len(sha) == 40 and set(sha) <= set("0123456789abcdef"), sha
    assert set(sha) != {"0"}, "ref points at the null id"

    resp = await flux_client.get(
        f"/.git/objects/{sha[:2]}/{sha[2:]}",
        headers=caller, allow_redirects=False,
    )
    assert resp.status == 200
