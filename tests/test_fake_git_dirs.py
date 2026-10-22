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


# --- loose-object fan-out directories ----------------------------------
#
# `objects/` holds one two-hex directory per object a repo stores, and an
# autoindex lists them. Listing only `info/` and `pack/` was internally
# inconsistent: the tree served `objects/<2-hex>/<38-hex>` while denying
# that `<2-hex>/` existed, so a dumper that lists before it fetches saw an
# empty object store and stopped walking.

def _fanout_prefixes(repo):
    """The two-hex prefixes of every loose object the tree registers."""
    return {
        key.split("/")[3]
        for key in repo
        if key.startswith("/.git/objects/")
        and len(key.split("/")) == 5
        and len(key.split("/")[3]) == 2
        and len(key.split("/")[4]) == 38
    }


def test_tree_actually_stores_loose_objects(repo):
    """Guard the premise: if this is empty the rest proves nothing."""
    assert _fanout_prefixes(repo)


def test_every_fanout_directory_has_an_autoindex(repo):
    for prefix in _fanout_prefixes(repo):
        assert f"/.git/objects/{prefix}/" in repo, prefix


def test_objects_index_lists_every_fanout_directory(repo):
    body = repo["/.git/objects/"].decode()
    for prefix in _fanout_prefixes(repo):
        assert f'href="{prefix}/"' in body, prefix


def test_objects_index_still_lists_info_and_pack(repo):
    body = repo["/.git/objects/"].decode()
    assert 'href="info/"' in body
    assert 'href="pack/"' in body


def test_fanout_autoindex_lists_the_object_it_holds(repo):
    for prefix in _fanout_prefixes(repo):
        listing = repo[f"/.git/objects/{prefix}/"].decode()
        suffixes = [
            key.split("/")[4] for key in repo
            if key.startswith(f"/.git/objects/{prefix}/")
            and len(key.split("/")) == 5 and len(key.split("/")[4]) == 38
        ]
        assert suffixes, prefix
        for suffix in suffixes:
            assert f'href="{suffix}"' in listing, (prefix, suffix)


def test_unused_prefixes_are_not_invented(repo):
    """A real repo has no directory for a prefix it stores nothing under.
    Fabricating all 256 would be the tell."""
    present = _fanout_prefixes(repo)
    absent = [f"{n:02x}" for n in range(256) if f"{n:02x}" not in present]
    assert absent, "tree cannot plausibly occupy all 256 prefixes"
    for prefix in absent[:12]:
        assert f"/.git/objects/{prefix}/" not in repo, prefix


async def _served_prefixes(flux_client, ip):
    """Two-hex prefixes as the LIVE tree lists them. Rebuilding the repo
    locally yields different shas (the commit timestamp moves), so the
    prefixes must come from the server's own index, not a second build."""
    import re as _re
    resp = await flux_client.get(
        "/.git/objects/", headers={"X-Forwarded-For": ip},
    )
    assert resp.status == 200
    return sorted(set(_re.findall(r'href="([0-9a-f]{2})/"', await resp.text())))


def _enable(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()


async def test_served_objects_index_lists_fanout_dirs(flux_client, monkeypatch):
    _enable(monkeypatch)
    assert await _served_prefixes(flux_client, "203.0.113.38")


async def test_bare_fanout_directory_redirects(flux_client, monkeypatch):
    """The spelling actually observed is bare (`/.git/objects/9d`), so it
    must reach the existing directory redirect rather than a miss."""
    _enable(monkeypatch)
    prefix = (await _served_prefixes(flux_client, "203.0.113.35"))[0]

    resp = await flux_client.get(
        f"/.git/objects/{prefix}",
        headers={"X-Forwarded-For": "203.0.113.35"}, allow_redirects=False,
    )
    assert resp.status == 301
    assert resp.headers["Location"] == f"/.git/objects/{prefix}/"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fake-git-redirect"


async def test_fanout_directory_serves_an_html_autoindex(flux_client, monkeypatch):
    _enable(monkeypatch)
    prefix = (await _served_prefixes(flux_client, "203.0.113.36"))[0]

    resp = await flux_client.get(
        f"/.git/objects/{prefix}/",
        headers={"X-Forwarded-For": "203.0.113.36"},
    )
    assert resp.status == 200
    assert "text/html" in resp.headers["Content-Type"]
    assert f"Index of /.git/objects/{prefix}" in await resp.text()


async def test_listed_object_is_fetchable_so_the_walk_completes(
    flux_client, monkeypatch,
):
    """The point of the fix: a lister must be able to go index -> object."""
    import re as _re
    _enable(monkeypatch)
    prefix = (await _served_prefixes(flux_client, "203.0.113.37"))[0]

    index = await (await flux_client.get(
        f"/.git/objects/{prefix}/", headers={"X-Forwarded-For": "203.0.113.37"},
    )).text()
    suffix = _re.search(r'href="([0-9a-f]{38})"', index).group(1)

    resp = await flux_client.get(
        f"/.git/objects/{prefix}/{suffix}",
        headers={"X-Forwarded-For": "203.0.113.37"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/x-git-loose-object"
    assert (await resp.read()).startswith(b"\x78")  # zlib deflate
