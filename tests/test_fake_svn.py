"""Fake Subversion working copy.

A working copy left in a webroot is a long-lived exposure class, and the
`.svn/*` dictionary is still walked in the same sweep that walks
`.git/config`. The trap answers both working-copy generations — the
pre-1.7 `entries` + `text-base` layout and the 1.7+ `wc.db` + `pristine`
layout — because which one a client asks for, and whether it follows
that format through to the pristine copy holding the file contents, is
the measurement the trap exists to produce.

These tests pin the routing, the two layouts staying mutually
consistent, the three independent canary placements, and the rule that
matters most: nothing secret-shaped may be a fixed literal.
"""
import hashlib
import sqlite3
import tempfile

import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


@pytest.fixture
def wc():
    files, meta = tbenv._build_fake_svn_wc(FAKE_TRACEBIT)
    return files, meta


# --- path routing -----------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/.svn", "/.svn/"),
    ("/.svn/", "/.svn/"),
    ("/.svn/entries", "/.svn/entries"),
    ("/.svn/wc.db", "/.svn/wc.db"),
    ("/.svn/auth/svn.simple", "/.svn/auth/svn.simple"),
    ("/.SVN/Entries", "/.svn/entries"),
    ("/login/.svn/entries", "/.svn/entries"),
    ("/app/sub/.svn/wc.db", "/.svn/wc.db"),
])
def test_extract_svn_path_canonicalises(path, expected):
    assert tbenv.extract_svn_path(path) == expected


@pytest.mark.parametrize("path", [
    "/",
    "/.env",
    "/.git/config",
    "/svn/entries",       # no leading dot on the segment
    "/.svneditor",        # substring, not a path segment
    "",
])
def test_non_svn_paths_are_not_claimed(path):
    assert tbenv.extract_svn_path(path) is None


def test_git_prefixed_svn_paths_stay_with_fake_git():
    """A scanner appending the svn dictionary to every git path it tried
    produces `/.git/config/.svn/entries`. Dispatch consults fake-git
    first, so that stays a fake-git miss instead of being reclassified as
    svn traffic — the existing signal is worth more than the extra 200."""
    path = "/.git/config/.svn/entries"
    assert tbenv.extract_git_path(path) == "/.git/config/.svn/entries"
    # extract_svn_path would also match it; dispatch order is what decides.
    assert tbenv.extract_svn_path(path) == "/.svn/entries"


# --- working copy contents -------------------------------------------

def test_pre_17_and_modern_layouts_are_both_served(wc):
    files, _meta = wc
    # pre-1.7
    assert files["/.svn/format"] == b"10\n"
    assert b"\x0c" in files["/.svn/entries"], "entries records are form-feed separated"
    assert "/.svn/text-base/.env.svn-base" in files
    # 1.7+
    assert files["/.svn/wc.db"].startswith(b"SQLite format 3\x00")
    assert any(k.startswith("/.svn/pristine/") and k.endswith(".svn-base") for k in files)


def test_wc_db_is_a_real_database_naming_real_pristine_files(wc):
    """A dumper opens wc.db with SQLite, reads NODES for the file list and
    each `$sha1$...` checksum, then fetches the pristine file that
    checksum names. Every step has to actually work."""
    files, _meta = wc
    with tempfile.NamedTemporaryFile(suffix=".db") as handle:
        handle.write(files["/.svn/wc.db"])
        handle.flush()
        connection = sqlite3.connect(handle.name)
        try:
            root, uuid_value = connection.execute(
                "SELECT root, uuid FROM REPOSITORY",
            ).fetchone()
            assert uuid_value
            rows = connection.execute(
                "SELECT local_relpath, checksum FROM NODES"
                " WHERE kind = 'file' ORDER BY local_relpath",
            ).fetchall()
        finally:
            connection.close()

    assert {relpath for relpath, _c in rows} == {
        ".env", "README.md", "config/database.yml", "deploy.sh",
    }
    for relpath, checksum in rows:
        assert checksum.startswith("$sha1$"), relpath
        sha1 = checksum[len("$sha1$"):]
        pristine_key = f"/.svn/pristine/{sha1[:2]}/{sha1}.svn-base"
        assert pristine_key in files, f"{relpath} names a pristine file that isn't served"
        assert hashlib.sha1(files[pristine_key]).hexdigest() == sha1


def test_entries_lists_the_same_files_as_wc_db(wc):
    """The two layouts describe one working copy; a client that reads
    either must be told about the same tracked files."""
    files, _meta = wc
    entries = files["/.svn/entries"].decode()
    for name in (".env", "README.md", "deploy.sh", "config"):
        assert name in entries


def test_text_base_matches_pristine_for_root_level_files(wc):
    """`text-base` (pre-1.7) and `pristine` (1.7+) are two spellings of the
    same pristine copy — the bytes must agree or a client that fetches
    both sees an inconsistent working copy."""
    files, _meta = wc
    env_body = files["/.svn/text-base/.env.svn-base"]
    sha1 = hashlib.sha1(env_body).hexdigest()
    assert files[f"/.svn/pristine/{sha1[:2]}/{sha1}.svn-base"] == env_body


def test_directory_probes_get_an_autoindex(wc):
    """A 404 on a bare directory reads as 'not really exposed' and ends
    the walk. Every listing links only to keys the trap answers."""
    files, meta = wc
    for directory in ("/.svn/", "/.svn/text-base/", "/.svn/pristine/",
                      "/.svn/auth/", "/.svn/auth/svn.simple/"):
        assert directory in files, directory
        assert b"Index of" in files[directory]
    # The auth listing hands over the one filename a client cannot guess.
    assert meta["svnRealmHash"].encode() in files["/.svn/auth/svn.simple/"]


# --- canary placement -------------------------------------------------

def test_repo_url_carries_the_canary_as_basic_userinfo(wc):
    """A client that reads only the metadata file still leaves with a live
    credential — the same reasoning as the fake-git remote-origin URL."""
    files, _meta = wc
    entries = files["/.svn/entries"].decode()
    assert "AKIAFAKEEXAMPLE01:" in entries
    # The secret is percent-encoded: it contains '/' which would otherwise
    # terminate the userinfo component.
    assert "wJalrXUtnFEMI%2FK7MDENG%2FbPxRfiCYEXAMPLEKEY" in entries


def test_auth_cache_is_svn_hash_dump_format_with_the_canary(wc):
    """`.svn/auth/svn.simple/<md5>` is Subversion's own saved-credential
    store, which is why harvesters ask for it directly. The serialization
    has to be the real one, byte lengths included."""
    files, meta = wc
    body = files[f"/.svn/auth/svn.simple/{meta['svnRealmHash']}"].decode()
    assert "K 15\nsvn:realmstring\n" in body
    assert "deploybot42" in body
    assert "p@ssCanaryValue" in body
    assert body.endswith("END\n")
    # Declared byte lengths must match the values that follow them.
    lines = body.split("\n")
    for index, line in enumerate(lines):
        if line.startswith(("K ", "V ")):
            assert len(lines[index + 1].encode()) == int(line[2:]), line


def test_pristine_env_holds_the_canary(wc):
    files, _meta = wc
    env_body = files["/.svn/text-base/.env.svn-base"].decode()
    assert "AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01\n" in env_body
    assert "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" in env_body


def test_no_fixed_credential_literals_across_builds():
    """Every secret-shaped field is per-hit: either a Tracebit canary or a
    per-hit synthetic. A fixed literal gives zero detection on replay and
    fingerprints every deployment with one shared string."""
    first, _m1 = tbenv._build_fake_svn_wc(FAKE_TRACEBIT)
    second, _m2 = tbenv._build_fake_svn_wc(FAKE_TRACEBIT)
    key = "/.svn/pristine/"
    first_db = [v for k, v in first.items() if k.startswith(key)]
    second_db = [v for k, v in second.items() if k.startswith(key)]
    # The database password is the only non-canary secret in the tree, and
    # it must differ between builds.
    first_yaml = next(b for b in first_db if b.startswith(b"production:\n  adapter"))
    second_yaml = next(b for b in second_db if b.startswith(b"production:\n  adapter"))
    assert first_yaml != second_yaml, "database password is a fixed literal"


def test_mint_failure_leaves_no_secret_material_in_the_repo_url():
    """When the canary mint fails the URL must degrade to a bare host
    rather than emit a malformed or half-populated credential."""
    files, meta = tbenv._build_fake_svn_wc({})

    # Assert on every URL the working copy records, not on a fixed line
    # index — the record layout has empty fields either side of it, so a
    # positional check silently lands on the wrong line and passes for
    # the wrong reason.
    url_lines = [
        line for line in files["/.svn/entries"].decode().splitlines()
        if line.startswith("https://")
    ]
    assert url_lines, "entries records no repository URL at all"
    for line in url_lines:
        assert "@" not in line, f"userinfo survived a failed mint: {line}"

    with tempfile.NamedTemporaryFile(suffix=".db") as handle:
        handle.write(files["/.svn/wc.db"])
        handle.flush()
        connection = sqlite3.connect(handle.name)
        try:
            (root,) = connection.execute("SELECT root FROM REPOSITORY").fetchone()
        finally:
            connection.close()
    assert "@" not in root, root

    assert meta["svnAuthCached"] is False
    assert not any(k.startswith("/.svn/auth/svn.simple/") and len(k) > len("/.svn/auth/svn.simple/")
                   for k in files), "no auth cache without credentials to put in it"


def test_repo_url_line_is_where_the_userinfo_lands_on_success():
    """Counterpart to the mint-failure case above: on the happy path the
    same URL lines are the ones that must carry the credential."""
    files, _meta = tbenv._build_fake_svn_wc(FAKE_TRACEBIT)
    url_lines = [
        line for line in files["/.svn/entries"].decode().splitlines()
        if line.startswith("https://")
    ]
    assert any("AKIAFAKEEXAMPLE01:" in line for line in url_lines), url_lines


# --- dispatch ---------------------------------------------------------

async def test_dispatch_serves_the_working_copy(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)

    resp = await flux_client.get("/.svn/entries", headers={"X-Forwarded-For": "203.0.113.21"})
    assert resp.status == 200
    body = await resp.read()
    assert b"AKIAFAKEEXAMPLE01" in body

    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "fake-svn"
    assert entries[-1]["svnKey"] == "/.svn/entries"
    assert entries[-1]["svnAuthCached"] is True


async def test_dispatch_serves_wc_db_with_a_sqlite_content_type(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)

    resp = await flux_client.get("/.svn/wc.db", headers={"X-Forwarded-For": "203.0.113.22"})
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/x-sqlite3"
    assert (await resp.read()).startswith(b"SQLite format 3\x00")


async def test_unknown_child_is_a_logged_miss_not_a_bare_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)

    resp = await flux_client.get(
        "/.svn/no-such-file", headers={"X-Forwarded-For": "203.0.113.23"},
    )
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "fake-svn-miss"
    assert entries[-1]["svnKey"] == "/.svn/no-such-file"


async def test_one_source_sees_one_consistent_working_copy(flux_client, monkeypatch):
    """A dictionary sweep costs one issuance and must not hand the client
    a tree whose checksums stop matching halfway through the walk."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_SVN_CACHE.clear()

    first = await (await flux_client.get(
        "/.svn/entries", headers={"X-Forwarded-For": "203.0.113.24"})).read()
    second = await (await flux_client.get(
        "/login/.svn/entries", headers={"X-Forwarded-For": "203.0.113.24"})).read()
    assert first == second


async def test_disabled_switch_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", False)

    resp = await flux_client.get("/.svn/entries", headers={"X-Forwarded-For": "203.0.113.25"})
    assert resp.status == 404
    entries = _log_entries(flux_client.log_path)
    assert entries[-1]["result"] == "not-handled"


async def test_keyless_deployment_serves_nothing(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "FAKE_SVN_ENABLED", True)

    resp = await flux_client.get("/.svn/wc.db", headers={"X-Forwarded-For": "203.0.113.26"})
    assert resp.status == 404
