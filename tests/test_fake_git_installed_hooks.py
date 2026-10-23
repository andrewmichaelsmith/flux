"""Installed hooks, the worktree-scoped config, and the submodule map.

Three parts of a git checkout that a dumping dictionary asks for and the
tree was answering 404, each for a different reason.

**Installed hooks.** A stock `git init` leaves every hook as a `.sample`,
so the non-suffixed names are the second half of the same dictionary —
and 404 is the *correct* answer for a stock repo, which is why this was
never simply a missed route. The repository worth presenting is the one
with hooks installed, because an installed hook is a script the
deployment runs, and a deploy script carries credentials attached to the
release pipeline rather than to the application. Only a plausible subset
is installed: a repo with all nineteen hooks active does not exist, and
fabricating it would be the tell this avoids.

The listing is the measurement. `hooks/` names exactly the `.sample`
stubs plus the installed subset, so a client that read the autoindex asks
for the three that resolve, while a client replaying a dictionary asks
for all nineteen and takes sixteen 404s. `fakeGitInstalledHook` in the
log makes that split a column rather than a path regex.

**`config.worktree`.** Served as a genuinely different file from
`config`, not a byte-copy of it the way the `config.bak` / `config.old`
editor-leftover aliases correctly are. It holds what real worktree config
holds — `core.worktree` and a per-worktree remote — and `config` declares
the `extensions.worktreeConfig` flag that makes git read it at all.
Without that flag the file would sit on disk and be ignored by every git
command, which is the incoherence a careful reader spots. The upstream
remote carries a *different* canary type than origin, so which canary
comes back on replay says which of the two files was parsed.

**`.gitmodules`.** The one worktree dotfile that names other
repositories, as URLs — so it is both a credential placement and the only
part of the git surface offering a next target rather than another file
of the same repo.
"""

import json

import pytest

import flux.server as tbenv

from .test_server import (  # noqa: F401
    FAKE_TRACEBIT,
    _fake_canary,
    _log_entries,
    flux_client,
)


@pytest.fixture
def repo():
    files, _meta = tbenv._build_fake_repo("db_password: hunter2\n", FAKE_TRACEBIT)
    return files


AWS_KEY = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
AWS_SECRET = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]
GL = FAKE_TRACEBIT["http"]["gitlab-username-password"]["credentials"]


# --- premise guards ----------------------------------------------------
# Each loop below derives its cases from a module constant. An empty
# constant would make every parametrised assertion pass vacuously, so
# assert non-emptiness before relying on it.

def test_installed_hook_set_is_non_empty_and_a_strict_subset():
    assert tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES, "installed-hook set must not be empty"
    installed = set(tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)
    allnames = set(tbenv._FAKE_GIT_HOOK_NAMES)
    assert installed < allnames, (
        "installed hooks must be a strict subset of the hook vocabulary — "
        "a repo with every hook active is the shape no real repo has"
    )
    assert len(allnames - installed) >= 10, (
        "most hook names must stay uninstalled, or the 404s stop being "
        "evidence that only some hooks are real"
    )


def test_uninstalled_hook_names_are_non_empty(repo):
    assert set(tbenv._FAKE_GIT_HOOK_NAMES) - set(tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)


# --- installed hooks resolve, uninstalled ones do not ------------------

@pytest.mark.parametrize("name", tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)
def test_installed_hook_resolves(repo, name):
    body = repo.get(f"/.git/hooks/{name}")
    assert body is not None, f"installed hook {name} must be served"
    assert body.startswith(b"#!/bin/sh\n"), "a hook git runs must be a script"


@pytest.mark.parametrize(
    "name",
    sorted(set(tbenv._FAKE_GIT_HOOK_NAMES) - set(tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)),
)
def test_uninstalled_hook_name_is_absent(repo, name):
    """404 here is the correct answer, not a gap: the `.sample` exists and
    the enabled hook does not, which is what a stock repo looks like."""
    assert f"/.git/hooks/{name}" not in repo


@pytest.mark.parametrize("name", tbenv._FAKE_GIT_HOOK_NAMES)
def test_sample_hook_still_resolves(repo, name):
    assert repo.get(f"/.git/hooks/{name}.sample") is not None


# --- the listing and the tree agree -----------------------------------

def test_hooks_autoindex_lists_every_installed_hook(repo):
    listing = repo["/.git/hooks/"].decode("utf-8")
    for name in tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES:
        assert f'href="{name}"' in listing, f"{name} is served but not listed"


def test_hooks_autoindex_does_not_list_uninstalled_names(repo):
    """The whole value of the listing is that it is honest: a client that
    trusts it must not be sent to a 404."""
    listing = repo["/.git/hooks/"].decode("utf-8")
    uninstalled = set(tbenv._FAKE_GIT_HOOK_NAMES) - set(tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)
    for name in sorted(uninstalled):
        assert f'href="{name}"' not in listing, f"{name} listed but 404s"


def test_every_hooks_listing_entry_resolves(repo):
    """Derived from the served listing rather than rebuilt from the
    constants, so this catches a listing that names something the tree
    does not hold."""
    import re
    listing = repo["/.git/hooks/"].decode("utf-8")
    entries = [
        e for e in re.findall(r'href="([^"?]+)"', listing)
        if e not in ("../",)
    ]
    assert len(entries) >= len(tbenv._FAKE_GIT_HOOK_NAMES), "listing looks truncated"
    for entry in entries:
        assert repo.get(f"/.git/hooks/{entry}") is not None, f"{entry} listed but missing"


# --- what the hook bodies carry ---------------------------------------

def test_post_receive_carries_the_aws_canary(repo):
    body = repo["/.git/hooks/post-receive"].decode("utf-8")
    assert f"export AWS_ACCESS_KEY_ID={AWS_KEY}" in body
    assert f"export AWS_SECRET_ACCESS_KEY={AWS_SECRET}" in body
    assert "aws s3 sync" in body, "the credential needs a reason to be here"


def test_post_receive_is_consistent_with_a_non_bare_repo(repo):
    """`config` says `bare = false`, so the deploy hook has to be the
    `GIT_WORK_TREE` checkout idiom rather than a bare-repo one."""
    body = repo["/.git/hooks/post-receive"].decode("utf-8")
    assert "GIT_WORK_TREE=" in body
    assert tbenv.FAKE_GIT_DEPLOY_WORK_TREE in body


@pytest.mark.parametrize("name", ("pre-commit", "pre-push"))
def test_gate_hooks_carry_no_credential(repo, name):
    """One secret among three files reads as a real repository. These two
    name a next step instead."""
    body = repo[f"/.git/hooks/{name}"].decode("utf-8")
    assert AWS_KEY not in body
    assert AWS_SECRET not in body
    assert GL["password"] not in body


def test_hook_bodies_are_not_all_identical(repo):
    bodies = {repo[f"/.git/hooks/{n}"] for n in tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES}
    assert len(bodies) == len(tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)


def test_post_receive_without_a_canary_emits_no_empty_export():
    """A mint failure must fall back to a credential-free body, not a
    file with `export AWS_ACCESS_KEY_ID=` and nothing after it — that
    reads as a stripped file, which is worse than a plain deploy script."""
    body = tbenv._fake_git_installed_hook_body("post-receive", {}).decode("utf-8")
    assert "AWS_ACCESS_KEY_ID" not in body
    assert "export " not in body or "=\n" not in body
    assert body.startswith("#!/bin/sh\n")


def test_installed_hook_body_differs_from_the_sample_stub():
    for name in tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES:
        installed = tbenv._fake_git_installed_hook_body(name, FAKE_TRACEBIT)
        sample = tbenv._fake_git_hook_body(name)
        assert installed != sample
        assert b"removing the `.sample` suffix" not in installed


# --- config.worktree ---------------------------------------------------

def test_config_declares_the_worktree_config_extension(repo):
    config = repo["/.git/config"].decode("utf-8")
    assert "[extensions]" in config
    assert "worktreeConfig = true" in config


def test_config_worktree_is_served(repo):
    assert repo.get("/.git/config.worktree") is not None


def test_config_worktree_is_not_a_copy_of_config(repo):
    """The `.bak` / `.old` aliases are byte-copies, correctly — they are
    editor leftovers of the same file. `config.worktree` is a different
    file and has to read like one."""
    assert repo["/.git/config.worktree"] != repo["/.git/config"]
    assert repo["/.git/config.bak"] == repo["/.git/config"]


def test_config_worktree_holds_worktree_scoped_settings(repo):
    body = repo["/.git/config.worktree"].decode("utf-8")
    assert "worktree = " in body
    assert tbenv.FAKE_GIT_DEPLOY_WORK_TREE in body
    assert '[remote "upstream"]' in body


def test_upstream_url_carries_a_different_canary_type_than_origin(repo):
    """Two files, two canary types: a replay is attributable to the file
    it came from. One shared canary would make that impossible."""
    config = repo["/.git/config"].decode("utf-8")
    worktree = repo["/.git/config.worktree"].decode("utf-8")
    assert AWS_KEY in config, "origin keeps the AWS pair"
    assert GL["username"] in worktree, "upstream carries the GitLab pair"
    assert AWS_KEY not in worktree
    assert GL["password"] not in config


def test_upstream_url_percent_encodes_the_canary_password(repo):
    """`p@ssCanaryValue` has an `@` in it; left raw it would split the
    userinfo and the host, and every tool parsing the URL would read a
    different host than we meant."""
    body = repo["/.git/config.worktree"].decode("utf-8")
    assert "p%40ssCanaryValue" in body
    assert "p@ssCanaryValue@" not in body


def test_upstream_url_without_a_canary_falls_back_to_ssh():
    url = tbenv._build_fake_git_upstream_url({})
    assert url.startswith("git@")
    assert "://" not in url
    assert ":@" not in url


def test_config_worktree_in_the_root_listing(repo):
    listing = repo["/.git/"].decode("utf-8")
    assert 'href="config.worktree"' in listing


# --- the upstream remote's refs exist ---------------------------------

def test_upstream_refs_resolve(repo):
    head = repo.get("/.git/refs/remotes/upstream/head")
    assert head is not None
    assert head.startswith(b"ref: refs/remotes/upstream/")
    assert repo.get("/.git/refs/remotes/upstream/main") is not None
    assert repo.get("/.git/logs/refs/remotes/upstream/main") is not None


def test_remotes_listing_names_upstream(repo):
    listing = repo["/.git/refs/remotes/"].decode("utf-8")
    assert 'href="upstream/"' in listing
    assert 'href="origin/"' in listing


def test_every_upstream_listing_entry_resolves(repo):
    import re
    listing = repo["/.git/refs/remotes/upstream/"].decode("utf-8")
    entries = [e for e in re.findall(r'href="([^"?]+)"', listing) if e != "../"]
    assert entries, "upstream listing must not be empty"
    for entry in entries:
        assert repo.get(f"/.git/refs/remotes/upstream/{entry.lower()}") is not None


def test_declaring_a_remote_implies_its_refs(repo):
    """Guards the pairing rather than either half: if the worktree config
    ever names a third remote, its refs have to come with it."""
    import re
    body = repo["/.git/config.worktree"].decode("utf-8")
    for name in re.findall(r'\[remote "([^"]+)"\]', body):
        assert repo.get(f"/.git/refs/remotes/{name}/main") is not None, (
            f"remote {name} is declared but has no refs"
        )


def test_trunk_branch_ref_resolves(repo):
    assert repo.get("/.git/refs/heads/trunk") is not None
    assert 'href="trunk"' in repo["/.git/refs/heads/"].decode("utf-8")


# --- the sentinel and the uninstalled names stay refused --------------

def test_null_object_still_refused(repo):
    assert "/.git/objects/00/00000000000000000000000000000000000000" not in repo


def test_shallow_still_refused(repo):
    """A `shallow` file exists only in a shallow clone; this tree
    advertises full reflogs, so absence is the coherent answer."""
    assert "/.git/shallow" not in repo


# --- .gitmodules -------------------------------------------------------

def test_gitmodules_resolves_to_its_own_trap():
    trap = tbenv.find_canary_trap("/.gitmodules")
    assert trap is not None
    assert trap.name == "gitmodules"
    assert trap.canary_types == ("gitlab-username-password",)


def test_gitmodules_private_submodule_carries_the_canary():
    body = tbenv.render_gitmodules(FAKE_TRACEBIT).decode("utf-8")
    assert GL["username"] in body
    assert "p%40ssCanaryValue" in body


def test_gitmodules_public_submodule_has_no_inline_credential():
    """A `.gitmodules` where every URL has userinfo is not a shape that
    occurs; the contrast is what makes the private one worth following."""
    body = tbenv.render_gitmodules(FAKE_TRACEBIT).decode("utf-8")
    public = [ln for ln in body.splitlines() if "github.com" in ln]
    assert public, "expected a public submodule for contrast"
    for line in public:
        assert "@github.com" not in line


def test_gitmodules_names_a_second_repository():
    body = tbenv.render_gitmodules(FAKE_TRACEBIT).decode("utf-8")
    assert body.count("[submodule ") >= 2
    assert "path = " in body


def test_gitmodules_without_a_canary_emits_no_half_credential():
    body = tbenv.render_gitmodules({}).decode("utf-8")
    assert ":@" not in body
    assert "https://@" not in body
    assert "[submodule " in body


# --- .gitattributes ----------------------------------------------------

@pytest.mark.parametrize(
    "path",
    ("/.gitattributes", "/root/.gitattributes", "/api/.gitattributes",
     "/wp-content/.gitattributes"),
)
def test_gitattributes_matches_like_gitignore(path):
    assert tbenv.is_git_dotfile_path(path) is True


def test_gitattributes_carries_no_credential():
    body = tbenv.render_gitattributes().decode("utf-8")
    assert "AKIA" not in body
    assert "password" not in body.lower()
    assert body.startswith("* text=auto")


def test_gitattributes_gate_follows_the_dotfile_switch(monkeypatch):
    monkeypatch.setattr(tbenv, "GIT_DOTFILES_ENABLED", False)
    assert tbenv.is_git_dotfile_path("/.gitattributes") is False


# --- /awsconfig.json ---------------------------------------------------

@pytest.mark.parametrize(
    "path",
    ("/awsconfig.json", "/AwsConfig.json", "/AWSConfig.json",
     "/aws-config.json", "/aws_config.json", "/config/aws_config.json"),
)
def test_aws_config_json_spellings_resolve(path):
    trap = tbenv.find_canary_trap(path)
    assert trap is not None, f"{path} must be answered"
    assert trap.name == "aws-config-json"


def test_aws_config_json_is_the_flat_shape_not_the_amplify_one():
    """A collector greping for `accessKeyId` gets nothing useful out of
    the Amplify artifact, so answering this path with that shape would
    waste the answer."""
    body = json.loads(tbenv.render_aws_config_json(FAKE_TRACEBIT))
    assert body["accessKeyId"] == AWS_KEY
    assert body["secretAccessKey"] == AWS_SECRET
    assert "CredentialsProvider" not in body
    assert "aws_project_region" not in body


def test_aws_config_json_differs_from_the_amplify_trap():
    assert (
        tbenv.find_canary_trap("/awsconfig.json").name
        != tbenv.find_canary_trap("/awsconfiguration.json").name
    )


def test_aws_config_json_is_parseable_and_has_no_empty_credential():
    body = json.loads(tbenv.render_aws_config_json(FAKE_TRACEBIT))
    assert body["region"]
    assert body["s3"]["bucket"]
    assert body["accessKeyId"] and body["secretAccessKey"]


def test_aws_config_json_gate_follows_canary_traps(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    assert tbenv.find_canary_trap("/awsconfig.json") is None
    assert tbenv.find_canary_trap("/.gitmodules") is None


# --- served over HTTP, not just present in the tree -------------------
# The tree assertions above would all pass on a dict that dispatch never
# reaches. These exercise the real request path, which is also the only
# place the log field can be checked.


def _arm(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "FAKE_GIT_ENABLED", True)
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    tbenv._FAKE_GIT_CACHE.clear()


@pytest.mark.parametrize("name", tbenv._FAKE_GIT_INSTALLED_HOOK_NAMES)
async def test_installed_hook_served_over_http(flux_client, monkeypatch, name):
    _arm(monkeypatch)
    resp = await flux_client.get(
        f"/.git/hooks/{name}", headers={"X-Forwarded-For": "203.0.113.41"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert body.startswith("#!/bin/sh\n")
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] in ("fake-git", "fake-git-undripped")
    assert entry["fakeGitInstalledHook"] == name, (
        "the log field is what makes the listing-reader / dictionary-replayer "
        "split a column rather than a path regex"
    )


async def test_sample_hook_is_not_tagged_as_installed(flux_client, monkeypatch):
    _arm(monkeypatch)
    resp = await flux_client.get(
        "/.git/hooks/pre-commit.sample", headers={"X-Forwarded-For": "203.0.113.42"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["fakeGitInstalledHook"] == ""


async def test_uninstalled_hook_404s_over_http(flux_client, monkeypatch):
    _arm(monkeypatch)
    resp = await flux_client.get(
        "/.git/hooks/post-commit", headers={"X-Forwarded-For": "203.0.113.43"},
    )
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "fake-git-miss"


async def test_config_worktree_served_over_http_under_a_prefix(flux_client, monkeypatch):
    """The observed sweep walks `<prefix>/.git/config.worktree` across the
    whole app-layout dictionary, so the prefixed spelling is the one that
    has to resolve."""
    _arm(monkeypatch)
    resp = await flux_client.get(
        "/public_html/.git/config.worktree",
        headers={"X-Forwarded-For": "203.0.113.44"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert '[remote "upstream"]' in body
    assert "worktree = " in body


async def test_gitmodules_served_over_http(flux_client, monkeypatch):
    _arm(monkeypatch)
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    resp = await flux_client.get(
        "/.gitmodules", headers={"X-Forwarded-For": "203.0.113.45"},
    )
    assert resp.status == 200
    body = await resp.text()
    assert "[submodule " in body


async def test_aws_config_json_served_over_http_camel_spelling(flux_client, monkeypatch):
    """`AwsConfig.json` is the second-highest spelling on its own and it
    only resolves because lookup lowercases."""
    _arm(monkeypatch)
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    resp = await flux_client.get(
        "/AwsConfig.json", headers={"X-Forwarded-For": "203.0.113.46"},
    )
    assert resp.status == 200
    body = json.loads(await resp.text())
    assert "accessKeyId" in body


async def test_gitattributes_served_over_http(flux_client, monkeypatch):
    _arm(monkeypatch)
    monkeypatch.setattr(tbenv, "GIT_DOTFILES_ENABLED", True)
    resp = await flux_client.get(
        "/.gitattributes", headers={"X-Forwarded-For": "203.0.113.47"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "gitattributes"


# --- encoding: the two placements need opposite treatment -------------

def test_shell_export_carries_the_secret_verbatim_not_percent_encoded():
    """A URL placement must percent-encode the secret or the userinfo
    splits; a shell `export` must NOT, or the credential a harvester
    copies out is corrupt. Same canary, opposite requirement — getting
    it backwards is silent, so pin both directions.

    Exercised with a secret containing the characters a real AWS secret
    actually contains (`/`, `+`, `=`), which is where a placeholder
    passes and a genuine specimen fails.
    """
    realistic = {
        "aws": {
            "awsAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY+aa=",
        },
    }
    body = tbenv._fake_git_installed_hook_body("post-receive", realistic).decode("utf-8")
    secret = realistic["aws"]["awsSecretAccessKey"]
    assert f"export AWS_SECRET_ACCESS_KEY={secret}\n" in body, (
        "shell export must hold the secret byte-for-byte"
    )
    assert "%2F" not in body and "%2B" not in body


def test_url_placements_do_percent_encode(repo):
    """The other half of the same invariant."""
    worktree = repo["/.git/config.worktree"].decode("utf-8")
    modules = tbenv.render_gitmodules(FAKE_TRACEBIT).decode("utf-8")
    for body in (worktree, modules):
        assert "p%40ssCanaryValue" in body
        assert "p@ssCanaryValue" not in body


def test_aws_config_json_carries_the_secret_verbatim():
    """JSON escapes nothing in `/` or `+`, so the value must round-trip
    through json.loads unchanged."""
    realistic = {
        "aws": {
            "awsAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY+aa=",
        },
    }
    body = json.loads(tbenv.render_aws_config_json(realistic))
    assert body["secretAccessKey"] == realistic["aws"]["awsSecretAccessKey"]
