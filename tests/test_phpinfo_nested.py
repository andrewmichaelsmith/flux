"""phpinfo() resolved under an arbitrary parent directory.

The layout walk (`tests/test_trap_path_walk.py`) gates on a *parent*
vocabulary. This surface gates on the *leaf* instead, because a phpinfo
page belongs to no framework layout — it is dropped by hand wherever the
operator happened to be. These tests pin both halves of that trade: the
leaf list is permissive about parents, and tight about which leaves are
eligible at all.
"""
from __future__ import annotations

import pytest

from flux import server as tbenv


def _resolve(path: str):
    return tbenv.resolve_canary_trap(path)


# Parents drawn from observed sweeps — none of them are in the layout
# vocabulary, which is the whole reason this resolver exists.
@pytest.mark.parametrize("path", [
    "/wp-admin/phpinfo.php",
    "/cpanel/phpinfo.php",
    "/cgi-bin/phpinfo.php",
    "/plesk/phpinfo.php",
    "/phpinfo/phpinfo.php",
    "/dashboard/phpinfo.php",
    "/administrator/phpinfo.php",
    "/qa/phpinfo.php",
    "/portal/phpinfo.php",
    "/includes/phpinfo.php",
    "/cron/info.php",
    "/site/phpinfo.php",
])
def test_single_unknown_parent_resolves(path):
    trap, depth = _resolve(path)
    assert trap is not None, f"{path} should reach the phpinfo trap"
    assert trap.name == "phpinfo"
    assert depth == 1


@pytest.mark.parametrize("path,depth", [
    ("/crm/backend/phpinfo.php", 2),
    ("/prod/api/info.php", 2),
    ("/admin/dashboard/info.php", 2),
    ("/mailer/dev/info.php", 2),
    ("/a/b/c/phpinfo.php", 3),
    ("/a/b/c/d/phpinfo.php", 4),
])
def test_multi_segment_nesting_resolves_within_cap(path, depth):
    trap, got = _resolve(path)
    assert trap is not None and trap.name == "phpinfo"
    assert got == depth


def test_depth_cap_is_enforced():
    """One past PHPINFO_NESTED_MAX_DEPTH stops resolving."""
    assert tbenv.PHPINFO_NESTED_MAX_DEPTH == 4
    trap, _ = _resolve("/a/b/c/d/e/phpinfo.php")
    assert trap is None


@pytest.mark.parametrize("leaf", sorted(tbenv._PHPINFO_NESTED_LEAVES))
def test_every_eligible_leaf_has_a_root_table_entry(leaf):
    """The resolver looks the leaf up in the trap table rather than
    hardcoding a target, so a leaf with no entry would silently resolve
    to None and quietly do nothing."""
    assert tbenv.find_canary_trap("/" + leaf) is not None, (
        f"{leaf} is eligible for nesting but has no root-level trap entry"
    )


@pytest.mark.parametrize("leaf", sorted(tbenv._PHPINFO_NESTED_LEAVES))
def test_every_eligible_leaf_resolves_under_a_parent(leaf):
    trap, depth = _resolve("/somewhere/" + leaf)
    assert trap is not None and depth == 1


# The generic stems the root-level phpinfo trap also answers. Nesting
# these would collide with webshell-drop dictionaries and turn the
# resolver into an answer-everything switch.
@pytest.mark.parametrize("path", [
    "/wp-admin/test.php",
    "/wp-admin/x.php",
    "/wp-admin/1.php",
    "/wp-admin/i.php",
    "/wp-admin/pi.php",
    "/wp-admin/temp.php",
    "/wp-admin/time.php",
    "/wp-admin/asdf.php",
    "/wp-admin/php.php",
])
def test_generic_stems_do_not_nest(path):
    trap, _ = _resolve(path)
    assert trap is None, f"{path} must not resolve — generic stem"


@pytest.mark.parametrize("path", [
    "/wp-admin/shell.php",
    "/wp-admin/config.php",
    "/randomdir/aws.json",
    "/nothing/here.txt",
])
def test_unrelated_leaves_still_404(path):
    trap, _ = _resolve(path)
    assert trap is None


def test_bare_leaf_keeps_exact_match_and_zero_depth():
    trap, depth = _resolve("/phpinfo.php")
    assert trap is not None and trap.name == "phpinfo"
    assert depth == 0, "root-level probe must resolve exactly, not via the walk"


def test_exact_entry_wins_over_nesting():
    """`/_profiler/phpinfo.php` has its own Symfony renderer; the leaf
    resolver must not steal it."""
    trap, depth = _resolve("/_profiler/phpinfo.php")
    assert trap is not None
    assert trap.name == "symfony-profiler-phpinfo"
    assert depth == 0


def test_case_insensitive_leaf():
    trap, depth = _resolve("/WP-Admin/PhpInfo.PHP")
    assert trap is not None and trap.name == "phpinfo" and depth == 1


def test_disabled_switch_turns_nesting_off(monkeypatch):
    monkeypatch.setattr(tbenv, "PHPINFO_NESTED_ENABLED", False)
    trap, _ = _resolve("/wp-admin/phpinfo.php")
    assert trap is None
    # …but the root-level entry is untouched.
    trap, depth = _resolve("/phpinfo.php")
    assert trap is not None and depth == 0


def test_canary_traps_disabled_turns_nesting_off(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    trap, _ = _resolve("/wp-admin/phpinfo.php")
    assert trap is None


def test_survives_layout_walk_disabled(monkeypatch):
    """The two walks are independent surfaces with independent switches."""
    monkeypatch.setattr(tbenv, "TRAP_PATH_WALK_ENABLED", False)
    trap, depth = _resolve("/wp-admin/phpinfo.php")
    assert trap is not None and trap.name == "phpinfo" and depth == 1
    # The layout walk really is off.
    assert _resolve("/admin/aws.json")[0] is None


def test_layout_walk_still_wins_when_both_could_match(monkeypatch):
    """`/app/phpinfo.php` is reachable by both walks. The layout walk runs
    first, so depth comes from it — this pins that the fall-through added
    for the leaf resolver did not reorder the two."""
    trap, depth = _resolve("/app/phpinfo.php")
    assert trap is not None and trap.name == "phpinfo"
    assert depth == 1


def test_unknown_parent_credential_leaf_unchanged():
    """Regression: the leaf resolver must not have widened the layout
    walk. A credential leaf under an unrecognised parent still 404s."""
    for path in ("/9f2a1c/aws.json", "/randomword/.env", "/xyz/config.json"):
        assert _resolve(path)[0] is None
