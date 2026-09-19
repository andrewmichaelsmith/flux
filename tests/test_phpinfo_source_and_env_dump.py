"""Backup-suffix source disclosure, the `_environment` dump, and two
bare-filename service-account spellings.

All three surfaces answer paths that a credential sweep already walks and
that flux answered with a 404. The backup family is the interesting one:
the shell-jacking sweep gate cannot reach it, because that matcher
requires the name to end in `.php` and every suffix here takes it past
that — so no amount of sweep width opens it, only an entry does.
"""
from __future__ import annotations

import pytest

from flux import server as tbenv


def _resolve(path: str):
    return tbenv.resolve_canary_trap(path)


# --- backup-suffix source disclosure ------------------------------------

@pytest.mark.parametrize("path", [
    "/phpinfo.php.bak",
    "/phpinfo.php.old",
    "/phpinfo.php.save",
    "/phpinfo.php~",
    "/phpinfo.php.orig",
    "/phpinfo.php.swp",
    "/phpinfo.php.bak~",
    "/info.php.bak",
    "/info.php.old",
    "/info.php~",
    "/php.php.bak",
    "/test.php.bak",
])
def test_backup_suffix_resolves_to_source_trap(path):
    trap, _depth = _resolve(path)
    assert trap is not None, f"{path} should reach the source trap"
    assert trap.name == "phpinfo-source"


@pytest.mark.parametrize("path", [
    # The executed spellings keep the rendered page — a live `.php` is run
    # by the interpreter, so source would be the wrong disclosure.
    "/phpinfo.php",
    "/info.php",
    "/php.php",
    "/test.php",
])
def test_live_spellings_still_render_the_page(path):
    trap, _depth = _resolve(path)
    assert trap is not None
    assert trap.name == "phpinfo", f"{path} must not be diverted to source"


@pytest.mark.parametrize("path", [
    "/notphpinfo.php.bak",
    "/phpinfo.php.bak.php",
    "/phpinfo.txt.bak",
    "/random.php.bak",
])
def test_unrelated_backup_names_do_not_match(path):
    trap, _depth = _resolve(path)
    assert trap is None or trap.name != "phpinfo-source"


def test_source_body_is_php_source_not_rendered_html():
    body = tbenv.render_phpinfo_source({"aws": {
        "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
        "awsSecretAccessKey": "secret",
        "awsSessionToken": "token",
    }})
    assert body.startswith(b"<?php"), "a non-executed backup must return source"
    assert b"<html" not in body.lower()
    assert b"phpinfo()" in body
    assert b"AKIAFAKEEXAMPLE01" in body


def test_source_body_has_no_fixed_credential_literal():
    """Every secret-shaped field must vary per hit."""
    r = {"aws": {"awsAccessKeyId": "AKIAFAKEEXAMPLE01",
                 "awsSecretAccessKey": "s", "awsSessionToken": "t"}}
    first = tbenv.render_phpinfo_source(r)
    second = tbenv.render_phpinfo_source(r)
    assert first != second, "the DB password must be regenerated per hit"


# --- `_environment` dump -------------------------------------------------

@pytest.mark.parametrize("path", [
    "/_environment",
    "/webroot/index.php/_environment",
    "/index.php/_environment",
    "/app.php/_environment",
    "/public/index.php/_environment",
])
def test_environment_dump_resolves(path):
    trap, _depth = _resolve(path)
    assert trap is not None, f"{path} should reach the environment trap"
    assert trap.name == "environment-dump"


def test_environment_dump_body_is_key_value_with_canary():
    body = tbenv.render_environment_dump({"aws": {
        "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
        "awsSecretAccessKey": "secret",
        "awsSessionToken": "token",
    }})
    assert b"AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE01" in body
    assert b"DB_PASSWORD=" in body
    # Grep-shaped, not markup — that is what the client is scanning for.
    assert b"<" not in body


def test_environment_dump_password_varies_per_hit():
    r = {"aws": {"awsAccessKeyId": "AKIAFAKEEXAMPLE01",
                 "awsSecretAccessKey": "s", "awsSessionToken": "t"}}
    assert tbenv.render_environment_dump(r) != tbenv.render_environment_dump(r)


# --- service-account bare-filename gap fill ------------------------------

@pytest.mark.parametrize("path", ["/keyfile.json", "/gcp-sa.json"])
def test_service_account_spellings_join_the_existing_family(path):
    trap, _depth = _resolve(path)
    assert trap is not None, f"{path} should reach the service-account trap"
    # Same trap the sibling spellings in that tuple already resolve to.
    sibling, _ = _resolve("/key.json")
    assert sibling is not None
    assert trap.name == sibling.name
