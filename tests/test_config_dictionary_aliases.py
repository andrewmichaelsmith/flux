"""Config-dictionary spellings that answered 404 while their siblings paid.

These all arrive inside one config-harvesting sweep that walks a fixed
credential-file dictionary and forges a `Googlebot/2.1` User-Agent from
hosting-provider address space. The sweep already collects canaries from
most of this table, so each 404 here was splitting one dictionary across
two outcomes -- `/staging.env` issued a canary while `/production.env`
did not, `/wp-config.bak` paid while `/wp-config.save` did not,
`/settings.py` paid while `/settings/local.py` did not.

Every addition is an alias onto a renderer that already exists; no new
response shape is invented. The tests pin three things: the new leaves
route, the layout walk reaches the nested spellings the sweep actually
sends, and the vocabulary gate still refuses a junk parent.
"""
import pytest

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


# --- new leaf registrations ---------------------------------------------

@pytest.mark.parametrize("path,trap_name", [
    # Split-settings package + secrets module (Django/Flask).
    ("/local.py", "app-config-python"),
    ("/base.py", "app-config-python"),
    ("/dev.py", "app-config-python"),
    ("/production.py", "app-config-python"),
    ("/prod_settings.py", "app-config-python"),
    ("/secrets.py", "app-config-python"),
    ("/credentials.py", "app-config-python"),
    ("/celeryconfig.py", "app-config-python"),
    ("/gunicorn.conf.py", "app-config-python"),
    ("/superset_config.py", "app-config-python"),
    # Per-service env split.
    ("/production.env", "env-production"),
    ("/mysql.env", "env-production"),
    ("/mongodb.env", "env-production"),
    ("/postgres.env", "env-production"),
    ("/postgresql.env", "env-production"),
    ("/redis.env", "env-production"),
    ("/.db.env", "env-production"),
    # Hand-rolled PHP connection scripts.
    ("/db.php", "app-config-php-database"),
    ("/database.php", "app-config-php-database"),
    ("/connect.php", "app-config-php-database"),
    ("/connection.php", "app-config-php-database"),
    # PHP include-convention config + Drupal settings.
    ("/config.inc.php", "app-config-php"),
    ("/config.inc.php.bak", "app-config-php"),
    ("/config.inc.php.dist", "app-config-php"),
    ("/local.settings.php", "app-config-php"),
    # wp-config suffixes with `.php` dropped.
    ("/wp-config.inc", "wp-config"),
    ("/wp-config.save", "wp-config"),
    ("/wp-config.php_bak", "wp-config"),
])
def test_new_leaves_route_to_the_expected_trap(path, trap_name):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == trap_name, f"{path} routed to {trap.name}"


# --- the nested spellings the sweep actually sends ----------------------
#
# These are not separate table entries: each resolves by dropping known
# layout parents onto one of the leaves above. Pinning them here is what
# proves the leaf registration was the right mechanism -- if a future
# change narrows the walk vocabulary, these fail rather than silently
# going back to 404.

@pytest.mark.parametrize("path,trap_name", [
    ("/settings/local.py", "app-config-python"),
    ("/settings/base.py", "app-config-python"),
    ("/settings/dev.py", "app-config-python"),
    ("/settings/production.py", "app-config-python"),
    ("/config/settings/local.py", "app-config-python"),
    ("/config/settings/production.py", "app-config-python"),
    ("/mysite/settings/local.py", "app-config-python"),
    ("/myapp/settings/local.py", "app-config-python"),
    ("/project/settings/production.py", "app-config-python"),
    ("/conf/secrets.py", "app-config-python"),
    ("/config/secrets.py", "app-config-python"),
    ("/src/secrets.py", "app-config-python"),
    ("/instance/secrets.py", "app-config-python"),
    ("/env/production.env", "env-production"),
    ("/envs/production.env", "env-production"),
    ("/includes/db.php", "app-config-php-database"),
    ("/includes/database.php", "app-config-php-database"),
    ("/includes/connect.php", "app-config-php-database"),
    ("/includes/connection.php", "app-config-php-database"),
    ("/lib/db.php", "app-config-php-database"),
    ("/lib/database.php", "app-config-php-database"),
    ("/inc/database.php", "app-config-php-database"),
    ("/config/config.inc.php", "app-config-php"),
    ("/config/config.inc.php.bak", "app-config-php"),
    ("/config/config.inc.php.dist", "app-config-php"),
    ("/inc/config.inc.php", "app-config-php"),
    ("/sites/default/local.settings.php", "app-config-php"),
])
def test_nested_spellings_resolve_through_the_layout_walk(path, trap_name):
    trap, depth = tbenv.resolve_canary_trap(path)
    assert trap is not None, f"{path} resolves to no trap"
    assert trap.name == trap_name, f"{path} routed to {trap.name}"
    assert depth > 0, f"{path} matched exactly; expected a walk"


# --- the vocabulary gate still holds ------------------------------------

@pytest.mark.parametrize("path", [
    "/9f2a1c/secrets.py",
    "/x/y/z/mysql.env",
    "/random123/db.php",
    "/aaa/bbb/wp-config.save",
    "/nonsense/local.settings.php",
    "/deadbeef/production.env",
])
def test_junk_parents_still_get_nothing(path):
    """The walk answers a plausible deployment layout, not any parent.
    Answering these would advertise a host that says yes to anything."""
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap is None, f"{path} wrongly resolved to {trap.name if trap else None}"


# --- nothing was stolen from an existing owner --------------------------

def test_existing_owners_keep_their_renderers():
    """Every leaf added here sits beside a path that already answered;
    the pre-existing spelling must keep its own trap."""
    for path, want in [
        ("/wp-config.php", "wp-config"),
        ("/settings.py", "app-config-python"),
        ("/config.py", "app-config-python"),
        ("/instance/config.py", "app-config-python"),
        ("/config.php", "app-config-php"),
        ("/settings.php", "app-config-php"),
        ("/inc/config.php", "app-config-php"),
        ("/config/database.php", "app-config-php-database"),
        ("/staging.env", "env-production"),
        ("/db.env", "env-production"),
    ]:
        trap = tbenv._TRAP_BY_PATH.get(path)
        assert trap is not None and trap.name == want, (
            f"{path} -> {trap.name if trap else None}, expected {want}")


def test_deployment_tiers_are_answered_as_a_group():
    """The gap this closes: a dictionary walking prod/staging/production
    in order must not get a canary for two tiers and a 404 for the
    third."""
    for tier in ("prod", "staging", "production", "dev", "test"):
        assert f"/{tier}.env" in tbenv._TRAP_BY_PATH, tier


def test_service_env_split_covers_both_spellings():
    """`.env` is itself a dotfile, so the per-service split appears with
    and without the leading dot."""
    for name in ("mysql", "mongodb", "postgres", "redis", "db"):
        assert f"/{name}.env" in tbenv._TRAP_BY_PATH, name
        assert f"/.{name}.env" in tbenv._TRAP_BY_PATH, name


# --- dispatch + the per-hit-unique rule ---------------------------------

@pytest.mark.parametrize("path,result", [
    ("/settings/local.py", "app-config-python"),
    ("/mysql.env", "env-production"),
    ("/includes/db.php", "app-config-php-database"),
    ("/wp-config.save", "wp-config"),
])
async def test_dispatch_serves_the_new_paths(flux_client, monkeypatch, path, result):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.41"})
    assert resp.status == 200
    body = await resp.read()
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"].encode() in body
    assert _log_entries(flux_client.log_path)[-1]["result"] == result
