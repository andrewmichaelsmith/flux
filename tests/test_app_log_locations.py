"""Tests for the generic application-log family.

The table already answered the framework-canonical log locations —
Monolog's `storage/logs/laravel.log` and WordPress's
`wp-content/debug.log`. A credential-dredging sweep does not start from
the framework's layout: it asks for `error_log`, `debug.log`,
`access.log` and `production.log` at the webroot and under `log/` and
`logs/`, which is where a misconfigured static-file route actually
leaves them. Those spellings answered 404 while the canonical ones
answered, so a sweep's first request missed and only a later, more
specific one hit.

Two properties carry the family:

* **Shape follows the filename, not the path pattern.** A `php error_log`
  whose body is Monolog, or an `access.log` that renders a stack trace,
  tells a reader this host answers by pattern rather than by what the
  file is — the same tell as a `wsgi.py` whose body is a `manage.py`.
* **One registration covers the directory spellings.** The layout walk
  resolves `logs/`, `log/`, `public/`, `admin/` and `var/` from the bare
  leaf, so the table lists the leaf once. `log` (singular) had to join
  the walk vocabulary for this to hold — `logs` was already there, which
  had split the family in half and left the whole Rails tree, whose
  directory is `log/` by convention, answering 404.
"""

import pytest

from flux import server as tbenv


AWS = {
    "aws": {
        "awsAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "awsSecretAccessKey": "wJalrXUtnFEMI-EXAMPLE-KEY",
        "awsSessionToken": "FwoGZXIvYXdzEXAMPLETOKEN",
    },
}

# (path, trap that must answer, walk depth)
RESOLUTIONS = [
    # Bare leaves — exact entries.
    ("/error_log", "php-error-log", 0),
    ("/error.log", "php-error-log", 0),
    ("/errors.log", "php-error-log", 0),
    ("/debug.log", "php-error-log", 0),
    ("/php_errors.log", "php-error-log", 0),
    ("/server.log", "php-error-log", 0),
    ("/app.log", "php-error-log", 0),
    ("/application.log", "php-error-log", 0),
    ("/production.log", "rails-env-log", 0),
    ("/development.log", "rails-env-log", 0),
    ("/staging.log", "rails-env-log", 0),
    ("/dev.log", "rails-env-log", 0),
    ("/test.log", "rails-env-log", 0),
    ("/access.log", "web-access-log", 0),
    ("/access_log", "web-access-log", 0),
    ("/laravel.log", "laravel-log", 0),
    ("/laravel.log.bak", "laravel-log", 0),
    ("/laravel.log.old", "laravel-log", 0),
    # Reached by the layout walk from the bare leaf, not by their own
    # table entry. These are the spellings the dictionary actually walks.
    ("/logs/error.log", "php-error-log", 1),
    ("/log/error.log", "php-error-log", 1),
    ("/logs/debug.log", "php-error-log", 1),
    ("/log/debug.log", "php-error-log", 1),
    ("/log/production.log", "rails-env-log", 1),
    ("/log/development.log", "rails-env-log", 1),
    ("/logs/access.log", "web-access-log", 1),
    ("/public/laravel.log", "laravel-log", 1),
    ("/admin/laravel.log", "laravel-log", 1),
    ("/storage/laravel.log", "laravel-log", 1),
    ("/var/logs/dev.log", "rails-env-log", 2),
    ("/var/log/apache2/error.log", "php-error-log", 3),
]


@pytest.mark.parametrize("path,expected,depth", RESOLUTIONS)
def test_log_path_resolves(path, expected, depth):
    trap, got_depth = tbenv.resolve_canary_trap(path)
    assert trap is not None, f"{path} must be answered"
    assert trap.name == expected
    assert got_depth == depth


def test_log_singular_is_in_the_walk_vocabulary():
    """The reason the Rails tree resolves at all."""
    assert "log" in tbenv._TRAP_WALK_PREFIXES
    assert "logs" in tbenv._TRAP_WALK_PREFIXES


# --- the canonical locations keep their own renderers -----------------

def test_canonical_locations_are_unchanged():
    """The expansion must not move a route that already worked."""
    assert tbenv.find_canary_trap(
        "/storage/logs/laravel.log").name == "laravel-log"
    assert tbenv.find_canary_trap(
        "/wp-content/debug.log").name == "wp-debug-log"
    assert tbenv.find_canary_trap(
        "/wp-content/uploads/debug.log").name == "wp-debug-log"


def test_bare_debug_log_does_not_capture_the_wordpress_one():
    """`/debug.log` and `/wp-content/debug.log` are different files with
    different bodies; the exact entry must win over the walk."""
    assert tbenv.find_canary_trap("/debug.log").name == "php-error-log"
    assert tbenv.find_canary_trap(
        "/wp-content/debug.log").name == "wp-debug-log"


# --- shape follows the filename ---------------------------------------

def test_php_error_log_is_php_shaped():
    body = tbenv.render_php_error_log(dict(AWS)).decode("utf-8")
    assert "PHP Fatal error:" in body
    assert "Stack trace:" in body
    # Not Monolog, and not Rails.
    assert "production.INFO" not in body
    assert "INFO -- :" not in body


def test_rails_log_is_rails_shaped():
    body = tbenv.render_rails_log(dict(AWS)).decode("utf-8")
    assert "INFO -- :" in body
    assert "Processing by" in body
    assert "PHP Fatal error:" not in body


def test_access_log_is_combined_log_shaped():
    body = tbenv.render_web_access_log(dict(AWS)).decode("utf-8")
    assert '"GET / HTTP/1.1" 200' in body
    assert "PHP Fatal error:" not in body
    assert "INFO -- :" not in body


@pytest.mark.parametrize("renderer", [
    "render_php_error_log", "render_rails_log", "render_web_access_log",
])
def test_every_log_renderer_carries_the_canary(renderer):
    body = getattr(tbenv, renderer)(dict(AWS)).decode("utf-8")
    assert AWS["aws"]["awsAccessKeyId"] in body, (
        "a grep for AKIA over the leaked log is the dredging step this "
        "family exists to answer"
    )
    assert AWS["aws"]["awsSecretAccessKey"] in body


@pytest.mark.parametrize("renderer", [
    "render_php_error_log", "render_rails_log", "render_web_access_log",
])
def test_no_log_renderer_emits_a_fixed_secret(renderer):
    """Every credential-shaped field must be per-hit unique, or the body
    fingerprints every host serving it and detects nothing on replay."""
    fn = getattr(tbenv, renderer)
    a = fn(dict(AWS)).decode("utf-8")
    b = fn(dict(AWS)).decode("utf-8")
    assert a != b, "two reads must not be byte-identical"


def test_access_log_leaks_via_query_string_not_a_config_block():
    """An access log holds no config — the realistic leak is a client
    that passed its key as a query parameter."""
    body = tbenv.render_web_access_log(dict(AWS)).decode("utf-8")
    assert f"aws_access_key_id={AWS['aws']['awsAccessKeyId']}" in body


@pytest.mark.parametrize("path,_e,_d", RESOLUTIONS)
def test_every_log_trap_requests_the_aws_canary(path, _e, _d):
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap.canary_types == ("aws",)


# --- the enable gate ---------------------------------------------------

def test_disabled_removes_the_generic_names(monkeypatch):
    monkeypatch.setattr(tbenv, "APP_LOG_ENABLED", False)
    for path in ("/error_log", "/debug.log", "/access.log",
                 "/production.log", "/logs/error.log"):
        trap, _ = tbenv.resolve_canary_trap(path)
        assert trap is None, f"{path} must 404 when the family is off"


def test_disabled_leaves_the_canonical_locations_alone(monkeypatch):
    """Scoped flag: turning the expansion off restores the pre-expansion
    surface rather than taking the framework routes down with it."""
    monkeypatch.setattr(tbenv, "APP_LOG_ENABLED", False)
    assert tbenv.find_canary_trap(
        "/storage/logs/laravel.log").name == "laravel-log"
    assert tbenv.find_canary_trap(
        "/wp-content/debug.log").name == "wp-debug-log"
    assert tbenv.find_canary_trap("/laravel.log").name == "laravel-log"


def test_enabled_by_default():
    assert tbenv.APP_LOG_ENABLED is True


def test_gate_set_excludes_the_canonical_families():
    assert "laravel-log" not in tbenv._APP_LOG_TRAP_NAMES
    assert "wp-debug-log" not in tbenv._APP_LOG_TRAP_NAMES


# --- route-table integrity --------------------------------------------

def test_no_duplicate_paths_introduced():
    seen = {}
    for trap in tbenv.CANARY_TRAPS:
        for p in trap.paths:
            assert p not in seen, (
                f"{p} claimed by both {seen.get(p)} and {trap.name}"
            )
            seen[p] = trap.name
