"""WordPress plugin readme version probe + the nonce mint beside it."""

import json
import re

import pytest

from flux import server as tbenv


# --- matcher -------------------------------------------------------------

@pytest.mark.parametrize("path,slug", [
    ("/wp-content/plugins/super-forms/readme.txt", "super-forms"),
    ("/wp-content/plugins/woocommerce/readme.txt", "woocommerce"),
    ("/wp-content/plugins/wp-mail-smtp/readme.txt", "wp-mail-smtp"),
    ("/wp-content/plugins/the-events-calendar/readme.txt", "the-events-calendar"),
    ("/wp-content/plugins/w3-total-cache/readme.txt", "w3-total-cache"),
    # Case folds: the sweeps are not consistent about it.
    ("/WP-CONTENT/PLUGINS/Super-Forms/README.TXT", "super-forms"),
    # A query string is not part of the path.
    ("/wp-content/plugins/pods/readme.txt?ver=2", "pods"),
])
def test_readme_paths_match(path, slug):
    assert tbenv.wp_plugin_readme_slug(path) == slug


@pytest.mark.parametrize("path", [
    "",
    "/readme.txt",                                     # webroot, not a plugin
    "/wp-content/plugins/readme.txt",                  # no slug segment
    "/wp-content/themes/twentytwenty/readme.txt",      # themes are not plugins
    "/wp-content/plugins/super-forms/readme.html",     # different file
    "/wp-content/plugins/super-forms/lib/readme.txt",  # nested, not the slug root
    "/wp-content/plugins/super-forms/index.php",       # the webshell gate's shape
    "/wp-content/plugins/../../etc/passwd",
])
def test_non_readme_paths_do_not_match(path):
    assert tbenv.wp_plugin_readme_slug(path) == ""


def test_matcher_disabled_by_env(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_PLUGIN_README_ENABLED", False)
    assert tbenv.wp_plugin_readme_slug("/wp-content/plugins/pods/readme.txt") == ""


# --- version / rendering -------------------------------------------------

def test_version_is_stable_for_a_slug():
    """A scanner that asks twice must be told the same thing."""
    first = tbenv.wp_plugin_readme_version("super-forms")
    assert first == tbenv.wp_plugin_readme_version("super-forms")


def test_version_is_low_enough_to_read_as_vulnerable():
    """Version-gated checks compare against an upper bound; a low number
    reads as vulnerable against essentially any of them."""
    for slug in ["super-forms", "woocommerce", "pods", "forminator", "give"]:
        major = int(tbenv.wp_plugin_readme_version(slug).split(".")[0])
        assert 1 <= major <= 3


def test_version_differs_between_slugs():
    versions = {
        tbenv.wp_plugin_readme_version(s)
        for s in ["a", "b", "c", "d", "e", "f", "g", "h"]
    }
    assert len(versions) > 1


@pytest.mark.parametrize("slug,title", [
    ("super-forms", "Super Forms"),
    ("wp-mail-smtp", "WP Mail SMTP"),
    ("the-events-calendar", "The Events Calendar"),
    ("woocommerce", "WooCommerce"),
    ("pods", "Pods"),
])
def test_title_derivation(slug, title):
    assert tbenv.wp_plugin_readme_title(slug) == title


def test_readme_body_carries_the_parsed_fields():
    body = tbenv.render_wp_plugin_readme(
        "super-forms", tbenv.wp_plugin_readme_version("super-forms"),
    ).decode()
    assert body.startswith("=== Super Forms ===")
    # `Stable tag` is the line the version check actually reads.
    stable = re.search(r"^Stable tag: (\S+)$", body, re.M)
    assert stable is not None
    assert stable.group(1) == tbenv.wp_plugin_readme_version("super-forms")
    for field in ["Requires at least:", "Tested up to:", "License:"]:
        assert field in body
    assert "== Changelog ==" in body


def test_readme_body_has_no_credential_shaped_fields():
    """Packaging metadata carries no secrets; if that ever changes it must
    be per-hit, never a literal."""
    body = tbenv.render_wp_plugin_readme("super-forms", "1.2.3").decode().lower()
    for word in ["password", "api_key", "apikey", "secret", "token", "aws_"]:
        assert word not in body


# --- per-source cap ------------------------------------------------------

def test_first_probe_is_answered_immediately(monkeypatch):
    """A tool carrying one plugin's exploit asks about one plugin."""
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    assert tbenv.wp_plugin_readme_observe("198.51.100.7", "super-forms") == (1, True)


def test_repeat_probe_of_same_slug_is_not_a_new_slug(monkeypatch):
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    for _ in range(10):
        count, answer = tbenv.wp_plugin_readme_observe("198.51.100.7", "super-forms")
    assert (count, answer) == (1, True)


def test_cap_is_reached_by_distinct_slugs(monkeypatch):
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    cap = tbenv.WP_PLUGIN_README_MAX_SLUGS_PER_SOURCE
    results = [
        tbenv.wp_plugin_readme_observe("198.51.100.8", f"plugin-{i}")
        for i in range(cap + 3)
    ]
    assert [r[1] for r in results[:cap]] == [True] * cap
    assert [r[1] for r in results[cap:]] == [False] * 3
    # The recorded set never grows past the cap.
    assert all(r[0] <= cap for r in results)


def test_slug_already_answered_stays_answered_past_the_cap(monkeypatch):
    """A source at its cap must not start 404ing readmes it was handed —
    that contradicts the earlier answer inside one burst."""
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    cap = tbenv.WP_PLUGIN_README_MAX_SLUGS_PER_SOURCE
    for i in range(cap):
        tbenv.wp_plugin_readme_observe("198.51.100.12", f"plugin-{i}")
    # Cap reached: a new slug is refused...
    assert tbenv.wp_plugin_readme_observe("198.51.100.12", "brand-new")[1] is False
    # ...but every slug already answered keeps its answer.
    for i in range(cap):
        assert tbenv.wp_plugin_readme_observe("198.51.100.12", f"plugin-{i}")[1] is True


def test_sources_are_tracked_independently(monkeypatch):
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    tbenv.wp_plugin_readme_observe("198.51.100.9", "pods")
    assert tbenv.wp_plugin_readme_observe("198.51.100.10", "give") == (1, True)


def test_entries_expire(monkeypatch):
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    tbenv.wp_plugin_readme_observe("198.51.100.11", "pods", now=1000.0)
    later = 1000.0 + tbenv.WP_PLUGIN_README_TTL_SECONDS + 1
    assert tbenv.wp_plugin_readme_observe("198.51.100.11", "give", now=later) == (1, True)


def test_source_table_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    monkeypatch.setattr(tbenv, "WP_PLUGIN_README_MAX_SOURCES", 64)
    for i in range(400):
        tbenv.wp_plugin_readme_observe(f"203.0.113.{i % 256}-{i}", "pods")
    assert len(tbenv._WP_PLUGIN_README_SEEN) <= 64 + 1


# --- nonce mint ----------------------------------------------------------

@pytest.mark.parametrize("qs", ["action=super_create_nonce", "action=SUPER_CREATE_NONCE&x=1"])
def test_nonce_action_matches(qs):
    assert tbenv.wp_plugin_nonce_action("/wp-admin/admin-ajax.php", qs) == "super_create_nonce"


@pytest.mark.parametrize("path,qs", [
    ("/wp-admin/admin-ajax.php", "action=heartbeat"),
    ("/wp-admin/admin-ajax.php", ""),
    ("/wp-admin/admin-post.php", "action=super_create_nonce"),
    ("/wp-content/plugins/x/readme.txt", "action=super_create_nonce"),
])
def test_nonce_action_does_not_match(path, qs):
    assert tbenv.wp_plugin_nonce_action(path, qs) == ""


def test_nonce_action_disabled_by_env(monkeypatch):
    monkeypatch.setattr(tbenv, "WP_PLUGIN_UPLOAD_ENABLED", False)
    assert tbenv.wp_plugin_nonce_action(
        "/wp-admin/admin-ajax.php", "action=super_create_nonce",
    ) == ""


def test_nonce_and_session_are_per_hit_unique():
    """Nothing credential-shaped is ever a literal: a fixed nonce is
    worthless on replay and identifies the whole fleet in one request."""
    seen_nonce, seen_session = set(), set()
    for _ in range(50):
        _, nonce, session = tbenv.render_wp_plugin_nonce_response()
        seen_nonce.add(nonce)
        seen_session.add(session)
    assert len(seen_nonce) == 50
    assert len(seen_session) == 50


def test_nonce_response_shape_is_parseable():
    body, nonce, session = tbenv.render_wp_plugin_nonce_response()
    payload = json.loads(body)
    assert payload["success"] is True
    assert payload["data"]["nonce"] == nonce
    assert payload["data"]["session"] == session
    # WordPress nonces are ten characters wide.
    assert len(nonce) == 10


# --- upload vector -------------------------------------------------------

def test_super_forms_upload_vector_is_registered():
    vector = tbenv.wp_plugin_upload_vector(
        "/wp-admin/admin-ajax.php", "action=submit_form",
    )
    assert vector is not None
    assert vector["id"] == "super-forms"
    assert vector["idiom"] == "ajax"


def test_super_forms_vector_needs_its_action():
    assert tbenv.wp_plugin_upload_vector(
        "/wp-admin/admin-ajax.php", "action=not_submit_form",
    ) is None


def test_mint_and_upload_are_different_branches():
    """Same address — only the action separates the two halves of the chain."""
    assert tbenv.wp_plugin_nonce_action(
        "/wp-admin/admin-ajax.php", "action=submit_form",
    ) == ""
    assert tbenv.wp_plugin_upload_vector(
        "/wp-admin/admin-ajax.php", "action=super_create_nonce",
    ) is None


def test_readme_trap_defaults_on():
    assert tbenv.WP_PLUGIN_README_ENABLED


def test_unidentified_source_does_not_bypass_the_cap(monkeypatch):
    """A missing source identity must not switch the cap off — that is
    the case where an enumeration oracle is least affordable."""
    monkeypatch.setattr(tbenv, "_WP_PLUGIN_README_SEEN", {})
    cap = tbenv.WP_PLUGIN_README_MAX_SLUGS_PER_SOURCE
    results = [tbenv.wp_plugin_readme_observe("", f"plugin-{i}") for i in range(cap + 2)]
    assert results[0] == (1, True)
    assert results[cap][1] is False
