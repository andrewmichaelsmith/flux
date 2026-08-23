"""YAML credential files at the spellings sweeps actually send.

Three gaps, all in families that already had a renderer:

  * The Rails DB config was answered at `/config/database.yml` and its
    prefix matrix, but not at the webroot-dropped leaf (`/database.yml`,
    `/db.yml`) — which dictionaries ask for *more* than the canonical
    path — nor at the application-prefixed spellings where the prefix
    replaces `config/` rather than preceding it (`/api/database.yml`).
  * Helm chart values were named in the generic YAML renderer's own
    docstring as a shape it covers, but no `values.yaml` path was ever
    listed, so the whole family 404'd.
  * `/credentials.json` was owned by the JSON trap; the YAML sibling the
    same sweep walks had no owner at all.
"""
import pytest

import flux.server as tbenv


@pytest.mark.parametrize("path", [
    # Webroot-dropped leaf.
    "/database.yml",
    "/database.yaml",
    "/db.yml",
    "/db.yaml",
    "/database.yml.bak",
    "/database.yml.old",
    "/database.yml~",
    # Prefix replaces `config/` rather than preceding it.
    "/api/database.yml",
    "/app/database.yml",
    "/backend/database.yml",
    "/server/database.yml",
    "/services/database.yml",
    "/src/database.yml",
    "/db/database.yml",
    "/conf/database.yml",
    "/api/database.yaml",
    "/app/db.yml",
])
def test_rails_db_config_answers_the_webroot_spellings(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == "rails-database-yml"


@pytest.mark.parametrize("path", [
    "/values.yaml",
    "/values.yml",
    "/helm/values.yaml",
    "/helm/values.yml",
    "/chart/values.yaml",
    "/charts/values.yaml",
    "/deploy/values.yaml",
    "/k8s/values.yaml",
    # Per-environment overlays — where the production credentials are.
    "/values-prod.yaml",
    "/values.prod.yaml",
    "/values-production.yaml",
    "/values.production.yaml",
    "/values-staging.yaml",
    "/values.staging.yaml",
    "/helm/values-prod.yaml",
    "/helm/values.production.yaml",
    # YAML sibling of the JSON credentials file.
    "/credentials.yml",
    "/credentials.yaml",
])
def test_helm_values_and_yaml_credentials_answer(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == "app-config-yaml"


def test_the_canonical_rails_paths_keep_their_owner():
    """The additions sit beside the existing entries, they do not
    replace them."""
    assert tbenv._TRAP_BY_PATH["/config/database.yml"].name == "rails-database-yml"
    assert tbenv._TRAP_BY_PATH["/config/secrets.yml"].name == "rails-secrets-yml"
    assert tbenv._TRAP_BY_PATH["/config/database.yml.pgsql"].name == "rails-database-yml"
    # `/api/config/database.yml` is the `_app_layout_variants` shape and
    # must still resolve — the new prefix set is a different layout, not
    # a replacement for it.
    assert tbenv._TRAP_BY_PATH["/app/config/database.yml"].name == "rails-database-yml"


def test_json_and_yaml_credentials_keep_separate_owners():
    """`/credentials.json` has its own renderer; adding the YAML
    spelling must not move it."""
    assert tbenv._TRAP_BY_PATH["/credentials.json"].name == "config-json"
    assert tbenv._TRAP_BY_PATH["/credentials.yml"].name == "app-config-yaml"


def test_the_webroot_leaf_renders_the_same_document_as_the_canonical_path():
    """`/database.yml` and `/config/database.yml` are the same file seen
    from two docroots. Serving two different documents would be a tell."""
    assert (
        tbenv._TRAP_BY_PATH["/database.yml"]
        is tbenv._TRAP_BY_PATH["/config/database.yml"]
    )


def test_the_values_family_inherits_the_editor_suffix_rule():
    """The Helm paths join `app-config-yaml`, which is in the
    editor-leftover family, so their `.bak` / `.swp` siblings come for
    free. This is the rule working for a path added after it."""
    for suffix in tbenv._APP_CONFIG_EDITOR_SUFFIXES:
        trap = tbenv._TRAP_BY_PATH.get("/values.yaml" + suffix)
        assert trap is not None, f"/values.yaml{suffix} is not routed"
        assert trap.name == "app-config-yaml"


@pytest.mark.parametrize("path", [
    # Not claimed: too generic, or owned elsewhere.
    "/values",
    "/database",
    "/db",
    "/application.yml",
    "/config/database.yml.nope",
])
def test_neighbouring_spellings_are_not_over_claimed(path):
    trap = tbenv._TRAP_BY_PATH.get(path)
    if path == "/application.yml":
        # Owned by its own trap, and must stay there.
        assert trap is not None and trap.name != "app-config-yaml"
    else:
        assert trap is None, f"{path} should not be claimed, got {trap}"
