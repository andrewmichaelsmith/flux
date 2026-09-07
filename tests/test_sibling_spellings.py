"""Sibling spellings of traps that already existed, plus PM2.

Each path here was recurring in the same credential-dredging sweep while
returning 404, next to a spelling of the *same file* that answered. That
shape — the trap exists, one of its names does not — is cheaper to miss
than a missing trap, because nothing about the surface looks broken.
"""
import json

import pytest

import flux.server as tbenv
from tests.test_server import FAKE_TRACEBIT


AWS_KEY_ID = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
AWS_SECRET = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]


@pytest.mark.parametrize("path,expected_trap", [
    # GCP Application Default Credentials under the home directories a
    # deployed app actually runs as. The webroot-relative spelling
    # already answered; the absolute ones did not.
    ("/home/ubuntu/.config/gcloud/application_default_credentials.json", "firebase-json"),
    ("/home/ec2-user/.config/gcloud/application_default_credentials.json", "firebase-json"),
    ("/home/app/.config/gcloud/application_default_credentials.json", "firebase-json"),
    ("/root/.config/gcloud/application_default_credentials.json", "firebase-json"),
    # Project-local GCP key spellings.
    ("/gcp.json", "firebase-json"),
    ("/config/gcp.json", "firebase-json"),
    # Django override settings — the dotted spelling of a file whose
    # underscored spelling (`/local_settings.py`) already answered.
    ("/settings.local.py", "app-config-python"),
    ("/app/settings.local.py", "app-config-python"),
    ("/core/settings.local.py", "app-config-python"),
    ("/backend/settings.local.py", "app-config-python"),
    ("/config/settings.local.py", "app-config-python"),
    # PM2 process definition.
    ("/ecosystem.config.js", "pm2-ecosystem-config"),
    ("/ecosystem.config.cjs", "pm2-ecosystem-config"),
    ("/ecosystem.json", "pm2-ecosystem-config"),
    ("/pm2.config.js", "pm2-ecosystem-config"),
    ("/pm2.json", "pm2-ecosystem-config"),
    ("/app/ecosystem.config.js", "pm2-ecosystem-config"),
    ("/api/ecosystem.config.js", "pm2-ecosystem-config"),
    ("/backend/ecosystem.config.js", "pm2-ecosystem-config"),
])
def test_sibling_spellings_dispatch(path, expected_trap):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is not None and trap.name == expected_trap, (
        f"{path!r} should dispatch to {expected_trap}, got {trap and trap.name!r}"
    )


@pytest.mark.parametrize("path", [
    "/ecosystem.config.json",
    "/ecosystem.js",
    "/myecosystem.config.js",
    "/settings.local.pyc",
    "/settings.locale.py",
    "/gcp.json.bak",
    "/mygcp.json",
])
def test_near_misses_are_not_swallowed(path):
    trap = tbenv._TRAP_BY_PATH.get(path.lower())
    assert trap is None or trap.name not in {
        "pm2-ecosystem-config", "app-config-python", "firebase-json",
    }, f"{path!r} should not have been claimed, got {trap and trap.name!r}"


def test_gcp_credentials_json_still_belongs_to_its_own_trap():
    """`/gcp-credentials.json` has a dedicated trap with a closer body.
    The GCP spellings added here must not take it — the collision guard
    caught exactly this while the change was being written."""
    for path in ("/gcp-credentials.json", "/config/gcp-credentials.json"):
        trap = tbenv._TRAP_BY_PATH.get(path)
        assert trap is not None and trap.name == "gcp-credentials-json"


# --- PM2 body ------------------------------------------------------------

def _pm2_config(r):
    raw = tbenv.render_pm2_ecosystem_config(r).decode()
    assert raw.startswith("// PM2 process definition")
    body = raw.split("module.exports =", 1)[1].rsplit(";", 1)[0]
    return json.loads(body)


def test_pm2_canary_lands_in_the_env_block_pm2_actually_injects():
    cfg = _pm2_config(FAKE_TRACEBIT)
    env = cfg["apps"][0]["env_production"]
    assert env["AWS_ACCESS_KEY_ID"] == AWS_KEY_ID
    assert env["AWS_SECRET_ACCESS_KEY"] == AWS_SECRET


def test_pm2_is_parseable_and_names_other_files():
    """The descriptor half: a client that parses rather than greps has
    somewhere to go next."""
    app = _pm2_config(FAKE_TRACEBIT)["apps"][0]
    for key in ("script", "cwd", "error_file", "out_file"):
        assert app[key]


def test_pm2_without_a_canary_leaves_the_slot_empty():
    env = _pm2_config({})["apps"][0]["env_production"]
    assert env["AWS_ACCESS_KEY_ID"] == ""
    assert env["AWS_SECRET_ACCESS_KEY"] == ""
    assert "AKIA" not in tbenv.render_pm2_ecosystem_config({}).decode()


def test_pm2_db_password_is_per_hit_not_a_fixed_literal():
    a = _pm2_config(FAKE_TRACEBIT)["apps"][0]["env_production"]["DATABASE_URL"]
    b = _pm2_config(FAKE_TRACEBIT)["apps"][0]["env_production"]["DATABASE_URL"]
    assert a != b, "a fixed DB password would fingerprint every deployment"
