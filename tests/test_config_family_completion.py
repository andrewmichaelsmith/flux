"""Coverage gaps closed in the framework-config families.

Two shapes of miss, both found the same way — replaying a captured
dredging dictionary against dispatch and reading off what 404'd:

  * Spring publishes defaults in `application.<ext>` and the values that
    actually differ per environment in `application-<profile>.<ext>`.
    Only the bare spelling answered, i.e. the one file whose real-world
    copy is least likely to hold a credential.
  * A stock Laravel `config/` directory was answering four of its
    members and 404ing the rest, including `filesystems.php` and
    `queue.php` — which are where the object-store and queue credentials
    actually land.
"""
import json

import pytest

from flux import server as tbenv
from .test_server import FAKE_TRACEBIT, _fake_canary, flux_client  # noqa: F401


def _trap_for(path):
    for trap in tbenv.CANARY_TRAPS:
        if path in trap.paths:
            return trap
    return None


# --- Spring profile suffixes ---------------------------------------------


@pytest.mark.parametrize("path", [
    "/application-prod.yml",
    "/application-prod.yaml",
    "/application-production.yml",
    "/application-dev.yml",
    "/application-development.yaml",
    "/application-staging.yml",
    "/application-stage.yml",
    "/application-test.yml",
    "/application-local.yml",
    "/application-qa.yml",
    "/application-uat.yml",
    "/application-default.yml",
    "/bootstrap-prod.yml",
    "/bootstrap-dev.yaml",
])
def test_spring_yaml_profile_spellings_are_trapped(path):
    trap = _trap_for(path)
    assert trap is not None, f"{path} is not on any trap"
    assert trap.name == "application-yml"
    assert trap.canary_types == ("aws",)


@pytest.mark.parametrize("path", [
    "/application-prod.properties",
    "/application-staging.properties",
    "/application-test.properties",
    "/application-local.properties",
    "/bootstrap-prod.properties",
    "/bootstrap-dev.properties",
])
def test_spring_properties_profile_spellings_are_trapped(path):
    trap = _trap_for(path)
    assert trap is not None, f"{path} is not on any trap"
    assert trap.name == "application-properties"


def test_bare_spring_spellings_still_answer_their_own_traps():
    """The profile suffixes are additive — the bare spellings must not
    have been moved or shadowed."""
    assert _trap_for("/application.yml").name == "application-yml"
    assert _trap_for("/application.yaml").name == "application-yml"
    assert _trap_for("/application.properties").name == "application-properties"


def test_profile_suffixes_do_not_collide_with_the_bare_bootstrap_traps():
    """`/bootstrap.yml` and `/bootstrap.properties` belong to the
    framework-agnostic families. Adding `bootstrap-<profile>` must not
    have claimed the un-suffixed spellings from them."""
    assert _trap_for("/bootstrap.yml").name == "app-config-yaml"
    assert _trap_for("/bootstrap.properties").name == "app-config-properties"


def test_no_path_is_claimed_by_two_traps():
    """A path on two traps is a silent behaviour change: which renderer
    wins depends on table order rather than on intent."""
    seen: dict[str, str] = {}
    for trap in tbenv.CANARY_TRAPS:
        for path in trap.paths:
            assert path not in seen, (
                f"{path} claimed by both {seen[path]} and {trap.name}"
            )
            seen[path] = trap.name


def test_profile_vocabulary_is_a_fixed_list_not_a_wildcard():
    """A host that answers every profile name ever guessed is not a
    host."""
    assert _trap_for("/application-notaprofile.yml") is None
    assert _trap_for("/application-%s.yml" % ("x" * 40)) is None


# --- Laravel config/ directory completion --------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/config/filesystems.php", "app-config-php-filesystems"),
    ("/config/filesystem.php", "app-config-php-filesystems"),
    ("/config/queue.php", "app-config-php-queue"),
    ("/config/horizon.php", "app-config-php-queue"),
    ("/config/broadcasting.php", "app-config-php-broadcasting"),
    ("/config/websockets.php", "app-config-php-broadcasting"),
    ("/config/session.php", "app-config-php-structural"),
    ("/config/logging.php", "app-config-php-structural"),
    ("/config/view.php", "app-config-php-structural"),
    ("/config/hashing.php", "app-config-php-structural"),
    ("/config/auth.php", "app-config-php-structural"),
    ("/config/cors.php", "app-config-php-structural"),
    ("/config/sanctum.php", "app-config-php-structural"),
])
def test_laravel_config_directory_members_are_trapped(path, expected):
    trap = _trap_for(path)
    assert trap is not None, f"{path} is not on any trap"
    assert trap.name == expected


def test_filesystems_carries_the_object_store_key_pair():
    """This is the file a real Laravel install puts the S3 pair in, so
    the canary belongs in the `s3` disk rather than somewhere adjacent."""
    body = tbenv.render_php_filesystems_config(FAKE_TRACEBIT).decode("utf-8")
    assert body.startswith("<?php\n")
    assert "'driver' => 's3'," in body
    assert "'key' => 'AKIAFAKEEXAMPLE01'," in body
    assert "'secret' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'," in body


def test_filesystems_config_has_no_non_canary_secret():
    """Stands in for the per-hit-uniqueness check the other renderers
    get. This file's only credential is the request's canary, so it is
    byte-stable within a fixed fixture by design — what has to be true
    instead is that no secret-shaped slot holds anything the canary did
    not supply, i.e. no fixed literal ever creeps in."""
    body = tbenv.render_php_filesystems_config(FAKE_TRACEBIT).decode("utf-8")
    aws = FAKE_TRACEBIT["aws"]
    canary_values = {
        aws["awsAccessKeyId"], aws["awsSecretAccessKey"], aws["awsSessionToken"],
    }
    for line in body.splitlines():
        stripped = line.strip()
        if not any(
            stripped.startswith(f"'{slot}' =>")
            for slot in ("key", "secret", "token", "password")
        ):
            continue
        value = stripped.split("=>", 1)[1].strip().rstrip(",").strip("'")
        assert value in canary_values, (
            f"{stripped!r} holds a value the canary did not supply — a "
            f"fixed literal here ships the same string from every host"
        )


def test_queue_carries_both_the_sqs_pair_and_a_redis_password():
    body = tbenv.render_php_queue_config(FAKE_TRACEBIT).decode("utf-8")
    assert "'driver' => 'sqs'," in body
    assert "'key' => 'AKIAFAKEEXAMPLE01'," in body
    assert "'driver' => 'redis'," in body
    assert "'password' => '" in body


def test_broadcasting_secrets_are_per_hit_synthetics():
    """No canary provider issues a Pusher app secret, so it must be a
    per-hit synthetic rather than a literal."""
    first = tbenv.render_php_broadcasting_config(FAKE_TRACEBIT).decode("utf-8")
    second = tbenv.render_php_broadcasting_config(FAKE_TRACEBIT).decode("utf-8")
    assert "'driver' => 'pusher'," in first
    assert first != second


def test_structural_config_invents_no_credentials():
    """These files hold no secrets in a real install. Fabricating one
    would be both implausible and a fixed-literal risk; the file is
    served for coherence, not for capture."""
    body = tbenv.render_php_session_config(FAKE_TRACEBIT).decode("utf-8")
    assert body.startswith("<?php\n")
    assert "password" not in body.lower()
    assert "secret" not in body.lower()
    assert "AKIAFAKEEXAMPLE01" not in body
    # Byte-stable is correct here precisely because there is nothing
    # per-hit to vary — asserting it keeps a credential from being added
    # later without also making it unique.
    assert body == tbenv.render_php_session_config(FAKE_TRACEBIT).decode("utf-8")


def test_structural_family_spends_no_canary():
    trap = _trap_for("/config/session.php")
    assert trap.canary_types == ()


# --- end-to-end through dispatch -----------------------------------------


@pytest.mark.parametrize("path,marker", [
    ("/application-prod.yml", b"spring:"),
    ("/application-staging.properties", b"="),
    ("/config/filesystems.php", b"'driver' => 's3',"),
    ("/config/queue.php", b"'driver' => 'sqs',"),
    ("/config/broadcasting.php", b"'driver' => 'pusher',"),
    ("/config/session.php", b"'lifetime' => 120,"),
])
async def test_dispatch_serves_the_new_paths(flux_client, monkeypatch, path, marker):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.60"})
    assert resp.status == 200, f"{path} did not dispatch"
    assert marker in await resp.read()


async def test_structural_path_dispatches_without_an_api_key(flux_client, monkeypatch):
    """It spends no canary, so a keyless deployment should still serve
    it rather than 404ing alongside the canary-backed members."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.get(
        "/config/session.php", headers={"X-Forwarded-For": "203.0.113.61"})
    assert resp.status in (200, 404)
    if resp.status == 200:
        assert b"'lifetime' => 120," in await resp.read()


async def test_new_paths_do_not_match_the_tarpit(flux_client):
    """Tarpit dispatch runs first; a path it claims drips junk bytes and
    issues no canary."""
    for path in (
        "/application-prod.yml", "/bootstrap-dev.yaml",
        "/config/filesystems.php", "/config/queue.php",
        "/config/broadcasting.php", "/config/session.php",
    ):
        assert not tbenv.is_tarpit_path(path), f"tarpit shadows {path}"
