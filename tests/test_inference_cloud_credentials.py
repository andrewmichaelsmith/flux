"""Inference / GPU-cloud credential files, and the spelling gaps beside them.

Two things are pinned here.

1. The new family: the credential files a box running a self-hosted LLM
   stack actually holds — the GPU and serverless-compute providers it
   rents capacity from, the chat front-end that collects the upstream
   provider keys, and the edge-runtime secrets file beside a deployed
   inference proxy. Each must resolve, carry a per-hit canary in the
   field a credential extractor reads, and parse in its own format.

2. The four one-file-two-spellings gaps found beside it, all the same
   defect: a trap answered one spelling of a file and 404ed a sibling
   spelling of the *same* file, so a dictionary walking both in one pass
   split across two outcomes. The OCI one is the worst of the four
   because it breaks a chain — the config Flux serves names the key file,
   and the key file is the read that carries the credential.
"""
import json

import pytest

import flux.server as tbenv

from tests.test_server import FAKE_TRACEBIT


AWS = FAKE_TRACEBIT["aws"]


# --- 1. the new family ----------------------------------------------------

# (path, expected result tag)
MUST_MATCH = [
    ("/.runpod/config.toml", "runpod-config"),
    ("/.modal.toml", "modal-config"),
    ("/.lambda_cloud/lambda_keys", "lambda-cloud-keys"),
    ("/.paperspace/config.json", "paperspace-config"),
    ("/librechat.yaml", "librechat-config"),
    ("/librechat.yml", "librechat-config"),
    ("/.dev.vars", "cloudflare-dev-vars"),
]

FAMILY = sorted({tag for _p, tag in MUST_MATCH})

MUST_NOT_MATCH = [
    "/runpod/config.toml",
    "/modal.toml",
    "/lambda_keys",
    "/paperspace/config.json",
    "/librechat",
    "/librechat.json",
    "/dev.vars",
    "/.dev.vars.example",
]


@pytest.mark.parametrize("path,tag", MUST_MATCH)
def test_every_member_resolves_to_its_own_tag(path, tag):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == tag


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_non_members_do_not_resolve(path):
    assert tbenv._TRAP_BY_PATH.get(path.lower()) is None, path


@pytest.mark.parametrize("tag", FAMILY)
def test_every_member_carries_the_canary(tag):
    """The canary must land in the field a credential extractor grabs —
    otherwise the probe is the only signal and replay is invisible."""
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == tag)
    body = trap.render(FAKE_TRACEBIT).decode("utf-8")
    assert any(
        AWS[k] in body
        for k in ("awsAccessKeyId", "awsSecretAccessKey", "awsSessionToken")
    ), f"{tag} carries no canary material"


ALT_TRACEBIT = {
    "aws": {
        "awsAccessKeyId": "AKIAALTEXAMPLE99",
        "awsSecretAccessKey": "ALTsecretXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "awsSessionToken": "FwoGZXIvYXdzALTTOKEN=",
        "awsExpiration": "2030-01-01T00:00:00Z",
        "awsConfirmationId": "conf-aws-2",
    },
}


@pytest.mark.parametrize("tag", FAMILY)
def test_no_member_ships_a_fixed_credential_literal(tag):
    """Swap the issued canary and every credential-shaped field must
    change with it. A value that survives the swap is a literal baked
    into the source — undetectable on replay, and identical on every
    host serving it, which turns the whole deployment into one
    fingerprint.
    """
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == tag)
    first = trap.render(FAKE_TRACEBIT).decode("utf-8")
    second = trap.render(ALT_TRACEBIT).decode("utf-8")
    assert first != second, f"{tag} renders identically under two canaries"
    for value in AWS.values():
        assert value not in second, (
            f"{tag} carries canary material from a different issuance: "
            f"{value!r} is hardcoded"
        )


def test_each_member_parses_in_its_own_format():
    """A reader that parses rather than greps must not get a syntax
    error, or the response is a tell."""
    paperspace = json.loads(
        tbenv.render_paperspace_config_json(FAKE_TRACEBIT).decode("utf-8")
    )
    assert paperspace["apiKey"] == AWS["awsSecretAccessKey"]

    # TOML: section header plus quoted scalars.
    modal = tbenv.render_modal_toml(FAKE_TRACEBIT).decode("utf-8")
    assert modal.startswith("[prod]")
    assert f'token_id = "{AWS["awsAccessKeyId"]}"' in modal
    runpod = tbenv.render_runpod_config_toml(FAKE_TRACEBIT).decode("utf-8")
    assert runpod.startswith("[default]")
    assert f'api_key = "{AWS["awsSecretAccessKey"]}"' in runpod

    # Lambda's file is a bare `api_key` line, no section header.
    lam = tbenv.render_lambda_cloud_keys(FAKE_TRACEBIT).decode("utf-8")
    assert not lam.startswith("[")
    assert lam.strip() == f"api_key = {AWS['awsSecretAccessKey']}"

    # `.dev.vars` is dotenv: every line KEY=value, no spaces around `=`.
    dv = tbenv.render_cloudflare_dev_vars(FAKE_TRACEBIT).decode("utf-8")
    for line in dv.strip().splitlines():
        assert "=" in line and " = " not in line.split("=", 1)[0], line


def test_dev_vars_db_password_is_per_hit_unique():
    """The one non-canary credential in the file is a synthetic, so two
    reads never share it."""
    a = tbenv.render_cloudflare_dev_vars(FAKE_TRACEBIT).decode("utf-8")
    b = tbenv.render_cloudflare_dev_vars(FAKE_TRACEBIT).decode("utf-8")
    assert a != b, "dev.vars is byte-identical across hits"


# --- the chain the LibreChat config sets up -------------------------------

def test_librechat_points_its_custom_endpoint_at_our_own_inference_surface():
    """The reason this file is worth serving: a parsed config steers the
    reader to an endpoint we already answer, so a harvested credential
    becomes a second logged request rather than a dead end."""
    body = tbenv.render_librechat_yaml({"_requestHost": "sensor.example"}).decode()
    assert 'baseURL: "https://sensor.example/v1"' in body
    # ...and that surface is really implemented.
    assert "/v1/chat/completions" in tbenv.LLM_ENDPOINT_PATHS


def test_librechat_custom_endpoint_bearer_is_the_canary_session_token():
    """The token on the self-referencing endpoint is the per-hit canary,
    which is what joins a follow-on inference request back to this exact
    config read."""
    body = tbenv.render_librechat_yaml(FAKE_TRACEBIT).decode("utf-8")
    assert f'apiKey: "{AWS["awsSessionToken"]}"' in body


def test_librechat_never_advertises_a_loopback_host():
    """Behind a proxy that rewrites Host the requested host arrives as a
    loopback literal; publishing it would advertise the reader's own
    machine and, being identical everywhere, fingerprint the deployment."""
    for host in ("127.0.0.1", "localhost", "", "::1"):
        body = tbenv.render_librechat_yaml({"_requestHost": host}).decode("utf-8")
        assert "127.0.0.1" not in body and "localhost" not in body, host


# --- 2. one file, two spellings ------------------------------------------

# (path, expected tag, the spelling that already worked)
SPELLING_GAPS = [
    # LiteLLM proxy config — `.yml` is the same file as `.yaml`.
    ("/litellm_config.yml", "litellm-config", "/litellm_config.yaml"),
    ("/litellm/config.yml", "litellm-config", "/litellm/config.yaml"),
    ("/proxy_config.yml", "litellm-config", "/proxy_config.yaml"),
    # Continue's config moved JSON -> YAML; only the legacy name resolved.
    ("/.continue/config.yaml", "continue-config", "/.continue/config.json"),
    ("/.continue/config.yml", "continue-config", "/.continue/config.json"),
    # The OCI key file's other two names, and the undotted spellings.
    ("/.oci/api_key.pem", "oci-api-key-pem", "/.oci/oci_api_key.pem"),
    ("/.oci/private_key.pem", "oci-api-key-pem", "/.oci/oci_api_key.pem"),
    ("/oci_api_key.pem", "oci-api-key-pem", "/.oci/oci_api_key.pem"),
    ("/oci/oci_api_key.pem", "oci-api-key-pem", "/.oci/oci_api_key.pem"),
    ("/oracle/oci_api_key.pem", "oci-api-key-pem", "/.oci/oci_api_key.pem"),
    ("/oci/config", "oci-config", "/.oci/config"),
    ("/oci_config", "oci-config", "/.oci/config"),
    ("/oracle/config", "oci-config", "/.oci/config"),
]


@pytest.mark.parametrize("path,tag,already", SPELLING_GAPS)
def test_both_spellings_of_one_file_reach_the_same_trap(path, tag, already):
    """A dictionary walking both spellings in one pass must not split
    across a 200 and a 404."""
    assert tbenv._TRAP_BY_PATH.get(already) is not None, already
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} still 404s while {already} resolves"
    assert trap.name == tag


def test_the_oci_config_names_a_key_file_that_resolves():
    """The chain this fix exists to close: the config Flux serves names
    `key_file`, and that file is the read that actually carries the
    credential. Answering the config and 404ing the key it points at
    dead-ends the walk on its second step."""
    body = tbenv.render_oci_config(FAKE_TRACEBIT).decode("utf-8")
    named = [
        line.split("=", 1)[1].strip()
        for line in body.splitlines()
        if line.startswith("key_file=")
    ]
    assert named, "oci config names no key_file"
    # `~/.oci/oci_api_key.pem` is read over HTTP as `/.oci/oci_api_key.pem`.
    as_path = named[0].lstrip("~")
    assert tbenv._TRAP_BY_PATH.get(as_path) is not None, as_path


def test_oci_config_does_not_answer_scanner_invented_suffixes():
    """The file is INI. Answering INI at a `.json` or `.yaml` name is a
    tell, so those spellings stay 404 even though sweeps ask for them."""
    for path in ("/oci_config.json", "/oci-config.json", "/oci_config.yaml"):
        assert tbenv._TRAP_BY_PATH.get(path) is None, path


# --- 3. the leftover copy ------------------------------------------------

LEFTOVER_FAMILY_ADDITIONS = [
    "oci-api-key-pem",
    "runpod-config",
    "modal-config",
    "lambda-cloud-keys",
    "paperspace-config",
    "librechat-config",
    "cloudflare-dev-vars",
]


@pytest.mark.parametrize("tag", LEFTOVER_FAMILY_ADDITIONS)
def test_credential_files_answer_their_leftover_copy(tag):
    """A credentials file is exactly the file an operator copies aside
    before rotating it — the rule the leftover family already states.
    `oci-config` was admitted and the key file it names was not, so the
    config answered its backup copy while the key answered only its
    canonical name."""
    assert tag in tbenv._APP_CONFIG_SUFFIX_FAMILY
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == tag)
    canonical = trap.paths[0].lower()
    for suffix in (".bak", ".old", ".save"):
        got = tbenv._TRAP_BY_PATH.get(canonical + suffix)
        assert got is not None and got.name == tag, canonical + suffix


def test_leftovers_are_not_stacked_on_leftovers():
    """No scanner asks for `.bak.old`, and generating them would double
    the table for nothing."""
    assert tbenv._TRAP_BY_PATH.get("/.modal.toml.bak.old") is None
    assert tbenv._TRAP_BY_PATH.get("/.oci/oci_api_key.pem.bak.save") is None
