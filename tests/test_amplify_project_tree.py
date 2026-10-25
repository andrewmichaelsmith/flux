"""Tests for the rest of the AWS Amplify project tree, and the Java-SDK
spelling of the credentials file.

Two client configs from the previous Amplify generation were already
answered while the directory that actually holds the credentials — and
the file a current build ships — were not. A sweep walking the tree read
one real answer surrounded by 404s, which describes no deployment that
exists. These tests pin the tree being answered as a whole, and pin the
credential material being a per-request canary rather than a literal.
"""
from __future__ import annotations

import json

import pytest

from flux import server as tbenv

# The shared fixture, not a local one: every trap below is canary-bearing,
# and the dispatch gate only serves those when an API key is set. A
# hand-rolled client that sets up the log path alone leaves the key unset,
# so the whole lane 404s and the end-to-end checks here measure the
# fixture rather than the table. It also stubs the outbound issuance call,
# which keeps these tests offline.
from .test_server import flux_client  # noqa: F401


NEW_PATHS = [
    "/amplify_outputs.json",
    "/src/amplify_outputs.json",
    "/public/amplify_outputs.json",
    "/assets/amplify_outputs.json",
    "/amplify/.config/local-aws-info.json",
    "/amplify/team-provider-info.json",
    "/AwsCredentials.properties",
    "/aws/AwsCredentials.properties",
    "/WEB-INF/AwsCredentials.properties",
    "/WEB-INF/classes/AwsCredentials.properties",
]

TRAP_NAMES = {
    "aws-amplify-outputs-json",
    "aws-amplify-local-aws-info",
    "aws-amplify-team-provider-info",
    "aws-credentials-properties",
}


def _trap(name):
    for trap in tbenv.CANARY_TRAPS:
        if trap.name == name:
            return trap
    raise AssertionError(f"no trap named {name}")


def test_every_new_trap_is_registered():
    registered = {t.name for t in tbenv.CANARY_TRAPS}
    assert TRAP_NAMES <= registered


def test_every_new_path_is_claimed_exactly_once():
    """Two traps answering one path means which renderer runs depends on
    table order, which is the drift this check exists to stop."""
    for path in NEW_PATHS:
        owners = [t.name for t in tbenv.CANARY_TRAPS if path.lower() in
                  tuple(p.lower() for p in t.paths)]
        assert len(owners) == 1, f"{path} claimed by {owners}"


def test_new_traps_request_the_aws_canary():
    for name in TRAP_NAMES:
        assert _trap(name).canary_types == ("aws",)


# --------------------------------------------------------------------------
# rendered content
# --------------------------------------------------------------------------

CANARY = {"aws": {
    "awsAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "awsSessionToken": "FwoGZXIvYXdzEEXAMPLETOKEN",
}}


def test_local_aws_info_carries_the_canary_where_the_cli_writes_it():
    doc = json.loads(tbenv.render_amplify_local_aws_info(CANARY))
    for env in doc.values():
        assert env["configLevel"] == "project"
        assert env["config"]["accessKeyId"] == CANARY["aws"]["awsAccessKeyId"]
        assert env["config"]["secretAccessKey"] == CANARY["aws"]["awsSecretAccessKey"]


def test_team_provider_info_carries_stack_inventory_and_the_canary():
    doc = json.loads(tbenv.render_amplify_team_provider_info(CANARY))
    cfn = doc["prod"]["awscloudformation"]
    assert cfn["accessKeyId"] == CANARY["aws"]["awsAccessKeyId"]
    assert cfn["StackName"] and cfn["DeploymentBucketName"]


def test_amplify_outputs_matches_the_current_generation_shape():
    doc = json.loads(tbenv.render_amplify_outputs_json(CANARY))
    # Gen-2 keys, not the `aws_exports` spelling of the previous one.
    assert doc["auth"]["user_pool_id"]
    assert doc["storage"]["access_key_id"] == CANARY["aws"]["awsAccessKeyId"]
    assert doc["data"]["api_key"].startswith("da2-")


def test_credentials_properties_is_java_property_syntax():
    text = tbenv.render_aws_credentials_properties(CANARY).decode()
    assert "accessKey=" + CANARY["aws"]["awsAccessKeyId"] in text
    assert "secretKey=" + CANARY["aws"]["awsSecretAccessKey"] in text
    # Property files are `key=value`; JSON here would be the tell.
    assert not text.lstrip().startswith("{")


def test_appsync_key_is_per_hit_unique():
    """A shared key would be the same string on every host running this."""
    keys = {
        json.loads(tbenv.render_amplify_outputs_json(CANARY))["data"]["api_key"]
        for _ in range(16)
    }
    assert len(keys) == 16


def test_renderers_embed_no_fixed_credential_literal():
    """Every secret-shaped field must come from the canary or be per-hit
    random — never a literal baked into the renderer."""
    blank = {"aws": {}}
    for render in (
        tbenv.render_amplify_local_aws_info,
        tbenv.render_amplify_team_provider_info,
        tbenv.render_amplify_outputs_json,
        tbenv.render_aws_credentials_properties,
    ):
        text = render(blank).decode()
        assert "AKIA" not in text, render.__name__
        # The only secret-shaped value left with no canary supplied is
        # the per-hit AppSync key, which is random by construction.
        assert CANARY["aws"]["awsSecretAccessKey"] not in text


# --------------------------------------------------------------------------
# served end to end
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", NEW_PATHS)
async def test_path_is_served_rather_than_404(flux_client, path):
    response = await flux_client.get(path)
    assert response.status != 404, path


async def test_previous_generation_configs_still_answer(flux_client):
    """The two files this lane was built around must not have been
    displaced by the new table entries."""
    for path in ("/amplifyconfiguration.json", "/aws-exports.js"):
        assert (await flux_client.get(path)).status != 404, path
