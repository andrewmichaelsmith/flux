"""The Terraform `.tf` source tree.

Flux answered `terraform.tfstate` and `terraform.tfvars` — the files that
hold Terraform's *values* — while 404ing every `.tf` file that declares
and references them. These tests pin the three properties that make the
tree worth serving:

1. every member resolves, and resolves to a result tag that names which
   part of the tree was read;
2. the tree is internally consistent, so a reader that parses rather than
   greps is steered to the value files by name;
3. the structural members hold nothing secret-shaped, and the two
   provider members carry a per-hit-unique canary — never a fixed
   literal.
"""
import pytest

import flux.server as tbenv

from tests.test_server import FAKE_TRACEBIT


# (path, expected result tag)
MUST_MATCH = [
    ("/variables.tf", "terraform-hcl-variables"),
    ("/variable.tf", "terraform-hcl-variables"),
    ("/vars.tf", "terraform-hcl-variables"),
    ("/terraform/variables.tf", "terraform-hcl-variables"),
    ("/infra/variables.tf", "terraform-hcl-variables"),
    ("/infrastructure/variables.tf", "terraform-hcl-variables"),
    ("/ops/variables.tf", "terraform-hcl-variables"),
    ("/deploy/variables.tf", "terraform-hcl-variables"),
    ("/main.tf", "terraform-hcl-main"),
    ("/terraform/main.tf", "terraform-hcl-main"),
    ("/infra/main.tf", "terraform-hcl-main"),
    ("/providers.tf", "terraform-hcl-providers"),
    ("/provider.tf", "terraform-hcl-providers"),
    ("/aws.tf", "terraform-hcl-providers"),
    ("/terraform/providers.tf", "terraform-hcl-providers"),
    ("/ovh.tf", "terraform-hcl-provider-ovh"),
    ("/terraform/ovh.tf", "terraform-hcl-provider-ovh"),
    ("/infra/ovh.tf", "terraform-hcl-provider-ovh"),
    ("/backend.tf", "terraform-hcl-backend"),
    ("/state.tf", "terraform-hcl-backend"),
    ("/outputs.tf", "terraform-hcl-outputs"),
    ("/output.tf", "terraform-hcl-outputs"),
    ("/versions.tf", "terraform-hcl-versions"),
    ("/version.tf", "terraform-hcl-versions"),
]

MUST_NOT_MATCH = [
    # Not a Terraform file; `.tf` is also a TrueType/other extension and
    # an arbitrary parent must not drag a member into scope.
    "/wp-content/uploads/variables.tf",
    "/assets/fonts/main.tf",
    "/random/deep/path/outputs.tf",
    "/variables.tfx",
    "/variables.t",
    "/notvariables.tf",
    "/variablestf",
    "/.tf",
]


@pytest.mark.parametrize("path,tag", MUST_MATCH)
def test_every_member_resolves_to_its_own_result_tag(path, tag):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} does not resolve"
    assert trap.name == tag


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_non_members_do_not_resolve(path):
    assert tbenv._TRAP_BY_PATH.get(path.lower()) is None, path


def test_the_tree_is_distinguishable_in_the_log():
    """Seven members, seven tags — a walk through the tree reads as a
    sequence rather than one undifferentiated `terraform` hit."""
    tags = {trap.name for _p, trap in tbenv._TRAP_BY_PATH.items()
            if trap.name.startswith("terraform-hcl-")}
    assert len(tags) == 7, sorted(tags)


# --- internal consistency -------------------------------------------------

def test_variables_declares_what_main_references():
    """A reader that parses the tree gets a project that hangs together:
    every `var.X` main.tf references is declared in variables.tf."""
    import re
    variables = tbenv.render_tf_variables({}).decode("utf-8")
    main = tbenv.render_tf_main({}).decode("utf-8")
    declared = set(re.findall(r'variable\s+"([^"]+)"', variables))
    referenced = set(re.findall(r'\bvar\.([a-z_]+)', main))
    assert referenced, "main.tf references no variables"
    assert referenced <= declared, referenced - declared


def test_backend_names_the_state_object_the_tfstate_trap_answers():
    """`backend.tf` is the file that steers a reader to remote state, and
    the object it names must be the one Flux already serves a canary
    from — otherwise the chain dead-ends."""
    backend = tbenv.render_tf_backend({}).decode("utf-8")
    assert "terraform.tfstate" in backend
    assert tbenv._TRAP_BY_PATH.get("/terraform.tfstate") is not None


def test_variables_names_the_secrets_the_value_file_supplies():
    """variables.tf declares the names; terraform.tfvars supplies them.
    The overlap is what makes the first file worth reading."""
    import re
    variables = tbenv.render_tf_variables({}).decode("utf-8")
    tfvars = tbenv.render_terraform_tfvars(FAKE_TRACEBIT).decode("utf-8")
    declared = set(re.findall(r'variable\s+"([^"]+)"', variables))
    assigned = set(re.findall(r'^([a-z_]+)\s*=', tfvars, re.M))
    assert assigned <= declared, assigned - declared


def test_every_structural_member_is_valid_hcl_shaped():
    """Braces balance and every block is closed — a harvester that feeds
    the file to a parser must not get a syntax error."""
    for render in (tbenv.render_tf_variables, tbenv.render_tf_main,
                   tbenv.render_tf_backend, tbenv.render_tf_outputs,
                   tbenv.render_tf_versions):
        body = render({}).decode("utf-8")
        assert body.count("{") == body.count("}"), render.__name__
        assert body.endswith("}\n"), render.__name__


# --- credential placement -------------------------------------------------

STRUCTURAL = (
    "terraform-hcl-variables",
    "terraform-hcl-main",
    "terraform-hcl-backend",
    "terraform-hcl-outputs",
    "terraform-hcl-versions",
)
CANARY_BEARING = ("terraform-hcl-providers", "terraform-hcl-provider-ovh")


@pytest.mark.parametrize("name", STRUCTURAL)
def test_structural_members_spend_no_canary(name):
    """A correct `variables.tf` declares `sensitive = true` and holds no
    values. Declaring the canary types empty is what keeps the secrets in
    the value files instead of spreading them over the whole tree."""
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    assert trap.canary_types == ()


@pytest.mark.parametrize("name", CANARY_BEARING)
def test_provider_members_request_a_canary(name):
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    assert trap.canary_types == ("aws",)


@pytest.mark.parametrize("name", STRUCTURAL)
def test_structural_members_emit_no_canary_material(name):
    """Even handed a populated canary, a structural renderer must not
    leak it — the `sensitive = true` declarations carry no values."""
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    body = trap.render(FAKE_TRACEBIT).decode("utf-8")
    for secret in (FAKE_TRACEBIT["aws"]["awsAccessKeyId"],
                   FAKE_TRACEBIT["aws"]["awsSecretAccessKey"],
                   FAKE_TRACEBIT["aws"]["awsSessionToken"]):
        assert secret not in body, f"{name} leaked canary material"


@pytest.mark.parametrize("name", CANARY_BEARING)
def test_provider_members_carry_the_canary(name):
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    body = trap.render(FAKE_TRACEBIT).decode("utf-8")
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"] in body
    assert FAKE_TRACEBIT["aws"]["awsSecretAccessKey"] in body
    assert FAKE_TRACEBIT["aws"]["awsSessionToken"] in body


@pytest.mark.parametrize("name", CANARY_BEARING)
def test_provider_members_hold_no_credential_without_a_canary(name):
    """With no canary issued the key fields render empty rather than
    falling back to a literal — nothing fixed ships across the fleet."""
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == name)
    body = trap.render({}).decode("utf-8")
    for line in body.splitlines():
        if any(k in line for k in ("access_key", "secret_key", "token",
                                   "application_key", "application_secret",
                                   "consumer_key")):
            assert line.strip().endswith('= ""'), line
