"""Tests for the Django/Flask entry-point module chain.

The chain is two steps. Step one answers the module a Python deployment
is *started* from — `manage.py`, `wsgi.py`, `asgi.py`, `app.py`,
`environment.py` — and the only thing of value in that body is the
`DJANGO_SETTINGS_MODULE` line, because a deployment's project package
name is written down nowhere else. Step two answers the
`/<project>/settings.py` that line points at.

That makes the second request the measurement. The package name is an
HMAC of the calling address under a per-process secret, so the name a
caller is given is in no wordlist, is not shared between deployments and
cannot be reached by enumeration: asking for it is evidence the caller
parsed the module rather than replaying a path list, which is the one
thing a fixed-prefix table cannot show. A vocabulary name this process
never issued to this address is tagged separately — that is the shape a
cross-deployment replay takes.

The family is keyless: the entry points carry no credential and mint
nothing, so it spends no issuance quota.
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

LEAVES = ("manage.py", "wsgi.py", "asgi.py", "app.py", "environment.py")

CLIENT_A = "203.0.113.7"
CLIENT_B = "198.51.100.9"


def _render(path, client_ip=CLIENT_A):
    return tbenv.render_django_entrypoint(
        {**AWS, "_clientIp": client_ip, "_requestPath": path}
    ).decode("utf-8")


# --- step one: the entry-point modules resolve -------------------------

@pytest.mark.parametrize("leaf", LEAVES)
def test_webroot_leaf_resolves_to_entrypoint(leaf):
    trap = tbenv.find_canary_trap(f"/{leaf}")
    assert trap is not None, f"/{leaf} must be answered"
    assert trap.name == "django-entrypoint"


@pytest.mark.parametrize("leaf", LEAVES)
@pytest.mark.parametrize("prefix", tbenv._APP_LAYOUT_CRED_PREFIXES)
def test_layout_prefixed_leaf_resolves_to_entrypoint(prefix, leaf):
    trap = tbenv.find_canary_trap(f"/{prefix}/{leaf}")
    assert trap is not None, f"/{prefix}/{leaf} must be answered"
    assert trap.name == "django-entrypoint"


def test_entrypoint_mints_nothing():
    """Keyless by construction — the body holds no credential, so the
    family must declare no canary types and spend no issuance quota."""
    trap = tbenv.find_canary_trap("/manage.py")
    assert trap.canary_types == ()


@pytest.mark.parametrize("leaf", LEAVES)
def test_each_leaf_renders_its_own_shape(leaf):
    """A `wsgi.py` whose body is a `manage.py` is a tell to anything that
    reads past the first line."""
    body = _render(f"/{leaf}")
    if leaf == "wsgi.py":
        assert "get_wsgi_application" in body
        assert "get_asgi_application" not in body
    elif leaf == "asgi.py":
        assert "get_asgi_application" in body
        assert "get_wsgi_application" not in body
    elif leaf == "manage.py":
        assert "execute_from_command_line" in body


@pytest.mark.parametrize("leaf", LEAVES)
def test_every_leaf_names_the_settings_module(leaf):
    """Naming the settings module is the whole point of the body.

    Flask's `app.py` names it in a `from_object` call rather than an
    environment default, so the invariant that holds across all five is
    the `<project>.settings` string itself, not the Django env var.
    """
    body = _render(f"/{leaf}")
    project = tbenv._django_project_for_client(CLIENT_A)
    assert f"{project}.settings" in body
    if leaf != "app.py":
        assert "DJANGO_SETTINGS_MODULE" in body


def test_no_credential_shaped_literal_in_any_leaf():
    """Nothing credential-shaped may appear in a keyless body."""
    for leaf in LEAVES:
        body = _render(f"/{leaf}")
        assert "AKIA" not in body
        assert AWS["aws"]["awsSecretAccessKey"] not in body


# --- the per-client project name --------------------------------------

def test_project_name_is_stable_per_client():
    """A caller that reads the module over one connection and asks for
    the settings file over another must agree with itself."""
    assert (tbenv._django_project_for_client(CLIENT_A)
            == tbenv._django_project_for_client(CLIENT_A))


def test_project_name_is_drawn_from_the_vocabulary():
    assert (tbenv._django_project_for_client(CLIENT_A)
            in tbenv._DJANGO_PROJECT_NAMES)


def test_project_vocabulary_is_disjoint_from_layout_prefixes():
    """Safety property: the chain can only ever add a route, never move
    one the app-config table already owns."""
    owned = {"app", "core", "backend", "src", "project", "config",
             "instance"}
    assert not (set(tbenv._DJANGO_PROJECT_NAMES) & owned)
    assert not (set(tbenv._DJANGO_PROJECT_NAMES)
                & set(tbenv._APP_LAYOUT_CRED_PREFIXES))


def test_missing_client_ip_still_renders():
    body = _render("/manage.py", client_ip="")
    assert "DJANGO_SETTINGS_MODULE" in body


# --- step two: the settings module the entry point named --------------

def test_named_project_is_tagged_named():
    issued = tbenv._django_project_for_client(CLIENT_A)
    trap, requested, got = tbenv.resolve_django_settings_module(
        f"/{issued}/settings.py", CLIENT_A
    )
    assert trap is not None
    assert trap.name == "django-settings-named"
    assert requested == issued == got


def test_foreign_vocabulary_name_is_tagged_foreign():
    """A vocabulary name this address was never given — the
    cross-deployment-replay shape, and also what sweeping the
    vocabulary looks like."""
    issued = tbenv._django_project_for_client(CLIENT_A)
    other = next(n for n in tbenv._DJANGO_PROJECT_NAMES if n != issued)
    trap, requested, got = tbenv.resolve_django_settings_module(
        f"/{other}/settings.py", CLIENT_A
    )
    assert trap is not None
    assert trap.name == "django-settings-foreign"
    assert requested == other
    assert got == issued


def test_same_path_discriminates_across_two_clients():
    """The discriminator is the pairing of name to caller, not the path:
    one spelling must read `named` for the address it was issued to and
    `foreign` for another."""
    a = tbenv._django_project_for_client(CLIENT_A)
    b = tbenv._django_project_for_client(CLIENT_B)
    if a == b:
        pytest.skip("both test addresses drew the same project name")
    path = f"/{a}/settings.py"
    assert tbenv.resolve_django_settings_module(path, CLIENT_A)[0].name == (
        "django-settings-named")
    assert tbenv.resolve_django_settings_module(path, CLIENT_B)[0].name == (
        "django-settings-foreign")


def test_non_vocabulary_project_name_refuses():
    trap, _, _ = tbenv.resolve_django_settings_module(
        "/zzzz/settings.py", CLIENT_A
    )
    assert trap is None


def test_deeper_spelling_refuses():
    """Exact two-segment shape only — a project name is not a layout
    directory, and a deeper spelling is the layout walk's business."""
    issued = tbenv._django_project_for_client(CLIENT_A)
    trap, _, _ = tbenv.resolve_django_settings_module(
        f"/a/{issued}/settings.py", CLIENT_A
    )
    assert trap is None


def test_bare_settings_py_is_not_this_family():
    """`/settings.py` and `/config.py` keep their own table entry."""
    trap, _, _ = tbenv.resolve_django_settings_module(
        "/settings.py", CLIENT_A
    )
    assert trap is None
    assert tbenv.find_canary_trap("/settings.py").name == "app-config-python"
    assert tbenv.find_canary_trap("/config.py").name == "app-config-python"


def test_settings_module_target_helper():
    issued = tbenv._django_project_for_client(CLIENT_A)
    assert tbenv._django_settings_module_target(
        f"/{issued}/settings.py") == issued
    assert tbenv._django_settings_module_target("/settings.py") is None
    assert tbenv._django_settings_module_target("/zzzz/settings.py") is None
    assert tbenv._django_settings_module_target(
        f"/{issued}/config.py") is None


def test_settings_module_match_is_case_insensitive():
    issued = tbenv._django_project_for_client(CLIENT_A)
    assert tbenv._django_settings_module_target(
        f"/{issued.upper()}/SETTINGS.PY") == issued


def test_both_settings_traps_are_indistinguishable_but_for_the_tag():
    """Only the result tag may differ.

    The two traps must share renderer, canary types and content type, so
    a caller cannot tell from the response which tag it earned — if it
    could, the tag would itself be a fingerprint. Note the bodies are
    deliberately NOT byte-equal across calls: `render_python_settings`
    mints a per-hit `SECRET_KEY` and DB password, which is the
    every-credential-is-per-hit-unique rule, so sameness is asserted on
    the renderer rather than its output.
    """
    named = tbenv.DJANGO_SETTINGS_NAMED_TRAP
    foreign = tbenv.DJANGO_SETTINGS_FOREIGN_TRAP
    assert named.canary_types == foreign.canary_types == ("aws",)
    assert named.render is foreign.render
    assert named.content_type == foreign.content_type


def test_settings_body_carries_no_fixed_secret():
    """Two reads of the same route must not share a credential."""
    r = {**AWS, "_clientIp": CLIENT_A, "_requestPath": "/x/settings.py"}
    a = tbenv.DJANGO_SETTINGS_NAMED_TRAP.render(dict(r)).decode("utf-8")
    b = tbenv.DJANGO_SETTINGS_NAMED_TRAP.render(dict(r)).decode("utf-8")
    assert a != b, "a fixed literal would make these identical"
    assert "SECRET_KEY" in a


# --- the enable gate ---------------------------------------------------

def test_disabled_removes_the_entrypoint_route(monkeypatch):
    """Gated at the single lookup seam, so the switch covers the layout
    walk and every other caller, not just the exact-match route."""
    monkeypatch.setattr(tbenv, "DJANGO_ENTRYPOINT_ENABLED", False)
    assert tbenv.find_canary_trap("/manage.py") is None
    assert tbenv.find_canary_trap("/app/wsgi.py") is None


def test_disabled_removes_the_settings_chain(monkeypatch):
    issued = tbenv._django_project_for_client(CLIENT_A)
    monkeypatch.setattr(tbenv, "DJANGO_ENTRYPOINT_ENABLED", False)
    trap, _, _ = tbenv.resolve_django_settings_module(
        f"/{issued}/settings.py", CLIENT_A
    )
    assert trap is None


def test_disabled_leaves_the_app_config_table_alone(monkeypatch):
    """The gate must not take the neighbouring family down with it."""
    monkeypatch.setattr(tbenv, "DJANGO_ENTRYPOINT_ENABLED", False)
    assert tbenv.find_canary_trap("/settings.py").name == "app-config-python"


def test_canary_traps_disabled_refuses_the_chain(monkeypatch):
    issued = tbenv._django_project_for_client(CLIENT_A)
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", False)
    trap, _, _ = tbenv.resolve_django_settings_module(
        f"/{issued}/settings.py", CLIENT_A
    )
    assert trap is None


def test_enabled_by_default():
    assert tbenv.DJANGO_ENTRYPOINT_ENABLED is True


# --- route-table integrity --------------------------------------------

def test_entrypoint_adds_no_duplicate_paths():
    seen = {}
    for trap in tbenv.CANARY_TRAPS:
        for p in trap.paths:
            assert p not in seen, (
                f"{p} claimed by both {seen.get(p)} and {trap.name}"
            )
            seen[p] = trap.name
