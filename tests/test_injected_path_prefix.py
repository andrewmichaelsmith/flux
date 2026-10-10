"""Path-generator leakage in the first segment.

Credential dictionaries arrive carrying a fragment of the context they
were expanded in, pasted into the path where a directory would go:

    /~/.boto            an unexpanded home-directory reference
    /$(pwd)/.env        command substitution that no shell ever ran
    /localhost/.env     a host concatenated into the path component
    /:443/.env          the same mistake one component further on

None of these is a directory any server has, so every one of them used to
404 -- on families this honeypot has already built and would happily have
answered under the unprefixed spelling. These tests pin two properties:
the prefix is stripped before dispatch so the existing family answers,
and a path that only *looks* like one of these shapes is left alone.
"""
import pytest

import flux.server as tbenv
from tests.test_server import flux_client, _log_entries  # noqa: F401


# --- the strip itself ---------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("/~/.boto", "/.boto"),
    ("/~/.netrc", "/.netrc"),
    ("/~/.aws/credentials", "/.aws/credentials"),
    ("/$(pwd)/.env", "/.env"),
    ("/$(pwd)/terraform.tfstate", "/terraform.tfstate"),
    ("/$(pwd)/docker-compose.yml", "/docker-compose.yml"),
    ("/localhost/.env", "/.env"),
    ("/:443/.env", "/.env"),
    ("/:80/.env", "/.env"),
    ("/:8080/wp-config.php", "/wp-config.php"),
    ("/:8443/wp-config.php", "/wp-config.php"),
])
def test_injected_prefix_is_stripped(raw, expected):
    assert tbenv.normalize_path(raw) == expected


@pytest.mark.parametrize("raw", [
    # Percent-encoded, which is how the segment arrives about as often as
    # it arrives literally.
    "/%24%28pwd%29/.env",
    "/%7e/.env",
])
def test_injected_prefix_is_stripped_after_decoding(raw):
    assert tbenv.normalize_path(raw) == "/.env"


def test_stacked_prefixes_are_stripped():
    """One template pasting twice. Bounded, but more than one."""
    assert tbenv.normalize_path("/~/$(pwd)/.env") == "/.env"


def test_strip_is_bounded():
    """A sender choosing the repeat count does not choose our work."""
    deep = "/~" * 50 + "/.env"
    out = tbenv.normalize_path(deep)
    assert out.endswith("/.env")
    # Exactly MAX_STRIPS segments came off, not all 50.
    assert out.count("~") == 50 - tbenv._INJECTED_PREFIX_MAX_STRIPS


# --- what must NOT be stripped -----------------------------------------

@pytest.mark.parametrize("raw", [
    # A real per-user webroot. `~` only leaks as a whole segment.
    "/~alice/.env",
    "/~bob/public_html/.env",
    # A plausible subdirectory keeps routing as the subdirectory request
    # it might really be.
    "/blog/.env",
    "/localhost2/.env",
    "/localhosting/.env",
])
def test_plausible_paths_are_untouched(raw):
    assert tbenv.normalize_path(raw) == raw


@pytest.mark.parametrize("raw", [
    # The daemon-API trap reads a colon-port as the point of the request,
    # not as noise. A service port must survive to reach it.
    "/:2375/containers/json",
    "/:9000/.env",
    "/:22/.env",
    "/:3306/.env",
])
def test_service_ports_survive_for_the_traps_that_read_them(raw):
    assert tbenv.normalize_path(raw) == raw


def test_only_web_ports_are_in_the_strip_set():
    """Pins the closed set. Widening it to a `\\d{1,5}` range is what
    deletes the SSRF signal, so the narrowness is the invariant."""
    assert tbenv._INJECTED_WEB_PORTS == ("80", "443", "8080", "8443")


# --- the payoff: existing families now answer these spellings ----------

@pytest.mark.parametrize("raw,family", [
    ("/~/.boto", "boto-config"),
    ("/~/.netrc", "netrc"),
    ("/~/.s3cfg", "s3cfg"),
    ("/~/.git-credentials", "git-credentials"),
    ("/~/.aws/credentials", "aws-credentials-file"),
    ("/~/.aws/config", "aws-config-file"),
    ("/$(pwd)/terraform.tfstate", "terraform-tfstate"),
    ("/$(pwd)/docker-compose.yml", "docker-compose"),
    ("/$(pwd)/serverless.yml", "serverless-config"),
    ("/$(pwd)/netlify.toml", "app-config-toml"),
    ("/$(pwd)/package.json", "package-json"),
    ("/$(pwd)/.env.local", "env-production"),
    ("/:8443/wp-config.php", "wp-config"),
])
def test_prefixed_spelling_reaches_the_existing_family(raw, family):
    trap = tbenv._TRAP_BY_PATH.get(tbenv.normalize_path(raw).lower())
    assert trap is not None, f"{raw} still resolves to nothing"
    assert trap.name == family


def test_prefixed_env_reaches_the_env_canary_not_the_tarpit():
    """`/.env` is owned by a dedicated handler upstream of the trap
    table, so the assertion is about the tarpit NOT claiming it: a
    prefixed `.env` used to end `/.env`-suffixed and drip tarpit bytes
    instead of issuing a canary."""
    for raw in ("/$(pwd)/.env", "/localhost/.env", "/:443/.env"):
        norm = tbenv.normalize_path(raw)
        assert norm == "/.env", raw
        assert not tbenv.is_tarpit_path(norm), raw


def test_unprefixed_subdirectory_env_still_takes_the_tarpit():
    """The counterpart. `/blog/.env` is a directory that could exist, so
    its existing tarpit routing is deliberately unchanged."""
    assert tbenv.is_tarpit_path(tbenv.normalize_path("/blog/.env"))


# --- the log field -----------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("/~/.boto", "~"),
    ("/$(pwd)/.env", "$(pwd)"),
    ("/%24%28pwd%29/.env", "$(pwd)"),
    ("/localhost/.env", "localhost"),
    ("/:443/.env", ":443"),
    ("/~/$(pwd)/.env", "~/$(pwd)"),
])
def test_the_stripped_segment_is_recoverable_for_the_log(raw, expected):
    assert tbenv._injected_prefix_of(raw) == expected


@pytest.mark.parametrize("raw", ["/.boto", "/blog/.env", "/~alice/.env", "/", ""])
def test_no_prefix_field_for_ordinary_paths(raw):
    """Presence of the field is the signal, so it must be absent -- not
    empty -- on every request that did not carry a leak."""
    assert tbenv._injected_prefix_of(raw) == ""


# --- end to end --------------------------------------------------------

async def test_prefixed_credential_path_issues_a_canary_and_logs_the_leak(
    flux_client,
):
    """The whole point, exercised through real dispatch: a spelling that
    used to 404 now serves the family body, and the row records both the
    spelling that arrived and the leak it carried."""
    resp = await flux_client.get(
        "/~/.aws/credentials", headers={"X-Forwarded-For": "203.0.113.7"}
    )
    assert resp.status == 200
    body = await resp.text()
    assert "aws_access_key_id" in body

    rows = [
        e for e in _log_entries(flux_client.log_path)
        if e.get("path") == "/.aws/credentials"
    ]
    assert rows, "no row logged for the normalized path"
    row = rows[-1]
    assert row["rawPath"] == "/~/.aws/credentials"
    assert row["injectedPathPrefix"] == "~"


async def test_ordinary_path_logs_no_prefix_field(flux_client):
    resp = await flux_client.get(
        "/.aws/credentials", headers={"X-Forwarded-For": "203.0.113.8"}
    )
    assert resp.status == 200
    rows = [
        e for e in _log_entries(flux_client.log_path)
        if e.get("path") == "/.aws/credentials"
    ]
    assert rows
    assert "injectedPathPrefix" not in rows[-1]
