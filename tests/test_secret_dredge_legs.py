"""Three unreachable legs of one secret-dredging sweep.

The sweeps that walk credential dictionaries do not stop at `.env`. The
same pass asks for CI/CD pipeline descriptors, for a container's
projected cluster identity, and for arbitrary files through whatever
fetch-shaped endpoint the app exposes. Each of those had a leg that
could not be reached:

1. **Scheme-less reads.** The relay entry paths recognised
   `url=file:///app/.env` but not the far more common `file=../../.env`.
   The candidate filter required a URL scheme, so the plain spelling
   fell out of the list entirely and was answered as an unrecognised
   request — even though the document behind it already had a renderer.
   This is the subtle one: the fix must widen the read spelling *without*
   turning the endpoint into an open proxy and without letting an
   unresolved read shadow a metadata host named by a later parameter.

2. **The projected service-account volume.** A read primitive aimed at
   `…/kubernetes.io/serviceaccount/token` reached the read handler and
   missed, because the system-file table held only the three `/etc`
   entries.

3. **CI/CD leaves.** Hosted-CI descriptors whose siblings were all
   present (Travis beside appveyor/drone/circleci), the publish workflow
   beside release, and the `<dotdir>/<name>.env` spelling that the
   ordinary webroot prefixes already answered.
"""
import json

import pytest

from flux import server as tbenv
from .test_server import FAKE_TRACEBIT, _fake_canary, flux_client  # noqa: F401


@pytest.fixture
def canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    # Bare `/.env` predates the trap table and still calls the issuing
    # function directly, so a read that resolves onto it misses the
    # patch above. The scheme-less-read test lands there by design.
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)


# --- 1. scheme-less reads on the relay entry paths -----------------------

SCHEMELESS_READS = [
    "file=../../.env",
    "file=../../../../etc/passwd",
    "file=../../.aws/credentials",
    "path=/etc/passwd",
    "file=..\\..\\.env",
    # Double-encoded: the transport decodes once, the fetcher again.
    "file=%2e%2e%2f%2e%2e%2f.env",
]


@pytest.mark.parametrize("query", SCHEMELESS_READS)
@pytest.mark.parametrize("entry", ["/download", "/read", "/proxy", "/fetch"])
def test_schemeless_read_resolves_to_a_document(entry, query):
    relay = tbenv.resolve_ssrf_relay(entry, query)
    assert relay is not None, "the read spelling was not recognised at all"
    assert relay.cloud == "file"
    assert relay.fs is not None and relay.fs.resolved, (
        "recognised but no document behind it"
    )


def test_schemeless_read_still_refuses_a_remote_target():
    """The widened filter must not make this an open proxy. A remote
    authority is still not something we answer."""
    assert tbenv.resolve_ssrf_relay("/proxy", "url=http://example.com/") is None


def test_protocol_relative_target_still_reaches_the_host_table():
    """`//169.254.169.254/…` names an authority, not a file. If the read
    branch claimed it, the metadata resolver would never see it."""
    relay = tbenv.resolve_ssrf_relay(
        "/proxy", "url=//169.254.169.254/latest/meta-data/"
    )
    assert relay is not None and relay.cloud == "aws"


def test_unresolved_read_does_not_shadow_a_later_metadata_param():
    """A file we do not furnish is held back, not returned on the spot,
    so a metadata host named by a later parameter still wins."""
    relay = tbenv.resolve_ssrf_relay(
        "/fetch",
        "file=/no/such/file/here&url=http://169.254.169.254/latest/meta-data/",
    )
    assert relay is not None and relay.cloud == "aws"


def test_unresolved_read_is_reported_as_a_miss_not_a_hit():
    relay = tbenv.resolve_ssrf_relay("/download", "redirect=/home")
    assert relay is not None and relay.cloud == "file"
    assert relay.fs is not None and not relay.fs.resolved


def test_schemeless_read_is_only_honoured_on_a_relay_entry_path():
    assert tbenv.resolve_ssrf_relay("/not-an-entry-path", "file=../../.env") is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("../../.env", True),
        ("/etc/passwd", True),
        ("..\\..\\web.config", True),
        ("//example.com/a", False),   # protocol-relative authority
        ("http://example.com/", False),
        ("plain-value", False),
        ("", False),
    ],
)
def test_local_path_value_classifier(value, expected):
    assert tbenv._is_local_path_value(value) is expected


async def test_schemeless_read_serves_the_env_canary_over_http(flux_client, canary):
    resp = await flux_client.get(
        "/download?file=../../.env", headers={"X-Forwarded-For": "203.0.113.20"}
    )
    assert resp.status == 200
    body = (await resp.read()).decode("utf-8")
    aws = FAKE_TRACEBIT["aws"]
    assert aws["awsAccessKeyId"] in body


# --- 2. the projected service-account volume ----------------------------

K8S_ROOTS = ["/var/run", "/run"]


@pytest.mark.parametrize("root", K8S_ROOTS)
@pytest.mark.parametrize("leaf", ["token", "namespace", "ca.crt"])
def test_service_account_volume_is_registered(root, leaf):
    path = f"{root}/secrets/kubernetes.io/serviceaccount/{leaf}"
    assert path in tbenv._VITE_FS_SYSTEM_FILES


@pytest.mark.parametrize("root", K8S_ROOTS)
def test_service_account_token_resolves_through_the_read_primitive(root):
    target = tbenv.resolve_fs_read(
        f"{root}/secrets/kubernetes.io/serviceaccount/token"
    )
    assert target.system_file, "read primitive missed the projected volume"


def test_service_account_token_is_a_three_segment_jwt():
    token = tbenv.render_fake_k8s_sa_token().decode("ascii")
    header_b64, claims_b64, signature = token.split(".")
    assert signature
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    import base64

    header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
    claims = json.loads(base64.urlsafe_b64decode(pad(claims_b64)))
    assert header["alg"] == "RS256"
    assert claims["sub"].startswith("system:serviceaccount:")
    assert claims["exp"] > claims["iat"]
    assert claims["kubernetes.io"]["namespace"] == tbenv.K8S_SA_NAMESPACE


def test_service_account_token_is_unique_per_hit():
    """A fixed bearer would ship the same string from every deployment
    and make replay unattributable. This is the rule the whole trap
    surface is built on, so it is asserted, not assumed."""
    tokens = {tbenv.render_fake_k8s_sa_token() for _ in range(8)}
    assert len(tokens) == 8


def test_service_account_ca_cert_is_pem_and_not_fleet_constant():
    first = tbenv.render_fake_k8s_sa_ca_cert().decode("ascii")
    assert first.startswith("-----BEGIN CERTIFICATE-----")
    assert first.rstrip().endswith("-----END CERTIFICATE-----")
    assert first != tbenv.render_fake_k8s_sa_ca_cert().decode("ascii")


def test_service_account_namespace_matches_the_token_claim():
    """The three files describe one pod; a reader that pulls all of them
    must not see two different namespaces."""
    namespace = tbenv.render_fake_k8s_sa_namespace().decode("ascii")
    assert namespace == tbenv.K8S_SA_NAMESPACE
    token = tbenv.render_fake_k8s_sa_token().decode("ascii")
    import base64

    claims_b64 = token.split(".")[1]
    claims = json.loads(
        base64.urlsafe_b64decode(claims_b64 + "=" * (-len(claims_b64) % 4))
    )
    assert claims["kubernetes.io"]["namespace"] == namespace


def test_service_account_files_do_not_shadow_a_credential_trap():
    """System files are consulted only after the credential walk misses."""
    target = tbenv.resolve_fs_read("/var/run/secrets/kubernetes.io/serviceaccount/../../../../.env")
    assert not target.system_file


# --- 3. CI/CD leaves ----------------------------------------------------

@pytest.mark.parametrize(
    "path,expected_trap",
    [
        ("/.travis.yml", "generic-ci-config"),
        ("/.travis.yaml", "generic-ci-config"),
        ("/cloudbuild.yaml", "generic-ci-config"),
        ("/cloudbuild.yml", "generic-ci-config"),
        ("/.github/workflows/publish.yml", "github-actions-workflow"),
        ("/.github/workflows/publish.yaml", "github-actions-workflow"),
        ("/.github/secrets.env", "env-production"),
        ("/.github/keys.env", "env-production"),
        ("/.github/.env", "env-production"),
        ("/.config/secrets.env", "env-production"),
    ],
)
def test_ci_leaf_is_registered(path, expected_trap):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} has no trap entry"
    assert trap.name == expected_trap


@pytest.mark.parametrize(
    "path",
    [
        "/.travis.yml",
        "/cloudbuild.yaml",
        "/.github/workflows/publish.yml",
        "/.github/secrets.env",
    ],
)
async def test_ci_leaf_serves_a_canary(flux_client, canary, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.21"})
    assert resp.status == 200
    body = (await resp.read()).decode("utf-8")
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"] in body


@pytest.mark.parametrize("path", ["/.github/secrets.env", "/.config/secrets.env"])
def test_dotdir_env_leaf_is_exempt_from_the_tarpit(path):
    """`is_tarpit_path` claims `.env`-shaped leaves and exempts only
    those carrying a trap entry. Without the exemption these return a
    redirect chain and never issue a canary — a 200-shaped regression
    that a status assertion alone would not catch."""
    assert not tbenv.is_tarpit_path(path)


def test_unrelated_yaml_still_404s():
    """The expansion is a named-leaf list, not a `*.yml` catch-all."""
    assert tbenv._TRAP_BY_PATH.get("/random-file.yml") is None
