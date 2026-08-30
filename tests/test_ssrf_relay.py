"""SSRF relay onto the cloud metadata tree.

The metadata trap answers requests that put a metadata path at our
webroot. This one answers the other way the same documents get asked
for: a URL-taking parameter on a fetch-style endpoint, pointed at the
link-local metadata address.

These tests pin the three things that make it worth having. It must fire
only when a parameter actually names a metadata host, so it can never
behave like an open proxy. It must serve byte-identical bodies to the
direct trap, because a relay that returns a wrapper is not followable.
And it must record the parameter spelling and the requested target,
because the dictionary the client is sweeping is as much the point as
the credential.
"""
import base64
import json
from urllib.parse import quote

import pytest
import pytest_asyncio

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


AWS_ROOT = "http://169.254.169.254/latest/meta-data/"
AWS_ROLE_LIST = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
GCP_TOKEN = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)


# --- Path resolution ---


@pytest.mark.parametrize("entry", sorted(tbenv._SSRF_RELAY_ENTRY_PATHS))
def test_every_entry_path_resolves(entry):
    resolved = tbenv.resolve_ssrf_relay(entry, f"url={AWS_ROOT}")
    assert resolved is not None, f"expected a match for {entry}"
    assert resolved.cloud == "aws"


@pytest.mark.parametrize("entry", sorted(tbenv._SSRF_RELAY_ENTRY_PATHS))
def test_entry_paths_tolerate_a_trailing_slash(entry):
    assert tbenv.resolve_ssrf_relay(entry + "/", f"url={AWS_ROOT}") is not None


@pytest.mark.parametrize("param", [
    "url", "uri", "path", "dest", "target", "u", "link", "src", "next",
    "redirect", "callback", "image_url", "webhook",
])
def test_any_parameter_spelling_is_accepted(param):
    """The client sweeps parameter names because it cannot know which one
    the app used. Pinning a fixed list of names would mean answering the
    guesses we happened to have seen and 404ing the rest, which throws
    away the enumeration signal the trap exists to collect."""
    resolved = tbenv.resolve_ssrf_relay("/fetch", f"{param}={AWS_ROOT}")
    assert resolved is not None
    assert resolved.param == param


@pytest.mark.parametrize("query", [
    # Percent-encoded once, as the observed sweeps send it.
    "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
    # Encoded twice — a filter grepping the wire for the literal address
    # misses this, but a fetcher that unquotes before dereferencing does
    # not, which is exactly why the bypass is used.
    "url=http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F",
    # Credentials in the authority: `http://trusted@169.254.169.254/`.
    "url=http://expected-host@169.254.169.254/latest/meta-data/",
    # Explicit port.
    "url=http://169.254.169.254:80/latest/meta-data/",
    # A second parameter carries the payload.
    "w=1200&url=http://169.254.169.254/latest/meta-data/",
])
def test_encoding_and_bypass_shapes_resolve(query):
    resolved = tbenv.resolve_ssrf_relay("/fetch", query)
    assert resolved is not None, f"expected a match for {query}"
    assert resolved.host == "169.254.169.254"


@pytest.mark.parametrize("host,cloud", [
    ("169.254.169.254", "aws"),
    ("169.254.170.2", "aws"),
    # Alibaba mirrors the EC2 layout at its own link-local address.
    ("100.100.100.200", "aws"),
    ("instance-data", "aws"),
    ("metadata.google.internal", "gcp"),
    ("metadata.goog", "gcp"),
])
def test_metadata_hosts_map_to_the_right_cloud(host, cloud):
    resolved = tbenv.resolve_ssrf_relay("/fetch", f"url=http://{host}/latest/meta-data/")
    assert resolved is not None
    assert resolved.cloud == cloud


@pytest.mark.parametrize("path,query", [
    # Not an entry path — a metadata URL parked on some other trap's path
    # must not be stolen from that trap.
    ("/.env", f"url={AWS_ROOT}"),
    ("/wp-login.php", f"url={AWS_ROOT}"),
    ("/latest/meta-data/", f"url={AWS_ROOT}"),
    # Entry path, but nothing that names a metadata host. These are the
    # cases that must fall through rather than turn flux into a proxy.
    ("/fetch", "url=http://example.com/"),
    ("/fetch", "url=https://raw.githubusercontent.com/o/r/main/x"),
    ("/fetch", "url=http://127.0.0.1:8080/admin"),
    ("/fetch", "page=2&sort=asc"),
    ("/fetch", ""),
    # Host that merely contains a metadata name as a substring.
    ("/fetch", "url=http://169.254.169.254.evil.example/"),
    ("/fetch", "url=http://metadata.google.internal.evil.example/"),
])
def test_non_metadata_requests_are_not_claimed(path, query):
    assert tbenv.resolve_ssrf_relay(path, query) is None


def test_aws_target_resolves_through_the_direct_metadata_table():
    """The relay must not carry its own copy of the path table — a second
    table is a second thing to drift."""
    resolved = tbenv.resolve_ssrf_relay("/fetch", f"url={AWS_ROLE_LIST}")
    assert resolved.imds is not None
    assert resolved.imds.kind == "role-list"
    assert not resolved.issues_canary

    cred = tbenv.resolve_ssrf_relay(
        "/fetch", "url=http://169.254.169.254/latest/meta-data/"
                  "iam/security-credentials/ec2-app-instance-role",
    )
    assert cred.imds.kind == "role-credentials"
    assert cred.imds.role == "ec2-app-instance-role"
    assert cred.issues_canary


@pytest.mark.parametrize("target,kind", [
    ("http://metadata.google.internal/computeMetadata/v1/", "index"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts", "sa-index"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default", "sa-index"),
    (GCP_TOKEN, "token"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email", "email"),
])
def test_gcp_tree_steps_resolve(target, kind):
    resolved = tbenv.resolve_ssrf_relay("/fetch", f"url={target}")
    assert resolved.cloud == "gcp"
    assert resolved.gcp_kind == kind


def test_entry_paths_are_not_claimed_by_another_trap():
    """Same failure mode `test_no_path_is_claimed_by_two_traps` guards
    for the canary registry: dispatch order decides silently, so an entry
    path that another trap already owns would make one of them
    unreachable with no error anywhere."""
    owners = {p.lower(): t.name for t in tbenv.CANARY_TRAPS for p in t.paths}
    clashes = {p: owners[p] for p in tbenv._SSRF_RELAY_ENTRY_PATHS if p in owners}
    assert not clashes, f"SSRF entry paths already owned by a canary trap: {clashes}"

    for p in tbenv._SSRF_RELAY_ENTRY_PATHS:
        assert tbenv.resolve_cloud_imds(p) is None, p
        assert tbenv.extract_git_path(p) is None, p


# --- Dispatch ---


async def test_relay_serves_the_metadata_listing_and_spends_nothing(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    async def _explode(*args, **kwargs):
        raise AssertionError("a listing step must not issue a canary")

    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _explode)

    resp = await flux_client.get(
        "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
        "iam%2Fsecurity-credentials%2F",
        headers={"X-Forwarded-For": "203.0.113.90"},
    )
    assert resp.status == 200
    body = (await resp.read()).decode()
    assert body.strip() == tbenv.CLOUD_IMDS_ROLE_NAME
    assert "AKIA" not in body

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-aws-role-list"
    assert entry["ssrfParam"] == "url"
    assert entry["ssrfHost"] == "169.254.169.254"
    assert entry["ssrfTargetPath"] == "/latest/meta-data/iam/security-credentials/"
    assert entry["ssrfCloud"] == "aws"
    assert "canaryTypes" not in entry


async def test_relay_credential_step_serves_the_canary(flux_client, monkeypatch):
    """The payoff: a credential reached through the SSRF chain is the same
    monitored canary the direct path hands out, so a replay is attributable
    to the chain rather than untraceable."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get(
        "/fetch?target=http://169.254.169.254/latest/meta-data/"
        f"iam/security-credentials/{tbenv.CLOUD_IMDS_ROLE_NAME}",
        headers={"X-Forwarded-For": "203.0.113.91"},
    )
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/json"
    body = json.loads(await resp.read())
    assert body["AccessKeyId"] == "AKIAFAKEEXAMPLE01"
    assert body["Token"] == "FwoGZXIvYXdzEXAMPLEFAKE="

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-aws-role-credentials"
    assert entry["ssrfParam"] == "target"
    assert entry["imdsRole"] == tbenv.CLOUD_IMDS_ROLE_NAME
    assert "aws" in entry["canaryTypes"]


async def test_relay_body_is_identical_to_the_direct_path(flux_client, monkeypatch):
    """A client that chained SSRF is parsing what it believes is a
    metadata response. Anything but the same bytes is a tell."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    direct = await flux_client.get("/latest/meta-data/")
    relayed = await flux_client.get(f"/fetch?url={AWS_ROOT}")
    assert direct.status == relayed.status == 200
    assert await direct.read() == await relayed.read()
    assert direct.headers["Content-Type"] == relayed.headers["Content-Type"]


async def test_direct_and_relayed_hits_stay_separable_in_the_log(flux_client, monkeypatch):
    """Same bytes on the wire, different tags in the log — otherwise the
    two populations are indistinguishable after the fact."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    await flux_client.get("/latest/meta-data/")
    direct = _log_entries(flux_client.log_path)[-1]
    await flux_client.get(f"/fetch?url={AWS_ROOT}")
    relayed = _log_entries(flux_client.log_path)[-1]

    assert direct["result"] == "cloud-imds-index"
    assert relayed["result"] == "ssrf-relay-aws-index"
    assert "ssrfTarget" not in direct


async def test_unemulated_metadata_document_404s_but_is_logged(flux_client, monkeypatch):
    """A real metadata service 404s an unknown key, so this is the honest
    answer — and the target still has to reach the log, because it names
    the next document this tooling wants."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get(
        "/fetch?url=http://169.254.169.254/latest/dynamic/instance-identity/document",
        headers={"X-Forwarded-For": "203.0.113.92"},
    )
    assert resp.status == 404
    assert await resp.read() == b"not found\n"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-unmatched"
    assert entry["ssrfTargetPath"] == "/latest/dynamic/instance-identity/document"


async def test_gcp_token_is_unique_per_hit(flux_client, monkeypatch):
    """No fixed literal, ever. Tracebit issues no GCP-shaped credential,
    so this one cannot be monitored — which makes uniqueness the only
    thing standing between it and a fleet-wide shared fingerprint."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    seen = set()
    for _ in range(3):
        resp = await flux_client.get(f"/fetch?url={GCP_TOKEN}")
        assert resp.status == 200
        body = json.loads(await resp.read())
        assert body["token_type"] == "Bearer"
        assert body["access_token"].startswith("ya29.")
        seen.add(body["access_token"])
    assert len(seen) == 3, "GCP access token must be minted per hit"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-gcp-token"
    assert entry["syntheticToken"] is True
    # The synthetic must never reach the log — the log is the artefact we
    # ship, and a credential in it is a credential leaked.
    assert body["access_token"] not in json.dumps(entry)


async def test_gcp_listing_steps_carry_no_secret(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get(
        "/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default",
    )
    assert resp.status == 200
    body = (await resp.read()).decode()
    assert "token" in body
    assert "ya29." not in body
    assert _log_entries(flux_client.log_path)[-1]["result"] == "ssrf-relay-gcp-sa-index"


async def test_non_metadata_target_falls_through_to_404(flux_client, monkeypatch):
    """flux must never look like a working open proxy: an ordinary URL on
    an entry path gets the router's plain 404, and no relay log line."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get("/fetch?url=http://example.com/robots.txt")
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "not-handled"
    assert "ssrfTarget" not in entry


async def test_disabled_switch_stops_the_relay(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", False)

    resp = await flux_client.get(f"/fetch?url={AWS_ROOT}")
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[-1]["result"] == "not-handled"


async def test_no_api_key_404s_the_relay(flux_client, monkeypatch):
    """Same contract as every canary-backed trap: a keyless deployment
    must not serve a surface it cannot back with a real canary."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get(f"/fetch?url={AWS_ROOT}")
    assert resp.status == 404


async def test_head_returns_no_body_but_keeps_the_length(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.head(f"/fetch?url={AWS_ROOT}")
    assert resp.status == 200
    assert await resp.read() == b""
    assert int(resp.headers["Content-Length"]) > 0


@pytest.mark.parametrize("entry", [
    "/fetch", "/api/fetch", "/api/v1/fetch",
    "/api/proxy", "/api/preview",
    "/api/webhook", "/api/download", "/api/image",
])
def test_observed_entry_spellings_resolve(entry):
    """Entry spellings seen in real credential-harvester sweeps.

    The relay matches the entry path exactly and only sniffs the
    parameters for a metadata URL, so an unlisted spelling is a silent
    miss no parameter-name generality can recover. Four of these
    (`/api/v1/fetch`, `/api/webhook`, `/api/download`, `/api/image`)
    were misses: the list had `/v1/fetch` but not the `/api`-prefixed
    form, and `/api/webhook/test` but not the bare endpoint.

    Pinned by spelling rather than by iterating the set so that trimming
    the set is a visible test failure with a reason attached.
    """
    resolved = tbenv.resolve_ssrf_relay(entry, f"url={AWS_ROOT}")
    assert resolved is not None, f"{entry} is a spelling scanners actually send"
    assert resolved.cloud == "aws"


@pytest.mark.parametrize("entry", ["/redirect", "/api/redirect"])
def test_redirect_is_deliberately_not_an_entry_path(entry):
    """A redirect endpoint answers with a 302; it does not dereference
    the target server-side. Returning metadata document *content* from
    one would be a shape no real application produces, so it stays
    unmatched rather than being added for surface area."""
    assert tbenv.resolve_ssrf_relay(entry, f"url={AWS_ROOT}") is None


# --- Azure: the third cloud on the same entry paths ---------------------
#
# Azure shares the link-local address with EC2, so the host cannot say
# which cloud a client meant — only the layout can. Before these, an
# Azure-layout target fell through the EC2 resolver, matched nothing, and
# 404'd, so a sweep that got AWS and GCP credentials got a dead end on the
# one cloud where a managed-identity token is the *only* way in: Azure has
# no long-lived credential file to read off disk.

AZURE_TOKEN = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https://management.azure.com/"
)
AZURE_INSTANCE = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"


@pytest.mark.parametrize("target,kind", [
    (AZURE_TOKEN, "token"),
    ("http://169.254.169.254/metadata/identity/oauth2/token", "token"),
    # Pre-managed-identity spelling; older tooling still emits it.
    ("http://169.254.169.254/metadata/oauth2/token", "token"),
    (AZURE_INSTANCE, "instance"),
    ("http://169.254.169.254/metadata/instance/compute", "instance"),
    ("http://169.254.169.254/metadata/versions", "versions"),
])
def test_azure_layout_resolves_to_azure_not_aws(target, kind):
    resolved = tbenv.resolve_ssrf_relay("/proxy", "url=" + quote(target, safe=""))
    assert resolved is not None
    assert resolved.cloud == "azure"
    assert resolved.azure_kind == kind


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.170.2/v2/credentials/",
])
def test_azure_check_does_not_steal_ec2_layout_targets(target):
    """The Azure root must not shadow the roots the EC2 resolver owns.

    This is the regression that matters most in the dispatch order: the
    Azure branch is checked first on a shared host, so an over-broad match
    would silently divert every AWS credential request.
    """
    resolved = tbenv.resolve_ssrf_relay("/proxy", f"url={target}")
    assert resolved is not None
    assert resolved.cloud == "aws"
    assert resolved.azure_kind == ""


def test_azure_token_records_the_audience_it_was_asked_for():
    """The audience is the sharpest statement of intent in the sweep.

    A token for `management.azure.com` is for taking the subscription; one
    for `vault.azure.net` is for the key vault. Same request otherwise —
    only this parameter separates the objectives, and it lives in the
    *target* URL's query, which path matching throws away.
    """
    for resource in (
        "https://management.azure.com/",
        "https://vault.azure.net",
        "https://storage.azure.com/",
    ):
        target = quote(
            "http://169.254.169.254/metadata/identity/oauth2/token"
            f"?api-version=2018-02-01&resource={resource}", safe="",
        )
        resolved = tbenv.resolve_ssrf_relay("/proxy", f"url={target}")
        assert resolved.azure_resource == resource


def test_azure_token_is_per_hit_unique_and_jwt_shaped():
    """No fixed credential literals, ever.

    Tracebit issues no Azure-shaped credential, so this is a synthetic
    rather than a monitored canary — which makes per-hit uniqueness the
    only thing standing between us and one string shared across every
    deployment. The JWT shape is load-bearing separately: a client that
    actually uses the token parses it first.
    """
    first = json.loads(tbenv._ssrf_azure_token_body("https://vault.azure.net"))
    second = json.loads(tbenv._ssrf_azure_token_body("https://vault.azure.net"))
    assert first["access_token"] != second["access_token"]
    assert first["token_type"] == "Bearer"
    # Audience echoed back, as the real service does.
    assert first["resource"] == "https://vault.azure.net"
    header, payload, signature = first["access_token"].split(".")
    assert header and payload and signature
    decoded = json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    )
    assert decoded["aud"] == "https://vault.azure.net"
    assert decoded["exp"] > decoded["iat"]


async def test_azure_token_served_over_the_relay(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get("/proxy?url=" + quote(AZURE_TOKEN, safe=""))
    assert resp.status == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    body = json.loads(await resp.text())
    assert body["token_type"] == "Bearer"

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-azure-token"
    assert entry["ssrfCloud"] == "azure"
    assert entry["azureResource"] == "https://management.azure.com/"
    assert entry["syntheticToken"] is True


async def test_azure_listing_steps_spend_no_canary(flux_client, monkeypatch):
    """Same economics as the AWS and GCP listing steps: walking the tree
    costs nothing upstream, so a broad sweep cannot burn the quota."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get("/fetch?url=" + quote(AZURE_INSTANCE, safe=""))
    assert resp.status == 200
    body = json.loads(await resp.text())
    assert body["compute"]["azEnvironment"] == "AzurePublicCloud"
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-azure-instance"
    assert "syntheticToken" not in entry


# --- The file:// leg of the same sweep ----------------------------------
#
# The same parameter on the same entry paths is swept with `file://`
# targets in the same burst — the same read primitive aimed at disk
# instead of the network. Every one of those targets already had a
# renderer; they were unreachable only because a `file://` URL has no
# authority to match against the host tables, so they resolved to no host
# and fell out of the loop.

@pytest.mark.parametrize("target,expected", [
    ("file:///root/.aws/credentials", "/root/.aws/credentials"),
    ("file:///proc/self/environ", "/proc/self/environ"),
    ("file:///app/.env", "/app/.env"),
    ("file://localhost/root/.env", "/root/.env"),
    # Malformed single-slash spelling, which real tooling emits.
    ("file:/root/.aws/credentials", "/root/.aws/credentials"),
])
def test_file_targets_resolve_through_the_shared_read_table(target, expected):
    resolved = tbenv.resolve_ssrf_relay("/proxy", f"url={target}")
    assert resolved is not None
    assert resolved.cloud == "file"
    assert resolved.target_path == expected
    assert resolved.fs is not None and resolved.fs.resolved


@pytest.mark.parametrize("target", [
    # A real remote authority is not a local read, whatever the scheme.
    "file://evil.example.com/etc/passwd",
    "http://example.com/",
    "https://169.254.169.254.evil.example.com/",
])
def test_non_local_targets_stay_unmatched(target):
    """The relay must never look like an open proxy. A target we do not
    emulate is logged and refused, never fetched."""
    assert tbenv.resolve_ssrf_relay("/proxy", f"url={target}") is None


async def test_file_credential_read_serves_the_same_canary_as_a_direct_read(
    flux_client, monkeypatch,
):
    """Byte-identical to what a bare probe for the same file gets.

    The point of routing through the shared table rather than writing a
    second renderer: a credential file answers a relayed read with the
    same monitored canary it answers a direct read with, so replay-side
    telemetry does not depend on which surface the attacker used.
    """
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)

    resp = await flux_client.get("/proxy?url=file:///root/.aws/credentials")
    assert resp.status == 200
    body = await resp.text()
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"] in body

    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("ssrf-relay-file-")
    assert entry["ssrfCloud"] == "file"
    assert entry["ssrfFsRequestedPath"] == "/root/.aws/credentials"


async def test_file_miss_logs_the_path_it_wanted(flux_client, monkeypatch):
    """The misses describe the parts of the filesystem the scanner expects
    to find and we have chosen not to furnish — which is the half of the
    dictionary a hit can never show us."""
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CLOUD_IMDS_ENABLED", True)
    monkeypatch.setattr(tbenv, "SSRF_RELAY_ENABLED", True)

    resp = await flux_client.get("/fetch?url=file:///var/lib/nothing-here.conf")
    assert resp.status == 404
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "ssrf-relay-file-miss"
    assert entry["ssrfFsRequestedPath"] == "/var/lib/nothing-here.conf"


def test_file_read_only_claims_a_canary_when_the_trap_carries_one():
    """A resolved read is not automatically a credential. The same table
    answers `/proc/self/environ`, which has no canary in it."""
    creds = tbenv.resolve_ssrf_relay("/proxy", "url=file:///root/.aws/credentials")
    assert creds.issues_canary
    passwd = tbenv.resolve_ssrf_relay("/proxy", "url=file:///etc/passwd")
    assert passwd.fs.resolved and passwd.fs.system_file
    assert not passwd.issues_canary


# --- ECS task metadata --------------------------------------------------

def test_ecs_task_metadata_is_a_listing_not_a_credential():
    """`/v2/metadata` is swept in the same breath as `/v2/credentials/`
    but is inventory, not secret — so it answers, and spends nothing."""
    resolved = tbenv.resolve_cloud_imds("/v2/metadata")
    assert resolved is not None
    assert resolved.kind == "ecs-metadata"
    assert not resolved.issues_canary
    # The credential sibling must keep its own behaviour.
    assert tbenv.resolve_cloud_imds("/v2/credentials/").issues_canary


def test_unfurnished_file_target_does_not_shadow_a_later_metadata_host():
    """A request can carry several candidate parameters.

    A `file://` path we do not furnish is a miss, and a miss must not
    consume the request ahead of a metadata host named by a later
    parameter — otherwise adding the file branch would have silently
    broken the AWS branch for any sweep that puts the two in one query.
    """
    resolved = tbenv.resolve_ssrf_relay(
        "/proxy",
        "url=file:///var/lib/nothing-here.conf"
        f"&next={quote(AWS_ROLE_LIST, safe='')}",
    )
    assert resolved is not None
    assert resolved.cloud == "aws"
    assert resolved.imds.kind == "role-list"


def test_a_furnished_file_target_still_wins_immediately():
    """The converse: a read we can actually answer is a real answer, and
    is not deferred in favour of scanning the rest of the parameters."""
    resolved = tbenv.resolve_ssrf_relay(
        "/proxy",
        "url=file:///root/.aws/credentials"
        f"&next={quote(AWS_ROLE_LIST, safe='')}",
    )
    assert resolved.cloud == "file"
    assert resolved.fs.resolved


def test_file_miss_is_still_returned_when_nothing_else_matches():
    resolved = tbenv.resolve_ssrf_relay(
        "/proxy", "url=file:///var/lib/nothing-here.conf&next=http://example.com/",
    )
    assert resolved is not None
    assert resolved.cloud == "file"
    assert not resolved.fs.resolved
