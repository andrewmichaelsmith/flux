"""Tests for the Java deployment-descriptor read surface.

The descriptors under `WEB-INF` / `META-INF` arrive in three spellings —
bare, behind a traversal prefix, and behind the servlet path-parameter
bypass whose random segment rotates per campaign. The coverage question is
therefore "does one descriptor have one answer whichever spelling asked
for it", not "is this literal path listed"; an enumerated list of the
bypass spellings is stale as soon as the prefix rotates.
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

# One representative of each spelling, against the trap that must answer.
# The bypass prefixes are real observed shapes, including two different
# random segments, because the point is that the segment is not matched.
SPELLINGS = [
    ("/WEB-INF/web.xml", "java-web-xml", 0),
    ("/web/WEB-INF/web.xml", "java-web-xml", 1),
    ("/files/../WEB-INF/web.xml", "java-web-xml", 2),
    ("/META-INF/context.xml", "tomcat-context-xml", 0),
    ("/WEB-INF/context.xml", "tomcat-context-xml", 0),
    ("/META-INF/MANIFEST.MF", "java-manifest-mf", 0),
    ("/META-INF/persistence.xml", "jpa-persistence-xml", 0),
    ("/WEB-INF/classes/META-INF/persistence.xml", "jpa-persistence-xml", 2),
    (
        "/s/3323e21333e2933323e2534313/_/;/META-INF/maven"
        "/com.atlassian.jira/jira-webapp-dist/pom.properties",
        "maven-pom-properties",
        4,
    ),
    (
        "/s/cfx/_/;/META-INF/maven/com.atlassian.jira"
        "/jira-webapp-dist/pom.properties",
        "maven-pom-properties",
        4,
    ),
]


# --- Resolution (pure) -------------------------------------------------


@pytest.mark.parametrize("path,trap_name,dropped", SPELLINGS)
def test_every_spelling_resolves_to_its_descriptor(path, trap_name, dropped):
    trap, anchored, got_dropped = tbenv.resolve_java_descriptor_read(path)
    assert trap is not None, f"{path} must resolve"
    assert trap.name == trap_name
    assert got_dropped == dropped
    assert anchored.lower().lstrip("/").startswith(("web-inf", "meta-inf"))


def test_rotating_bypass_segment_is_not_matched():
    """Two different random segments must reach the same renderer — the
    segment is dropped, not enumerated, which is the whole reason this
    surface exists rather than a path list."""
    tail = (
        "/_/;/META-INF/maven/com.atlassian.jira"
        "/jira-webapp-dist/pom.properties"
    )
    first, _, _ = tbenv.resolve_java_descriptor_read("/s/aaaaaaaa" + tail)
    second, _, _ = tbenv.resolve_java_descriptor_read("/s/zz99zz00" + tail)
    assert first is not None and first is second


def test_maven_coordinates_do_not_have_to_be_catalogued():
    """The coordinates are data, so an artifact we never wrote down still
    resolves rather than 404ing on a groupId."""
    trap, _, _ = tbenv.resolve_java_descriptor_read(
        "/s/x/_/;/META-INF/maven/org.example.app/some-webapp/pom.properties",
    )
    assert trap is not None and trap.name == "maven-pom-properties"


@pytest.mark.parametrize("path", [
    "/", "/.env", "/index.php",
    "/webinfo/web.xml",            # not the descriptor directory
    "/api/web.xml.bak",            # a backup suffix is a different file
    "/s/x/_/;/META-INF/maven/g/a/other.txt",   # under the dir, not a descriptor
])
def test_unrelated_paths_are_not_claimed(path):
    trap, _, _ = tbenv.resolve_java_descriptor_read(path)
    assert trap is None


def test_descriptor_dir_without_a_known_leaf_still_reports_the_request():
    """A miss returns the anchored path anyway — the descriptor asked for
    is the intel whether or not anything answered it."""
    trap, anchored, dropped = tbenv.resolve_java_descriptor_read(
        "/s/x/_/;/WEB-INF/nothing-we-serve.xml",
    )
    assert trap is None
    assert anchored == "/WEB-INF/nothing-we-serve.xml"
    assert dropped == 4


def test_shared_read_path_is_reused_not_duplicated():
    """A descriptor directory in front of a file another trap already
    serves must reach that trap, not 404 — answering one spelling while
    404ing another is the drift the shared table exists to stop."""
    trap, _, _ = tbenv.resolve_java_descriptor_read(
        "/WEB-INF/classes/application.properties",
    )
    assert trap is not None and trap.name == "application-properties"


def test_disabled_switch_turns_the_surface_off(monkeypatch):
    monkeypatch.setattr(tbenv, "JAVA_DESCRIPTOR_READ_ENABLED", False)
    trap, _, _ = tbenv.resolve_java_descriptor_read("/WEB-INF/web.xml")
    assert trap is None


# --- Rendered bodies ---------------------------------------------------


def test_pom_properties_echoes_the_requested_coordinates():
    body = tbenv.render_maven_pom_properties({
        "_requestPath": (
            "/s/x/_/;/META-INF/maven/com.atlassian.confluence"
            "/confluence-webapp/pom.properties"
        ),
    }).decode()
    assert "groupId=com.atlassian.confluence" in body
    assert "artifactId=confluence-webapp" in body
    assert f"version={tbenv._JAVA_WEBAPP_VERSION}" in body


def test_pom_properties_falls_back_when_no_coordinates_were_named():
    body = tbenv.render_maven_pom_properties({}).decode()
    assert f"groupId={tbenv._JAVA_WEBAPP_GROUP}" in body


def test_version_is_stable_across_reads():
    """A version that moved between two reads of the same host would be
    the tell — and it is what the next request is selected from."""
    first = tbenv.render_maven_pom_properties({}).decode()
    second = tbenv.render_maven_pom_properties({}).decode()
    assert first == second


@pytest.mark.parametrize("render", [
    tbenv.render_tomcat_context_xml,
    tbenv.render_java_web_xml,
    tbenv.render_jpa_persistence_xml,
])
def test_datasource_password_is_per_hit(render):
    """Nothing credential-shaped may be a fixed literal: a hardcoded one
    gives zero detection on replay and ships one fingerprint fleet-wide."""
    assert render(dict(AWS)) != render(dict(AWS))


@pytest.mark.parametrize("render", [
    tbenv.render_tomcat_context_xml,
    tbenv.render_java_web_xml,
])
def test_cloud_canary_reaches_the_body(render):
    body = render(dict(AWS)).decode()
    assert AWS["aws"]["awsAccessKeyId"] in body
    assert AWS["aws"]["awsSecretAccessKey"] in body


@pytest.mark.parametrize("render,needle", [
    (tbenv.render_tomcat_context_xml, "<Context"),
    (tbenv.render_java_web_xml, "<web-app"),
    (tbenv.render_jpa_persistence_xml, "<persistence"),
])
def test_xml_descriptors_are_well_formed(render, needle):
    import xml.etree.ElementTree as ET
    body = render(dict(AWS)).decode()
    assert needle in body
    ET.fromstring(body)   # must parse — a malformed body is a tell


def test_descriptors_are_registered_in_the_shared_trap_table():
    for name in (
        "maven-pom-properties", "java-manifest-mf", "tomcat-context-xml",
        "java-web-xml", "jpa-persistence-xml",
    ):
        assert any(t.name == name for t in tbenv.CANARY_TRAPS), name


# --- Dispatch (end to end) ---------------------------------------------
#
# These pin the placement, not the resolution. The surface sits *after* the
# normal canary dispatch on purpose, so a spelling that dispatch can
# already resolve keeps its own result tag and only the bypass spellings
# carry the `java-descriptor-` prefix. Getting that order wrong is what
# silently re-tags traffic another trap already owned.

import json

import pytest_asyncio

from .test_server import FAKE_TRACEBIT, _fake_canary  # noqa: F401

BYPASS = (
    "/s/3323e21333e2933323e2534313/_/;/META-INF/maven"
    "/com.atlassian.jira/jira-webapp-dist/pom.properties"
)


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _rows(client, path):
    p = client.log_path
    if not p.exists():
        return []
    return [
        json.loads(ln) for ln in p.read_text().splitlines()
        if ln.strip() and json.loads(ln).get("path") == path
    ]


async def _get(client, path):
    return await client.get(path, headers={"X-Forwarded-For": "203.0.113.40"})


async def test_bypass_spelling_is_served_and_tagged_as_a_bypass(flux_client):
    resp = await _get(flux_client, BYPASS)
    assert resp.status == 200
    body = await resp.text()
    assert f"version={tbenv._JAVA_WEBAPP_VERSION}" in body
    row = _rows(flux_client, BYPASS)[-1]
    assert row["result"] == "java-descriptor-maven-pom-properties"
    # The anchored path is what the log records as asked-for, and the drop
    # count is what separates this from the bare spelling.
    assert row["javaDescriptorRequestedPath"].lower().startswith("/meta-inf/")
    assert row["javaDescriptorPrefixDropped"] == 4


async def test_bare_descriptor_keeps_its_own_tag(flux_client):
    """`/WEB-INF/web.xml` is resolvable by the normal dispatch, so it must
    NOT pick up the bypass prefix — otherwise the prefix stops meaning
    anything."""
    resp = await _get(flux_client, "/WEB-INF/web.xml")
    assert resp.status == 200
    row = _rows(flux_client, "/WEB-INF/web.xml")[-1]
    assert row["result"] == "java-web-xml"


async def test_already_owned_path_is_not_retagged(flux_client):
    """A descriptor directory in front of a file another trap owns must
    keep that trap's tag — this is the regression the fallback placement
    exists to prevent."""
    path = "/WEB-INF/classes/application.properties"
    resp = await _get(flux_client, path)
    assert resp.status == 200
    assert _rows(flux_client, path)[-1]["result"] == "application-properties"


async def test_descriptor_read_carries_the_canary_and_a_per_hit_password(flux_client):
    first = await (await _get(flux_client, "/META-INF/context.xml")).text()
    second = await (await _get(flux_client, "/META-INF/context.xml")).text()
    assert FAKE_TRACEBIT["aws"]["awsAccessKeyId"] in first
    assert first != second, "datasource password must be per-hit"
