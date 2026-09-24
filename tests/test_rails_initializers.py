"""Tests for the Rails service-initializer traps, the Airflow config trap,
and the Java build-layout routing fix.

A Rails app keeps one initializer per third-party integration, and that
integration's API key is the reason the file exists. A dictionary that walks
`config/initializers/` is therefore not asking "is this Rails?" — it already
knows — it is asking which vendor's key this app holds, one filename per
vendor. That is why each initializer gets its own result tag rather than a
single family tag: which services a sweep asks for, and which one it takes
before it stops, is only countable if the log separates them.

Two legs (`aws.rb`, `carrierwave.rb`) carry a live Tracebit canary because
those are the two where a real Rails app genuinely holds AWS keys, so a
replay is attributable. The rest mint per-hit synthetics in the vendor's own
key format — the point of the format is that a harvester grepping for
`sk_live_` or `SG.` finds something; the point of per-hit is that a fixed
literal would detect nothing on replay and fingerprint the whole fleet.

The routing tests at the bottom pin the Java fix: `/application.properties`
at bare webroot is the *derived* spelling, since the misconfiguration that
makes a Spring config readable over HTTP (a served project tree or exploded
WAR) puts the file at its build-layout path. Answering the root and 404ing
`src/main/resources/` answered the less likely half of the same sweep.
"""
from __future__ import annotations

import json
import re

import pytest
import pytest_asyncio

from flux import server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary  # noqa: F401

CANARY_AK = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
CANARY_SK = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def log_lines(path):
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


async def get(client, path, ip="203.0.113.40"):
    return await client.get(path, headers={"X-Forwarded-For": ip})


# --------------------------------------------------------------------------
# Routing — every initializer answers under its own tag
# --------------------------------------------------------------------------

INITIALIZERS = [
    ("/config/initializers/stripe.rb", "rails-initializer-stripe"),
    ("/config/initializers/sendgrid.rb", "rails-initializer-sendgrid"),
    ("/config/initializers/twilio.rb", "rails-initializer-twilio"),
    ("/config/initializers/aws.rb", "rails-initializer-aws"),
    ("/config/initializers/carrierwave.rb", "rails-initializer-carrierwave"),
    ("/config/initializers/devise.rb", "rails-initializer-devise"),
    ("/config/initializers/omniauth.rb", "rails-initializer-omniauth"),
    ("/config/initializers/smtp_settings.rb", "rails-initializer-smtp"),
    ("/config/initializers/secret_token.rb", "rails-initializer-secret-token"),
]


@pytest.mark.parametrize("path,expected_result", INITIALIZERS)
async def test_initializer_answers_under_its_own_tag(flux_client, path, expected_result):
    resp = await get(flux_client, path)
    assert resp.status == 200
    rows = [r for r in log_lines(flux_client.log_path) if r.get("path") == path]
    assert rows and rows[-1]["result"] == expected_result


@pytest.mark.parametrize("path,_tag", INITIALIZERS)
@pytest.mark.parametrize("suffix", [".bak", ".old", ".save", "~"])
async def test_editor_leftovers_answer_too(flux_client, path, _tag, suffix):
    """The same sweep that walks the directory walks its backups; a webroot
    that serves the file but not its `.bak` is describing a filesystem that
    does not exist."""
    resp = await get(flux_client, path + suffix)
    assert resp.status == 200


@pytest.mark.parametrize("path,tag", INITIALIZERS)
async def test_app_layout_prefix_answers(flux_client, path, tag):
    resp = await get(flux_client, "/app" + path)
    assert resp.status == 200
    rows = [r for r in log_lines(flux_client.log_path) if r.get("path") == "/app" + path]
    assert rows and rows[-1]["result"] == tag


@pytest.mark.parametrize("path", [
    "/config/initializers/",
    "/config/initializers/unknown_vendor.rb",
    "/config/initializer/stripe.rb",
    "/stripe.rb",
])
async def test_non_matching_paths_do_not_answer(flux_client, path):
    resp = await get(flux_client, path)
    assert resp.status != 200


# --------------------------------------------------------------------------
# Credentials — canary where a real app holds one, synthetic elsewhere,
# fixed literal nowhere
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/config/initializers/aws.rb",
    "/config/initializers/carrierwave.rb",
    "/airflow.cfg",
])
async def test_aws_legs_carry_the_canary(flux_client, path):
    """These three are the files where a real deployment genuinely holds AWS
    keys, so the key they hand over has to be the attributable one."""
    body = await (await get(flux_client, path)).text()
    assert CANARY_AK in body
    assert CANARY_SK in body


@pytest.mark.parametrize("path,pattern", [
    ("/config/initializers/stripe.rb", r"sk_live_[A-Za-z0-9]{20,}"),
    ("/config/initializers/sendgrid.rb", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("/config/initializers/twilio.rb", r"AC[0-9a-f]{32}"),
    ("/config/initializers/devise.rb", r"secret_key = '[0-9a-f]{128}'"),
    ("/config/initializers/secret_token.rb", r"secret_token = '[0-9a-f]{128}'"),
    ("/config/initializers/omniauth.rb", r"GOCSPX-[A-Za-z0-9_-]+"),
    ("/config/initializers/smtp_settings.rb", r"password: '\S+'"),
])
async def test_synthetic_legs_are_in_the_vendor_key_format(flux_client, path, pattern):
    """A harvester greps for the vendor's key prefix. A credential that does
    not look like one of those is not collected, so the trap has to emit the
    real shape even though the value is synthetic."""
    body = await (await get(flux_client, path)).text()
    assert re.search(pattern, body), body


# The two canary legs are excluded here on purpose: their secret comes from
# Tracebit, which the test stub pins to a constant, so "did it change?" is a
# question about the stub rather than about the renderer. Their contract is
# `test_aws_legs_carry_the_canary` instead — issuance is per-request in
# production, and `_get_or_issue_canary` owns that.
SYNTHETIC_LEGS = [
    p for p, tag in INITIALIZERS
    if tag not in {"rails-initializer-aws", "rails-initializer-carrierwave"}
] + ["/airflow.cfg"]

_SECRET_RE = re.compile(
    r"(sk_live_[A-Za-z0-9]+|pk_live_[A-Za-z0-9]+|whsec_[A-Za-z0-9_-]+"
    r"|SG\.[A-Za-z0-9_.-]+|AC[0-9a-f]{32}|GOCSPX-[A-Za-z0-9_-]+"
    r"|Iv1\.[0-9a-f]+|[0-9a-f]{128}|fernet_key = \S+"
    r"|password[:=] ?'?[^'\n]+'?)"
)


@pytest.mark.parametrize("path", SYNTHETIC_LEGS)
async def test_no_credential_is_a_fixed_literal(flux_client, path):
    """Two fetches of the same file must not hand over the same secret. A
    fixed literal detects nothing on replay and ships one string across every
    sensor, which turns the fleet into a single fingerprint."""
    first = await (await get(flux_client, path, ip="203.0.113.41")).text()
    second = await (await get(flux_client, path, ip="203.0.113.42")).text()
    a, b = set(_SECRET_RE.findall(first)), set(_SECRET_RE.findall(second))
    assert a, f"no credential-shaped field found in {path}"
    assert not (a & b), f"{path} reuses a credential across hits: {a & b}"


# --------------------------------------------------------------------------
# Airflow config
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/airflow.cfg",
    "/airflow/airflow.cfg",
    "/opt/airflow/airflow.cfg",
    "/config/airflow.cfg",
    "/airflow.cfg.bak",
])
async def test_airflow_cfg_spellings(flux_client, path):
    resp = await get(flux_client, path)
    assert resp.status == 200
    rows = [r for r in log_lines(flux_client.log_path) if r.get("path") == path]
    assert rows and rows[-1]["result"] == "airflow-cfg"


async def test_airflow_cfg_carries_all_three_credential_slots(flux_client):
    """The file is in harvester dictionaries because it holds three separate
    primitives: the DB URI with an inline password, the Fernet key that
    decrypts every stored Connection, and the Flask `secret_key` that signs
    the session a forger would need."""
    body = await (await get(flux_client, "/airflow.cfg")).text()
    assert re.search(r"sql_alchemy_conn = postgresql\+psycopg2://airflow:\S+@", body)
    assert re.search(r"fernet_key = \S{40,}", body)
    assert re.search(r"secret_key = [0-9a-f]{32}", body)


# --------------------------------------------------------------------------
# Java build-layout routing — the fix
# --------------------------------------------------------------------------

@pytest.mark.parametrize("prefix", [
    "/src/main/resources",
    "/WEB-INF/classes",
    "/BOOT-INF/classes",
    "/target/classes",
    "/build/resources/main",
])
@pytest.mark.parametrize("leaf,tag", [
    ("/application.properties", "application-properties"),
    ("/application.yml", "application-yml"),
    ("/config.properties", "app-config-properties"),
])
async def test_spring_config_answers_at_its_build_layout_path(flux_client, prefix, leaf, tag):
    path = prefix + leaf
    resp = await get(flux_client, path)
    assert resp.status == 200
    rows = [r for r in log_lines(flux_client.log_path) if r.get("path") == path]
    assert rows and rows[-1]["result"] == tag


@pytest.mark.parametrize("leaf", [
    "database", "db", "jdbc", "datasource", "secrets", "credentials",
    "aws", "s3", "cloud", "smtp", "mail", "spring", "hibernate",
    "redis", "kafka",
])
async def test_topic_named_properties_siblings_answer(flux_client, leaf):
    """A JVM project splits properties by concern rather than keeping one
    file, so the same pass asks for all of them."""
    for path in (f"/{leaf}.properties", f"/src/main/resources/{leaf}.properties"):
        resp = await get(flux_client, path)
        assert resp.status == 200, path


def test_build_layout_prefixing_does_not_claim_nested_conventions():
    """Only root-level leaves are lifted. A path that already carries a
    directory is its own convention, and re-prefixing it produces spellings
    no build tool creates.

    Asserted against the route table rather than over HTTP: the generic
    app-layout walk answers some of these anyway by stripping the prefix and
    re-resolving, and that behaviour predates this fix. What is pinned here is
    that the derived prefixing did not *add* them.
    """
    for path in (
        "/src/main/resources/config/bootstrap.properties",
        "/WEB-INF/classes/.gradle/gradle.properties",
        "/target/classes/config/application.properties",
    ):
        assert path.lower() not in tbenv._TRAP_BY_PATH, path


async def test_root_spelling_still_answers(flux_client):
    """Regression: the fix adds routes, it must not move an existing one."""
    for path in ("/application.properties", "/application.yml", "/config.properties"):
        resp = await get(flux_client, path)
        assert resp.status == 200, path
