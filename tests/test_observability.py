"""Observability / debug surface.

The family exists to serve disclosures that *name a further target*, so
the tests assert two things beyond "returns 200": that the actuator
index advertises only endpoints the server actually answers (an
advertised-but-404 link is the cheapest tell that the index is canned),
and that nothing credential-shaped in these bodies is a fixed literal.
"""
import json

import pytest

import flux.server as tbenv


# --- path matching -----------------------------------------------------

@pytest.mark.parametrize("path,kind", [
    ("/actuator", "actuator-index"),
    ("/actuator/", "actuator-index"),
    ("/metrics", "metrics"),
    ("/metrics/", "metrics"),
    ("/prometheus", "metrics"),
    ("/actuator/prometheus", "metrics"),
    ("/debug/vars", "expvar"),
    ("/health", "health"),
    ("/healthz", "health"),
    ("/_health", "health"),
    ("/api/health", "health"),
    ("/readyz", "health"),
    ("/livez", "health"),
    ("/health/ready", "health"),
    ("/api/status", "health"),
    ("/server-info", "server-info"),
    ("/server-info/", "server-info"),
    ("/nginx_status", "nginx-status"),
    ("/basic_status", "nginx-status"),
    ("/stub_status", "nginx-status"),
    ("/elmah.axd", "elmah"),
    ("/elmah", "elmah"),
    ("/debug", "profiler-index"),
    ("/_debug", "profiler-index"),
    ("/debug/profiler", "profiler-index"),
    ("/profiler", "profiler-index"),
    ("/__profiler__", "profiler-index"),
    ("/_profiler/panel.html", "profiler-index"),
])
def test_matches_and_classifies(path, kind):
    assert tbenv.observability_kind(path) == kind


def test_query_string_ignored_for_matching():
    assert tbenv.observability_kind("/metrics?format=text") == "metrics"
    assert tbenv.observability_kind("/actuator?x=1") == "actuator-index"


def test_case_insensitive():
    assert tbenv.observability_kind("/METRICS") == "metrics"
    assert tbenv.observability_kind("/Actuator") == "actuator-index"


@pytest.mark.parametrize("path", [
    # Neighbours with their own, better-targeted handlers. A prefix rule
    # on `/debug` or `/server-` would swallow these.
    "/debug/pprof/",
    "/debug/pprof/heap",
    "/server-status",
    "/_profiler",
    # Not an operational endpoint at all.
    "/metrics.php",
    "/healthcheck.html",
    "/actuator/env",
    "/actuatorx",
    "/",
    "/index.php",
    "/nginx_status.bak",
])
def test_does_not_match_neighbours_or_noise(path):
    assert tbenv.observability_kind(path) is None


def test_disabled_switch_matches_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "OBSERVABILITY_ENABLED", False)
    for p in ("/metrics", "/actuator", "/health", "/elmah.axd"):
        assert tbenv.observability_kind(p) is None
        assert not tbenv.is_observability_path(p)


def test_default_on():
    assert tbenv.OBSERVABILITY_ENABLED


# --- the exploit chain -------------------------------------------------

def test_actuator_index_advertises_only_endpoints_that_exist():
    """Every `_links` entry must resolve to a trap that answers.

    This is the load-bearing assertion of the whole family: the index is
    only worth serving if following it works, and a link we then 404 is
    a tell that costs more than the index gains.
    """
    doc = json.loads(tbenv._render_actuator_index(""))
    names = [k for k in doc["_links"] if k != "self"]
    assert names, "index must advertise something"
    missing = [
        n for n in names
        if tbenv.find_canary_trap(f"/actuator/{n}") is None
        and tbenv.observability_kind(f"/actuator/{n}") is None
    ]
    assert not missing, f"index advertises endpoints with no handler: {missing}"


def test_actuator_index_self_link_present():
    doc = json.loads(tbenv._render_actuator_index(""))
    assert doc["_links"]["self"]["href"] == "/actuator"


# --- bodies name a further target --------------------------------------

def test_metrics_names_internal_hosts():
    body = tbenv._render_prometheus_metrics().decode()
    assert tbenv.OBSERVABILITY_DB_HOST in body
    assert tbenv.OBSERVABILITY_CACHE_HOST in body
    # Prometheus exposition must stay parseable: HELP/TYPE before samples.
    assert body.startswith("# HELP ")
    for line in body.splitlines():
        assert line == "" or line.startswith("#") or " " in line


def test_expvar_is_json_and_names_a_config_path():
    doc = json.loads(tbenv._render_expvar())
    assert any("-config=" in a for a in doc["cmdline"])
    assert any(".env" in a for a in doc["cmdline"])
    assert doc["db"]["dsn_host"].startswith(tbenv.OBSERVABILITY_DB_HOST)


def test_health_is_json_and_names_backing_services():
    doc = json.loads(tbenv._render_health_json())
    assert doc["status"] == "UP"
    assert doc["components"]["db"]["details"]["host"] == tbenv.OBSERVABILITY_DB_HOST
    assert doc["components"]["redis"]["details"]["host"] == tbenv.OBSERVABILITY_CACHE_HOST


def test_server_info_names_config_files():
    body = tbenv._render_server_info_html("example.test").decode()
    assert "/etc/apache2/apache2.conf" in body
    assert ".env" in body
    assert "example.test" in body


def test_nginx_status_shape():
    body = tbenv._render_nginx_status().decode()
    lines = body.splitlines()
    assert lines[0].startswith("Active connections:")
    assert lines[1] == "server accepts handled requests"
    assert len(lines[2].split()) == 3


def test_profiler_index_links_tokens():
    body = tbenv._render_profiler_index("").decode()
    assert "/_profiler/a3f19c" in body


def test_html_bodies_escape_the_host_header():
    """Host is attacker-controlled; it must not land in the page raw."""
    hostile = 'x"><script>alert(1)</script>'
    for body in (
        tbenv._render_server_info_html(hostile),
        tbenv._render_elmah_html(hostile)[0],
    ):
        assert b"<script>" not in body


# --- no fixed credentials ----------------------------------------------

def test_elmah_password_is_per_hit():
    _, conn_a = tbenv._render_elmah_html("h")
    _, conn_b = tbenv._render_elmah_html("h")
    pw_a = conn_a.split("Password=")[1].split(";")[0]
    pw_b = conn_b.split("Password=")[1].split(";")[0]
    assert pw_a != pw_b, "a fixed literal would be one shared string per fleet"
    assert len(pw_a) >= 16


def test_no_aws_key_shaped_literal_in_any_body():
    """This family issues no canary, so nothing here may look like one —
    a static AKIA… would be an unbacked credential that never fires."""
    import re
    bodies = [
        tbenv._render_actuator_index(""),
        tbenv._render_prometheus_metrics(),
        tbenv._render_expvar(),
        tbenv._render_health_json(),
        tbenv._render_server_info_html("h"),
        tbenv._render_nginx_status(),
        tbenv._render_elmah_html("h")[0],
        tbenv._render_profiler_index(""),
    ]
    for body in bodies:
        assert not re.search(rb"(AKIA|ASIA)[0-9A-Z]{12,}", body)


def test_uptime_advances_not_frozen(monkeypatch):
    base = tbenv._observability_uptime_s()
    monkeypatch.setattr(tbenv, "_OBSERVABILITY_START", tbenv._OBSERVABILITY_START - 60)
    assert tbenv._observability_uptime_s() >= base + 59


# --- expansions to neighbouring traps ----------------------------------

@pytest.mark.parametrize("path", [
    "/aws-config.js", "/__env.js",
    "/configuration.js", "/app.config.js",
    "/static/js/aws-config.js", "/assets/__env.js",
])
def test_framework_runtime_config_bundles_resolve(path):
    """Framework-specific spellings of the SPA runtime-config bundle
    reach the same renderer as the generic `/config.js` names."""
    trap = tbenv.find_canary_trap(path)
    assert trap is not None and trap.name == "webapp-config-bundle-js"


@pytest.mark.parametrize("path", [
    "/_phpinfo.php", "/_info.php", "/phpinfo/index.php",
])
def test_prefixed_phpinfo_spellings_resolve(path):
    """A root-level leaf carrying a prefix is one segment deep, so the
    nested walk never sees it — only an exact entry answers."""
    trap, _ = tbenv.resolve_canary_trap(path)
    assert trap is not None and trap.name == "phpinfo"


@pytest.mark.parametrize("path", [
    "/admin/_phpinfo.php", "/cgi-bin/_info.php",
])
def test_prefixed_phpinfo_spellings_resolve_nested_too(path):
    trap, depth = tbenv.resolve_canary_trap(path)
    assert trap is not None and trap.name == "phpinfo"
    assert depth >= 1
