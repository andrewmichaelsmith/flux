"""Observability / debug surface.

The family exists to serve disclosures that *name a further target*, so
the tests assert two things beyond "returns 200": that the actuator
index advertises only endpoints the server actually answers (an
advertised-but-404 link is the cheapest tell that the index is canned),
and that nothing credential-shaped in these bodies is a fixed literal.
"""
import json
import re

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
    links = {k: v for k, v in doc["_links"].items() if k != "self"}
    assert links, "index must advertise something"

    def resolves(url: str) -> bool:
        return (tbenv.find_canary_trap(url) is not None
                or tbenv.observability_kind(url) is not None)

    # Follow the advertised href rather than rebuilding it from the link
    # name: a templated entry's name is not its path, and reconstructing
    # would silently stop checking the thing the client actually fetches.
    missing = [n for n, link in links.items()
               if not link["templated"] and not resolves(link["href"])]
    assert not missing, f"index advertises endpoints with no handler: {missing}"

    # A template is a promise about the concrete form, so check that.
    unresolved = [
        n for n, link in links.items()
        if link["templated"]
        and not resolves(re.sub(r"\{[^}]+\}", "process.uptime", link["href"]))
    ]
    assert not unresolved, (
        f"index advertises templates whose concrete form 404s: {unresolved}")


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
        tbenv._render_actuator_info(),
        tbenv._render_actuator_metrics_names(),
        tbenv._render_actuator_metric("process.uptime"),
        tbenv._render_actuator_beans(),
        tbenv._render_actuator_loggers(),
        tbenv._render_actuator_auditevents(),
        tbenv._render_actuator_sessions(),
    ]
    for body in bodies:
        assert not re.search(rb"(AKIA|ASIA)[0-9A-Z]{12,}", body)


# --- Spring Boot endpoints the index implies ---------------------------

@pytest.mark.parametrize("path,kind", [
    ("/actuator/info", "actuator-info"),
    ("/actuator/beans", "actuator-beans"),
    ("/actuator/loggers", "actuator-loggers"),
    ("/actuator/auditevents", "actuator-auditevents"),
    ("/actuator/sessions", "actuator-sessions"),
    ("/actuator/metrics", "actuator-metrics"),
    ("/actuator/metrics/process.uptime", "actuator-metric"),
    ("/actuator/metrics/anything.at.all", "actuator-metric"),
])
def test_spring_endpoints_classify(path, kind):
    assert tbenv.observability_kind(path) == kind


def test_info_is_served_because_spring_exposes_it_by_default():
    """`health` and `info` are the two endpoints Spring Boot exposes with
    no configuration. Answering one and 404ing the other is a shape no
    real deployment produces, and it would be the same shape on every
    host running this code."""
    # `health` is answered by the canary table, `info` by this surface —
    # what matters is that a client asking for either gets an answer.
    assert tbenv.find_canary_trap("/actuator/health") is not None
    assert tbenv.observability_kind("/actuator/info") is not None
    doc = json.loads(tbenv._render_actuator_info())
    assert doc["build"]["artifact"] == tbenv.OBSERVABILITY_APP_NAME
    assert doc["git"]["branch"]


def test_actuator_metrics_is_json_names_not_prometheus_text():
    """`/actuator/metrics` is the JSON meter index; the text exposition
    lives at `/actuator/prometheus`. Serving text here would be the tell."""
    doc = json.loads(tbenv._render_actuator_metrics_names())
    assert "process.uptime" in doc["names"]
    assert tbenv.observability_kind("/actuator/prometheus") == "metrics"


def test_named_meter_resolves_and_unknown_gets_springs_404_shape():
    known = json.loads(tbenv._render_actuator_metric("http.server.requests"))
    assert known["name"] == "http.server.requests"
    assert any(m["statistic"] == "COUNT" for m in known["measurements"])
    unknown = json.loads(tbenv._render_actuator_metric("not.a.real.meter"))
    assert unknown["status"] == 404
    assert "Unable to find metric" in unknown["message"]


def test_every_advertised_meter_name_answers():
    """The name index is only a lead if the names in it resolve."""
    for name in tbenv._ACTUATOR_METER_NAMES:
        doc = json.loads(tbenv._render_actuator_metric(name))
        assert doc.get("status") != 404, name
        assert doc["measurements"]


def test_auditevents_and_sessions_disclose_principals():
    """The disclosure that matters on both bodies is the account names —
    the same enumerate-then-brute chain the user-enumeration trap runs."""
    audit = json.loads(tbenv._render_actuator_auditevents())
    principals = {e["principal"] for e in audit["events"]}
    assert principals <= set(tbenv._ACTUATOR_PRINCIPALS)
    assert len(principals) > 1
    sessions = json.loads(tbenv._render_actuator_sessions())
    assert all(s["principalName"] in tbenv._ACTUATOR_PRINCIPALS
               for s in sessions["sessions"])


def test_session_ids_are_per_hit_not_fixed():
    """The session id is the credential-shaped field on that body: a
    fixed one is useless on replay and identical fleet-wide."""
    a = [s["id"] for s in json.loads(tbenv._render_actuator_sessions())["sessions"]]
    b = [s["id"] for s in json.loads(tbenv._render_actuator_sessions())["sessions"]]
    assert a != b
    assert len(set(a)) == len(a)


def test_beans_and_loggers_name_further_targets():
    beans = json.loads(tbenv._render_actuator_beans())["contexts"]["application"]["beans"]
    assert "dataSource" in beans
    assert "springSecurityFilterChain" in beans
    loggers = json.loads(tbenv._render_actuator_loggers())
    assert loggers["loggers"]["ROOT"]["effectiveLevel"] == "INFO"
    assert "DEBUG" in loggers["levels"]


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
