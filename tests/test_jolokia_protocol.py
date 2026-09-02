"""Jolokia JMX-over-HTTP: the operations that follow a `list`.

The listing was already served. What these tests pin is the part that
makes the listing worth serving: a client that reads the MBean tree and
comes back for `read/<mbean>/<attribute>` or `exec/<mbean>/<operation>`
gets an answer, and the request it sent — bean, member, arguments — lands
in the log, because that request is the payload.

Three properties matter and are asserted directly. The tree the listing
publishes and the tree the follow-ups answer from must be the same object,
or we advertise beans we then 404. The fingerprint sweep every off-the-
shelf Jolokia tool runs (`version`, the MBeanServerDelegate reads) must
cost no upstream canary, or a scanner population that tells us nothing
burns the quota for the one that does. And nothing credential-shaped may
be a fixed literal.
"""
import json

import pytest
import pytest_asyncio

import flux.server as tbenv

from .test_server import FAKE_TRACEBIT, _fake_canary, _log_entries, flux_client  # noqa: F401


AK = FAKE_TRACEBIT["aws"]["awsAccessKeyId"]
SK = FAKE_TRACEBIT["aws"]["awsSecretAccessKey"]

RUNTIME = "java.lang:type=Runtime"
DIAG = "com.sun.management:type=DiagnosticCommand"
DELEGATE = "JMImplementation:type=MBeanServerDelegate"
HOUSE = "com.internal.tools:type=Config"


def _tree():
    return tbenv._jolokia_mbean_tree(AK, SK, "jdbc:postgresql://db.internal:5432/appdb")


# --- Mount points -------------------------------------------------------


@pytest.mark.parametrize("prefix", tbenv._JOLOKIA_PREFIXES)
def test_every_mount_point_exposes_the_operations_beneath_it(prefix):
    assert tbenv.jolokia_protocol_rest(f"{prefix}/version") == "version"
    # The bare mount is the listing's address, answered by the exact-path
    # trap — the protocol handler must not claim it.
    assert tbenv.jolokia_protocol_rest(prefix) == ""
    assert tbenv.jolokia_protocol_rest(prefix + "/") == ""


@pytest.mark.parametrize("prefix", tbenv._JOLOKIA_PREFIXES)
def test_every_mount_point_is_also_a_listing_address(prefix):
    """A mount that answers `read` but 404s `list` (or the reverse) is the
    tell — the listing has to be reachable everywhere the operations are."""
    trap = next(t for t in tbenv.CANARY_TRAPS if t.name == "actuator-jolokia")
    assert prefix in trap.paths, f"{prefix} serves operations but no listing"


def test_unrelated_paths_are_not_claimed():
    for path in ("/actuator/env", "/jolokiafoo/version", "/api/v1/jolokia", "/"):
        assert tbenv.jolokia_protocol_rest(path) is None


def test_mount_matching_is_case_insensitive():
    assert tbenv.jolokia_protocol_rest("/Actuator/Jolokia/version") == "version"


# --- GET parsing --------------------------------------------------------


def test_parse_read_with_attribute_and_inner_path():
    req = tbenv.parse_jolokia_get(f"read/{RUNTIME}/SystemProperties/java.version")
    assert req.type == "read"
    assert req.mbean == RUNTIME
    assert req.attribute == "SystemProperties"
    assert req.inner_path == "java.version"


def test_parse_exec_keeps_every_argument():
    req = tbenv.parse_jolokia_get(f"exec/{DIAG}/vmFlags/-XX:+PrintFlagsFinal/second")
    assert req.type == "exec"
    assert req.operation == "vmFlags"
    assert req.arguments == ("-XX:+PrintFlagsFinal", "second")


def test_parse_write_takes_the_value_from_the_path():
    req = tbenv.parse_jolokia_get(f"write/{HOUSE}/LogLevel/DEBUG")
    assert (req.type, req.attribute, req.value) == ("write", "LogLevel", "DEBUG")


def test_parse_list_and_search_and_version():
    assert tbenv.parse_jolokia_get("version").type == "version"
    assert tbenv.parse_jolokia_get("list/java.lang").inner_path == "java.lang"
    assert tbenv.parse_jolokia_get("search/*:type=Runtime").mbean == "*:type=Runtime"


def test_parse_unescapes_jolokia_slash_escapes():
    """The agent escapes `/` inside an ObjectName as `!/` so the name
    survives the path split; a parser that does not undo it reads a
    truncated bean name."""
    req = tbenv.parse_jolokia_get("read/com.internal.tools:type=Config,path=!/app/Environment")
    assert req.mbean == "com.internal.tools:type=Config,path=/app"
    assert req.attribute == "Environment"


@pytest.mark.parametrize("rest", ["", "notanoperation", "notanoperation/x", "read"])
def test_junk_below_a_mount_point_is_not_a_request(rest):
    assert tbenv.parse_jolokia_get(rest) is None


# --- POST parsing -------------------------------------------------------


def test_parse_post_single_object():
    body = json.dumps({"type": "read", "mbean": RUNTIME, "attribute": "InputArguments"})
    reqs = tbenv.parse_jolokia_post(body.encode())
    assert len(reqs) == 1
    assert reqs[0].attribute == "InputArguments"


def test_parse_post_bulk_list_is_capped():
    body = json.dumps([{"type": "version"}] * 100)
    reqs = tbenv.parse_jolokia_post(body.encode())
    assert len(reqs) == tbenv.JOLOKIA_MAX_BULK_REQUESTS


def test_parse_post_survives_garbage():
    for body in (b"", b"not json", b"[[[", b"null", b'{"type":"nope"}'):
        assert tbenv.parse_jolokia_post(body) == []


# --- Canary spend -------------------------------------------------------


@pytest.mark.parametrize("req", [
    tbenv.JolokiaRequest(type="version"),
    tbenv.JolokiaRequest(type="search", mbean="*:*"),
    tbenv.JolokiaRequest(type="read", mbean=DELEGATE, attribute="ImplementationName"),
    tbenv.JolokiaRequest(type="read", mbean="java.lang:type=Memory", attribute="HeapMemoryUsage"),
])
def test_fingerprint_sweep_spends_no_canary(req):
    """`version` plus the delegate reads are what every stock Jolokia tool
    fires at every host. Minting a credential for those would let the
    population that tells us nothing burn the quota for the one that
    does."""
    assert tbenv.jolokia_request_needs_canary(req) is False


@pytest.mark.parametrize("req", [
    tbenv.JolokiaRequest(type="list"),
    tbenv.JolokiaRequest(type="read", mbean=RUNTIME, attribute="SystemProperties"),
    tbenv.JolokiaRequest(type="read", mbean=RUNTIME, attribute="InputArguments"),
    tbenv.JolokiaRequest(type="exec", mbean=DIAG, operation="vmCommandLine"),
    tbenv.JolokiaRequest(type="exec", mbean=DIAG, operation="vmSystemProperties"),
    tbenv.JolokiaRequest(type="read", mbean=HOUSE, attribute="AwsAccessKeyId"),
])
def test_credential_bearing_members_spend_a_canary(req):
    assert tbenv.jolokia_request_needs_canary(req) is True


# --- Resolution ---------------------------------------------------------


def _resolve(req):
    return tbenv.resolve_jolokia_request(req, AK, SK, tbenv._jolokia_jdbc_url(), "whsec_x")


def test_every_advertised_bean_answers_a_read():
    """The listing publishes the tree; a bean in it that 404s on `read` is
    the cheapest possible proof the listing is canned."""
    for domain, beans in _tree().items():
        for props in beans:
            answer = _resolve(tbenv.JolokiaRequest(type="read", mbean=f"{domain}:{props}"))
            assert answer["status"] == 200, f"{domain}:{props} advertised but unreadable"


def test_every_advertised_attribute_has_a_value():
    for domain, beans in _tree().items():
        for props, bean in beans.items():
            mbean = f"{domain}:{props}"
            for attribute in bean["attr"]:
                answer = _resolve(
                    tbenv.JolokiaRequest(type="read", mbean=mbean, attribute=attribute)
                )
                assert answer["status"] == 200, f"{mbean}/{attribute} advertised but unreadable"
                assert answer["value"] is not None, f"{mbean}/{attribute} reads as null"


def test_every_advertised_operation_executes():
    for domain, beans in _tree().items():
        for props, bean in beans.items():
            mbean = f"{domain}:{props}"
            for operation in bean["op"]:
                answer = _resolve(
                    tbenv.JolokiaRequest(type="exec", mbean=mbean, operation=operation)
                )
                assert answer["status"] == 200, f"{mbean}/{operation} advertised but not callable"


def test_runtime_input_arguments_carry_the_canary():
    answer = _resolve(
        tbenv.JolokiaRequest(type="read", mbean=RUNTIME, attribute="InputArguments")
    )
    assert any(AK in arg for arg in answer["value"])
    assert any(SK in arg for arg in answer["value"])


def test_diagnostic_command_line_carries_the_canary():
    """`vmCommandLine` is the operation the diagnostic bean is swept for —
    it prints the launch flags, which is where the credential lives."""
    answer = _resolve(tbenv.JolokiaRequest(type="exec", mbean=DIAG, operation="vmCommandLine"))
    assert AK in answer["value"]


def test_spring_env_operation_carries_the_canary():
    answer = _resolve(tbenv.JolokiaRequest(
        type="exec", mbean="org.springframework.boot:type=Endpoint,name=Env",
        operation="environment",
    ))
    assert AK in json.dumps(answer["value"])


def test_unknown_mbean_answers_the_agent_error_not_a_drop():
    answer = _resolve(tbenv.JolokiaRequest(type="read", mbean="com.example:type=Nope"))
    assert answer["status"] == 404
    assert answer["error_type"] == "javax.management.InstanceNotFoundException"
    # The echo is what lets a client keep guessing — and every guess is a
    # line in the dictionary we are collecting.
    assert answer["request"]["mbean"] == "com.example:type=Nope"


def test_unknown_attribute_and_operation_are_distinguishable():
    missing_attr = _resolve(
        tbenv.JolokiaRequest(type="read", mbean=RUNTIME, attribute="NoSuchThing")
    )
    assert missing_attr["error_type"] == "javax.management.AttributeNotFoundException"
    missing_op = _resolve(tbenv.JolokiaRequest(type="exec", mbean=DIAG, operation="rm"))
    assert missing_op["error_type"] == "java.lang.IllegalArgumentException"


def test_read_only_attribute_refuses_a_write():
    answer = _resolve(
        tbenv.JolokiaRequest(type="write", mbean=RUNTIME, attribute="Uptime", value="1")
    )
    assert answer["status"] == 400


def test_the_one_writable_attribute_takes_the_write():
    """A mutation that succeeds is a reason to send another one, and what
    the client chooses to change next is worth more than the refusal."""
    answer = _resolve(
        tbenv.JolokiaRequest(type="write", mbean=HOUSE, attribute="LogLevel", value="DEBUG")
    )
    assert answer["status"] == 200
    assert answer["value"] == "INFO"  # real agents return the previous value


def test_search_matches_the_published_names():
    answer = _resolve(tbenv.JolokiaRequest(type="search", mbean="java.lang:*"))
    assert RUNTIME in answer["value"]
    assert DIAG not in answer["value"]


def test_list_subtree_and_miss():
    ok = _resolve(tbenv.JolokiaRequest(type="list", inner_path="com.sun.management"))
    assert "type=DiagnosticCommand" in ok["value"]
    miss = _resolve(tbenv.JolokiaRequest(type="list", inner_path="com.nope"))
    assert miss["status"] == 404


def test_version_reports_an_agent():
    answer = _resolve(tbenv.JolokiaRequest(type="version"))
    assert answer["value"]["agent"] == tbenv.JOLOKIA_AGENT_VERSION
    assert answer["value"]["protocol"] == tbenv.JOLOKIA_PROTOCOL_VERSION


# --- Nothing fixed ------------------------------------------------------


def test_jdbc_password_is_per_hit():
    """Every credential-shaped field is per-hit unique. A fixed one gives
    zero detection on replay and ships the same string to every host."""
    assert tbenv._jolokia_jdbc_url() != tbenv._jolokia_jdbc_url()


def test_uptime_is_not_frozen():
    """A constant here would make every response from every sensor
    byte-identical on a value real agents move every millisecond."""
    tree = _tree()
    assert tree["java.lang"]["type=Runtime"]["attr"]["Uptime"]["rw"] is False
    first = tbenv._jolokia_uptime_ms()
    assert first > 0
    assert "timestamp" in _resolve(tbenv.JolokiaRequest(type="version"))


def test_listing_body_is_not_a_frozen_timestamp():
    body = json.loads(tbenv.render_actuator_jolokia_list(FAKE_TRACEBIT))
    assert body["timestamp"] != 1719567890
    assert body["request"] == {"type": "list"}
    assert body["status"] == 200


def test_listing_and_protocol_answer_from_the_same_tree():
    listing = json.loads(tbenv.render_actuator_jolokia_list(FAKE_TRACEBIT))["value"]
    protocol = _resolve(tbenv.JolokiaRequest(type="list"))["value"]
    assert sorted(listing) == sorted(protocol)
    for domain in listing:
        assert sorted(listing[domain]) == sorted(protocol[domain])


# --- Dispatch -----------------------------------------------------------


def _enable(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "JOLOKIA_PROTOCOL_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


async def test_dispatch_answers_the_read_that_follows_a_listing(flux_client, monkeypatch):
    _enable(monkeypatch)
    resp = await flux_client.get(
        f"/actuator/jolokia/read/{RUNTIME}/InputArguments",
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status == 200
    body = await resp.read()
    assert AK.encode() in body
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "jolokia-read"
    assert entry["jolokiaMBean"] == RUNTIME
    assert entry["jolokiaAttribute"] == "InputArguments"
    assert entry["jolokiaForm"] == "get"
    assert "aws" in entry["canaryTypes"]


async def test_dispatch_answers_the_exec_the_listing_points_at(flux_client, monkeypatch):
    _enable(monkeypatch)
    resp = await flux_client.get(
        f"/actuator/jolokia/exec/{DIAG}/vmSystemProperties",
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status == 200
    assert AK.encode() in await resp.read()
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "jolokia-exec"
    assert entry["jolokiaOperation"] == "vmSystemProperties"


async def test_dispatch_records_the_arguments_an_exec_carried(flux_client, monkeypatch):
    """The arguments are the payload: what the client chose to invoke is
    the thing this trap exists to capture."""
    _enable(monkeypatch)
    await flux_client.get(
        f"/actuator/jolokia/exec/{DIAG}/vmFlags/-XX:+PrintFlagsFinal",
        headers={"X-Forwarded-For": "203.0.113.12"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["jolokiaArgs"] == ["-XX:+PrintFlagsFinal"]


async def test_dispatch_flags_a_bean_only_this_server_publishes(flux_client, monkeypatch):
    _enable(monkeypatch)
    await flux_client.get(
        f"/actuator/jolokia/read/{HOUSE}/AwsAccessKeyId",
        headers={"X-Forwarded-For": "203.0.113.13"},
    )
    house = _log_entries(flux_client.log_path)[-1]
    assert house["jolokiaHouseBean"] is True

    await flux_client.get(
        f"/jolokia/read/{DELEGATE}/ImplementationName",
        headers={"X-Forwarded-For": "203.0.113.14"},
    )
    stock = _log_entries(flux_client.log_path)[-1]
    assert stock["jolokiaHouseBean"] is False


async def test_dispatch_answers_a_bulk_post(flux_client, monkeypatch):
    _enable(monkeypatch)
    resp = await flux_client.post(
        "/jolokia",
        data=json.dumps([
            {"type": "version"},
            {"type": "read", "mbean": RUNTIME, "attribute": "InputArguments"},
        ]),
        headers={"X-Forwarded-For": "203.0.113.15", "Content-Type": "application/json"},
    )
    assert resp.status == 200
    payload = json.loads(await resp.read())
    assert isinstance(payload, list) and len(payload) == 2
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "jolokia-bulk"
    assert entry["jolokiaBulkCount"] == 2
    assert entry["jolokiaForm"] == "post"


async def test_dispatch_tags_a_miss_apart_from_a_hit(flux_client, monkeypatch):
    _enable(monkeypatch)
    resp = await flux_client.get(
        "/actuator/jolokia/read/com.example:type=Nope/Whatever",
        headers={"X-Forwarded-For": "203.0.113.16"},
    )
    assert resp.status == 200
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "jolokia-miss"
    assert entry["jolokiaResolved"] == 0


async def test_dispatch_leaves_junk_below_the_mount_to_the_404(flux_client, monkeypatch):
    """A prefix that answers everything under it announces itself. Only
    real operations are claimed."""
    _enable(monkeypatch)
    resp = await flux_client.get(
        "/actuator/jolokia/nonsense", headers={"X-Forwarded-For": "203.0.113.17"},
    )
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[-1]["result"] == "not-handled"


async def test_dispatch_leaves_the_listing_address_to_the_listing(flux_client, monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    resp = await flux_client.get(
        "/actuator/jolokia/list", headers={"X-Forwarded-For": "203.0.113.18"},
    )
    assert resp.status == 200
    assert _log_entries(flux_client.log_path)[-1]["result"] == "actuator-jolokia"


async def test_disabled_falls_through_to_the_same_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "JOLOKIA_PROTOCOL_ENABLED", False)
    resp = await flux_client.get(
        f"/actuator/jolokia/read/{RUNTIME}/InputArguments",
        headers={"X-Forwarded-For": "203.0.113.19"},
    )
    assert resp.status == 404
    assert _log_entries(flux_client.log_path)[-1]["result"] == "not-handled"


async def test_keyless_deployment_falls_through(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "")
    monkeypatch.setattr(tbenv, "JOLOKIA_PROTOCOL_ENABLED", True)
    resp = await flux_client.get(
        f"/jolokia/exec/{DIAG}/vmCommandLine",
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    assert resp.status == 404


async def test_issuance_failure_looks_like_every_other_404(flux_client, monkeypatch):
    """A canary-backed trap that answers differently when upstream blips
    announces itself fleet-wide at once."""
    async def _no_canary(*args, **kwargs):
        return None

    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "JOLOKIA_PROTOCOL_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _no_canary)
    resp = await flux_client.get(
        f"/jolokia/read/{RUNTIME}/SystemProperties",
        headers={"X-Forwarded-For": "203.0.113.21"},
    )
    assert resp.status == tbenv.CREDENTIAL_FAILURE_STATUS
    assert _log_entries(flux_client.log_path)[-1]["result"] == "jolokia-error"


async def test_fingerprint_read_costs_no_upstream_call(flux_client, monkeypatch):
    called = []

    async def _counting_canary(*args, **kwargs):
        called.append(args)
        return FAKE_TRACEBIT

    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "JOLOKIA_PROTOCOL_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _counting_canary)
    await flux_client.get("/jolokia/version", headers={"X-Forwarded-For": "203.0.113.22"})
    await flux_client.get(
        f"/jolokia/read/{DELEGATE}/MBeanServerId",
        headers={"X-Forwarded-For": "203.0.113.22"},
    )
    assert called == []
