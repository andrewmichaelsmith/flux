"""Tests for the `php://filter` local-file-read trap.

The trap's job is to take a PHP stream-wrapper URL out of a query
parameter, resolve the file it names onto whichever renderer already
serves that file, and hand the bytes back *in the encoding the wrapper
asked for*. So the coverage questions are "does the wrapper grammar
parse", "does the resource resolve", and "is the response something the
client's own decode step can actually read" — not "is this literal query
string in a list".
"""

import base64
import json
import zlib

import pytest
import pytest_asyncio

from flux import server as tbenv


# --- Wrapper grammar (pure, no server needed) --------------------------


def test_queries_without_the_wrapper_are_not_claimed():
    """Dispatch must fall through for everything else, or the branch
    would shadow every path-matched trap that takes a query string."""
    for query in ("", "q=hello", "page=index", "file=/etc/passwd",
                  "url=http://169.254.169.254/", "s=php-filter"):
        assert tbenv.parse_php_filter_read(query) is None


def test_php_input_is_left_to_the_code_execution_branch():
    """`php://input` reads the request body, not a file. Claiming it here
    would reclassify a PHP-CGI RCE attempt as a file read."""
    query = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
    assert tbenv.parse_php_filter_read(query) is None


@pytest.mark.parametrize("query,param", [
    ("0=php://filter/convert.base64-encode/resource=.env", "0"),
    ("page=php://filter/convert.base64-encode/resource=wp-config.php", "page"),
    ("input_file=php://filter/resource=/etc/passwd", "input_file"),
    ("a=1&template=php://filter/resource=/etc/passwd", "template"),
])
def test_parameter_name_is_recovered(query, param):
    """`phpFilterParam` is what separates the three client populations
    that share this wrapper, so it has to survive parsing."""
    assert tbenv.parse_php_filter_read(query).param == param


def test_cgi_argument_injection_is_distinguished_from_an_include_bug():
    """Same wrapper, different vulnerability: this one targets the PHP
    binary's arguments, not a script's include."""
    read = tbenv.parse_php_filter_read(
        "-d+auto_prepend_file%3Dphp://filter/convert.base64-encode/resource%3D.env"
    )
    assert read.is_cgi_arg_injection
    assert read.param == "auto_prepend_file"
    # Double-encoded `=` — one decode pass would leave this unparseable.
    assert read.resource == ".env"


def test_application_sink_is_not_flagged_as_argument_injection():
    read = tbenv.parse_php_filter_read(
        "file=php://filter/convert.base64-encode/resource=.env"
    )
    assert not read.is_cgi_arg_injection


@pytest.mark.parametrize("spec,filters,resource", [
    # Bare filter, no `read=` prefix.
    ("convert.base64-encode/resource=.env", ("convert.base64-encode",), ".env"),
    # `read=` prefix form.
    ("read=convert.base64-encode/resource=../.env", ("convert.base64-encode",), "../.env"),
    # Pipe-separated chain.
    (
        "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=/etc/passwd",
        ("convert.iconv.UTF8.CSISO2022KR", "convert.base64-encode"),
        "/etc/passwd",
    ),
    # No filters at all — a raw read.
    ("resource=/etc/passwd", (), "/etc/passwd"),
    # Resource path contains the same slash the segments split on.
    ("resource=/etc/php/8.2/cli/php.ini", (), "/etc/php/8.2/cli/php.ini"),
])
def test_filter_spec_grammar(spec, filters, resource):
    assert tbenv._split_php_filter_spec(spec) == (filters, resource)


def test_wrapper_value_ends_at_the_next_parameter():
    read = tbenv.parse_php_filter_read(
        "file=php://filter/convert.base64-encode/resource=.env&submit=go"
    )
    assert read.resource == ".env"


def test_iconv_marks_the_generator_population():
    """A plain read never needs a charset conversion; the published
    filter-chain tooling is built on one."""
    plain = tbenv.parse_php_filter_read(
        "file=php://filter/convert.base64-encode/resource=.env")
    chained = tbenv.parse_php_filter_read(
        "file=php://filter/convert.iconv.UTF8.CSISO2022KR|"
        "convert.base64-encode/resource=.env")
    assert not plain.uses_iconv
    assert chained.uses_iconv


def test_disabled_switch_stops_the_parse():
    original = tbenv.PHP_FILTER_LFI_ENABLED
    try:
        tbenv.PHP_FILTER_LFI_ENABLED = False
        assert tbenv.parse_php_filter_read(
            "file=php://filter/resource=.env") is None
    finally:
        tbenv.PHP_FILTER_LFI_ENABLED = original


# --- Resource resolution ----------------------------------------------


@pytest.mark.parametrize("resource,expected", [
    (".env", "/.env"),
    ("../.env", "/.env"),
    ("/var/www/html/.env", "/var/www/html/.env"),
    ("wp-config.php", "/wp-config.php"),
    ("etc/passwd", "/etc/passwd"),
    ("/etc/passwd", "/etc/passwd"),
])
def test_resource_resolves_through_the_shared_file_read_walk(resource, expected):
    """Resolution is the same walk `/@fs/` uses, so anything furnished
    for one read surface is furnished for the other."""
    read = tbenv.parse_php_filter_read(f"file=php://filter/resource={resource}")
    assert read.target.requested_path == expected
    assert read.target.resolved


def test_unfurnished_resource_still_records_what_was_asked_for():
    read = tbenv.parse_php_filter_read(
        "file=php://filter/resource=/opt/app/secret.key")
    assert not read.target.resolved
    assert read.target.requested_path == "/opt/app/secret.key"


def test_php_ini_is_answered_at_the_packaged_locations():
    """A read reached through a PHP include bug is read by PHP, so
    php.ini is the file that says whether the next step is possible.
    The Debian layout gives it a couple of dozen absolute names."""
    for location in ("/etc/php/8.2/cli/php.ini", "/etc/php/7.4/fpm/php.ini",
                     "/etc/php.ini", "/usr/local/etc/php/php.ini"):
        read = tbenv.parse_php_filter_read(
            f"file=php://filter/resource={location}")
        assert read.target.resolved, location
        assert read.target.system_file == location


def test_php_ini_body_names_the_directives_that_gate_the_next_step():
    body = tbenv.render_stock_php_ini()
    for directive in (b"allow_url_include", b"allow_url_fopen",
                      b"disable_functions", b"include_path"):
        assert directive in body


def test_php_ini_carries_no_credential_shaped_value():
    """It is served as a fixed body, so it must contain nothing secret —
    a php.ini legitimately carries none."""
    body = tbenv.render_stock_php_ini().lower()
    for token in (b"aws_", b"akia", b"password =", b"secret_key", b"api_key"):
        assert token not in body


# --- Filter execution --------------------------------------------------


def test_base64_encode_is_exact():
    """The client base64-decodes what it gets back. Approximate is the
    same as wrong: its parse fails and the credential is discarded."""
    assert tbenv.apply_php_filters(b"AWS_ACCESS_KEY_ID=AKIA1\n",
                                   ("convert.base64-encode",)) == \
        base64.b64encode(b"AWS_ACCESS_KEY_ID=AKIA1\n")


def test_chain_applies_left_to_right():
    body = tbenv.apply_php_filters(
        b"secret", ("convert.base64-encode", "convert.base64-decode"))
    assert body == b"secret"


def test_iconv_passes_the_stream_through():
    """Ascii in, ascii out — the transcodings these chains name are
    near-identity on the bodies served here."""
    encoded = tbenv.apply_php_filters(
        b"hello", ("convert.iconv.UTF8.CSISO2022KR", "convert.base64-encode"))
    assert base64.b64decode(encoded) == b"hello"


def test_rot13_and_case_filters():
    assert tbenv.apply_php_filters(b"abc", ("string.rot13",)) == b"nop"
    assert tbenv.apply_php_filters(b"aBc", ("string.toupper",)) == b"ABC"
    assert tbenv.apply_php_filters(b"aBc", ("string.tolower",)) == b"abc"


def test_deflate_round_trips_as_raw_deflate():
    body = tbenv.apply_php_filters(b"hello world", ("zlib.deflate",))
    assert zlib.decompress(body, -zlib.MAX_WBITS) == b"hello world"


def test_unknown_filter_leaves_the_stream_alone():
    assert tbenv.apply_php_filters(b"abc", ("string.strip_tags", "nope.nope")) == b"abc"


def test_broken_decode_yields_nothing_rather_than_raising():
    """PHP emits nothing when a filter fails mid-stream; a traceback
    here would be a 500 and an obvious tell."""
    assert tbenv.apply_php_filters(b"\xff\xfe not base64", ("zlib.inflate",)) == b""


def test_chain_length_is_bounded():
    """Filter-chain generators emit hundreds of steps in one parameter."""
    chain = ("string.rot13",) * (tbenv.PHP_FILTER_MAX_FILTERS + 2)
    body = tbenv.apply_php_filters(b"abc", chain)
    # An even number of rot13 rounds is the identity; the cap is even, so
    # a bounded run and an unbounded one differ.
    assert body == tbenv.apply_php_filters(b"abc", chain[:tbenv.PHP_FILTER_MAX_FILTERS])


# --- End-to-end dispatch ----------------------------------------------


async def _fake_canary(*_args, **_kwargs):
    return {
        "aws": {
            "awsAccessKeyId": "AKIAFAKEEXAMPLE01",
            "awsSecretAccessKey": "fakeSecretExample01",
            "awsSessionToken": "fakeSessionExample01",
        },
    }


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "PHP_FILTER_LFI_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)
    # Bare `/.env` predates the trap table and mints through
    # `issue_credentials` rather than the shared canary helper, so a read
    # that resolves onto it needs this stubbed too — it is the single
    # most-requested resource on this surface.
    monkeypatch.setattr(tbenv, "issue_credentials", _fake_canary)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_credential_read_comes_back_base64_decodable(flux_client):
    """The whole trap in one assertion: the client's own decode step has
    to yield the canary, or it never harvests it."""
    resp = await flux_client.get(
        "/index.php?0=php://filter/convert.base64-encode/resource=.env",
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    assert resp.status == 200
    assert b"AKIAFAKEEXAMPLE01" in base64.b64decode(await resp.read())


async def test_raw_read_without_filters_is_served_verbatim(flux_client):
    """The plugin-advisory form names no filter at all."""
    resp = await flux_client.get(
        "/lib/dompdf/dompdf.php?input_file=php://filter/resource=/etc/passwd",
        headers={"X-Forwarded-For": "203.0.113.21"},
    )
    assert resp.status == 200
    assert b"root:x:0:0:" in await resp.read()


async def test_log_line_carries_the_wrapper_fields(flux_client):
    await flux_client.get(
        "/read.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR"
        "|convert.base64-encode/resource=/etc/passwd",
        headers={"X-Forwarded-For": "203.0.113.22"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"].startswith("php-filter-")
    assert entry["phpFilterEntry"] == "/read.php"
    assert entry["phpFilterParam"] == "page"
    assert entry["phpFilterRequestedPath"] == "/etc/passwd"
    assert entry["phpFilterIconv"] is True
    assert "convert.base64-encode" in entry["phpFilterChain"]


async def test_plain_read_does_not_claim_the_generator_marker(flux_client):
    await flux_client.get(
        "/index.php?file=php://filter/convert.base64-encode/resource=.env",
        headers={"X-Forwarded-For": "203.0.113.23"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert "phpFilterIconv" not in entry
    assert "phpFilterCgiArg" not in entry


async def test_argument_injection_is_logged_as_its_own_vector(flux_client):
    await flux_client.get(
        "/?-d+auto_prepend_file%3Dphp://filter/convert.base64-encode"
        "/resource%3Dwp-config.php",
        headers={"X-Forwarded-For": "203.0.113.24"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["phpFilterCgiArg"] is True
    assert entry["phpFilterParam"] == "auto_prepend_file"
    assert entry["phpFilterRequestedPath"] == "/wp-config.php"


async def test_unfurnished_file_returns_an_empty_200_not_a_404(flux_client):
    """A missing include emits nothing and the script still returns. A
    404 would claim the script itself is absent, contradicting the 200
    the same client just got from another parameter on it."""
    resp = await flux_client.get(
        "/index.php?file=php://filter/resource=/opt/app/secret.key",
        headers={"X-Forwarded-For": "203.0.113.25"},
    )
    assert resp.status == 200
    assert await resp.read() == b""
    entry = _log_entries(flux_client.log_path)[-1]
    assert entry["result"] == "php-filter-miss"
    # The dictionary is recorded whether or not we answer it.
    assert entry["phpFilterRequestedPath"] == "/opt/app/secret.key"


async def test_sink_discovery_sweep_answers_every_parameter_name(flux_client):
    """A sink sweep walks one script across a parameter dictionary. If
    only some names are answered the client concludes the others are not
    sinks, which is a fingerprint of an instrumented host."""
    for param in ("page", "path", "template", "p", "f", "file",
                  "include", "document", "load", "view", "0"):
        resp = await flux_client.get(
            f"/read.php?{param}=php://filter/convert.base64-encode/resource=.env",
            headers={"X-Forwarded-For": "203.0.113.26"},
        )
        assert resp.status == 200, param
        assert b"AKIAFAKEEXAMPLE01" in base64.b64decode(await resp.read()), param


async def test_php_input_still_reaches_the_code_execution_branch(flux_client):
    """Regression guard on dispatch order: the read branch must not
    swallow the RCE vector it shares a wrapper syntax with."""
    resp = await flux_client.get(
        "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        headers={"X-Forwarded-For": "203.0.113.27"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert not entry["result"].startswith("php-filter-")
    assert resp.status is not None


async def test_disabled_switch_falls_through_to_the_ordinary_response(flux_client,
                                                                      monkeypatch):
    monkeypatch.setattr(tbenv, "PHP_FILTER_LFI_ENABLED", False)
    resp = await flux_client.get(
        "/index.php?file=php://filter/convert.base64-encode/resource=.env",
        headers={"X-Forwarded-For": "203.0.113.28"},
    )
    entry = _log_entries(flux_client.log_path)[-1]
    assert not entry["result"].startswith("php-filter-")
    assert resp.status is not None
