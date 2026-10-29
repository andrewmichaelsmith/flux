"""Tests for the fake Apache Solr admin API + Velocity-template RCE trap.

Solr's admin API answers unauthenticated on a default install. Scanners
walk `/solr/admin/info/system?wt=json` and `/solr/admin/cores?...` for the
version and core list, then -- on a box they think is exploitable -- run the
CVE-2019-17558 chain: `POST /solr/<core>/config` enables the params resource
loader, and `GET /solr/<core>/select?wt=velocity&v.template.custom=<vtl>`
executes an attacker Velocity template.

Three properties carry this family and each is tested below:

* **Matching is exact on the admin leaves and regex on the attacker-named
  core segment, never a bare `/solr/` prefix.** `/solr/.env`,
  `/solr/%2eenv` and `/var/www/html/solr/.env` are a different population
  already served by the env-canary module, so the must-not-match cases are
  load-bearing.

* **The admin API answers without auth** -- that is the bug being imitated.

* **The `v.template.custom` extractor has to survive a real
  form-urlencoded Velocity payload**, with `+`-as-space, `%23`/`%27`
  encodings and a `%2B`-encoded literal plus, which a naive splitter would
  corrupt. The round-trip of a genuine specimen is the point of the trap.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_rows(client):
    if not client.log_path.exists():
        return []
    return [
        json.loads(line)
        for line in client.log_path.read_text().splitlines()
        if line.strip()
    ]


# A genuine CVE-2019-17558 Velocity RCE payload, exactly as it rides the
# query string: spaces as `+`, `#`/`'` as `%23`/`%27`. Decoded it is:
#   #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
#   $rt.getRuntime().exec('id')
_VELOCITY_RAW = (
    "%23set(%24x%3D%27%27)%23set(%24rt%3D%24x.class.forName(%27java.lang.Runtime%27))"
    "%24rt.getRuntime().exec(%27id%27)"
)
_VELOCITY_DECODED = (
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
    "$rt.getRuntime().exec('id')"
)


# --- registration / path matching --------------------------------------

def test_solr_enabled_by_default():
    assert tbenv.SOLR_ENABLED


MUST_MATCH = [
    "/solr",
    "/solr/",
    "/solr/index.html",
    "/solr/admin",
    "/solr/admin/info/system",
    "/solr/admin/info/properties",
    "/solr/admin/cores",
    "/solr/test/select",
    "/solr/collection1/config",
    "/solr/gettingstarted/admin/ping",
    "/solr/techproducts/dataimport",
    "/SOLR/ADMIN/CORES",
]

MUST_NOT_MATCH = [
    "/solr/.env",
    "/solr/%2eenv",
    "/var/www/html/solr/.env",
    "/solrpanel/login",
    "/solr-admin/x",
    "/solr/admin/../../etc/passwd",
    "/",
    "/webui/",
]


def test_premise_match_set_nonempty():
    # Guard against a helper that silently classifies nothing -- every
    # assertion below would then pass vacuously.
    assert [p for p in MUST_MATCH if tbenv._solr_family(p)]


@pytest.mark.parametrize("path", MUST_MATCH)
def test_must_match(path):
    assert tbenv.is_solr_path(path), path


@pytest.mark.parametrize("path", MUST_NOT_MATCH)
def test_must_not_match(path):
    assert not tbenv._solr_family(path), path


def test_disabled_switch_stops_matching(monkeypatch):
    monkeypatch.setattr(tbenv, "SOLR_ENABLED", False)
    assert not tbenv.is_solr_path("/solr/admin/cores")


# --- velocity template extractor (the round-trip that matters) ---------

def test_velocity_template_round_trips_a_real_payload():
    got = tbenv.solr_velocity_template(
        "q=1&wt=velocity&v.template=custom&v.template.custom=" + _VELOCITY_RAW,
        b"", "",
    )
    assert got == _VELOCITY_DECODED


def test_velocity_template_preserves_encoded_plus():
    # `%2B` is a literal `+` inside a Java expression; form decoding must
    # restore it, not turn it into a space.
    got = tbenv.solr_velocity_template(
        "v.template.custom=%24a%2B%24b", b"", "",
    )
    assert got == "$a+$b"


def test_velocity_template_from_post_body():
    got = tbenv.solr_velocity_template(
        "", b"v.template.custom=" + _VELOCITY_RAW.encode(),
        "application/x-www-form-urlencoded",
    )
    assert got == _VELOCITY_DECODED


def test_velocity_template_absent_returns_empty():
    assert tbenv.solr_velocity_template("q=*:*&wt=json", b"", "") == ""


# --- end-to-end through the server -------------------------------------

async def test_system_info_is_fingerprint(flux_client):
    resp = await flux_client.get("/solr/admin/info/system?wt=json")
    assert resp.status == 200
    body = await resp.json()
    assert body["lucene"]["solr-spec-version"] == tbenv._SOLR_VERSION
    rows = _log_rows(flux_client)
    assert rows[-1]["result"] == "solr-system-info"


async def test_cores_status(flux_client):
    resp = await flux_client.get("/solr/admin/cores?action=STATUS&wt=json")
    assert resp.status == 200
    body = await resp.json()
    assert body["status"]  # at least one core listed
    assert _log_rows(flux_client)[-1]["result"] == "solr-cores-status"


async def test_core_create_action_is_tagged(flux_client):
    resp = await flux_client.get(
        "/solr/admin/cores?action=CREATE&name=test&instanceDir=test&wt=json"
    )
    assert resp.status == 200
    row = _log_rows(flux_client)[-1]
    assert row["result"] == "solr-core-action"
    assert row["solrCoreAction"] == "create"
    assert row["solrCoreName"] == "test"


async def test_config_post_captures_body(flux_client):
    payload = json.dumps({
        "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "params.resource.loader.enabled": "true",
        }
    }).encode()
    resp = await flux_client.post("/solr/test/config", data=payload)
    assert resp.status == 200
    row = _log_rows(flux_client)[-1]
    assert row["result"] == "solr-config-post"
    assert row["solrCore"] == "test"
    assert "params.resource.loader.enabled" in row["solrConfigBodyPreview"]
    assert row["solrConfigBodyLen"] == len(payload)


async def test_velocity_select_captures_payload_and_flags_rce(flux_client):
    resp = await flux_client.get(
        "/solr/test/select?q=1&wt=velocity&v.template=custom&v.template.custom="
        + _VELOCITY_RAW
    )
    assert resp.status == 200
    row = _log_rows(flux_client)[-1]
    assert row["result"] == "solr-velocity-exec"
    assert row["solrVelocityTemplate"] == _VELOCITY_DECODED
    assert row["solrVelocityHasRce"] is True


async def test_plain_select_is_probe_not_exec(flux_client):
    resp = await flux_client.get("/solr/test/select?q=*:*&wt=json")
    assert resp.status == 200
    assert _log_rows(flux_client)[-1]["result"] == "solr-select-probe"


async def test_env_under_solr_is_not_solr(flux_client):
    # The env-canary module owns `/solr/.env`; the Solr trap must not steal
    # it. The row, whatever its result, must not be a Solr tag.
    resp = await flux_client.get(
        "/solr/.env", headers={"X-Forwarded-For": "203.0.113.9"}
    )
    rows = _log_rows(flux_client)
    assert rows, "request should have logged"
    assert not str(rows[-1].get("result", "")).startswith("solr-")
