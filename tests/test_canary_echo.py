"""Tests for the canary-echo observer and the inbound webhook receiver.

The two ship together because they answer the same question from
opposite ends: what happens to a credential after this server hands it
out. The observer notices one arriving back; the receiver keeps the
payload it arrives inside of.

Four properties are worth defending here:

1. **The observer never changes a response.** This is the load-bearing
   one. If a request carrying a recognised key were answered even
   slightly differently from one carrying an unrecognised key, anyone
   could test a credential for canary-ness by sending it here and
   diffing. Several tests below exist only to pin that byte-for-byte.
2. **Recognition is learned, never configured.** The issuing account is
   not written down in the source, so `own` and `account` matches have
   to come from keys the process actually served.
3. **The key id is logged; the secret never is.** The id is what joins a
   replay back to its issuance. The secret has no such use.
4. **The receiver matches a delivery address, not everything under
   `/api`.** Neighbouring shapes belong to other surfaces.
"""

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


OWN_KEY = "ASIAEXAMPLE00000AAAA"
SAME_ACCOUNT_KEY = "ASIAEXAMPLE00000BBBB"
FOREIGN_KEY = "AKIAZZZZZZZZZZZZZZZZ"


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    """Every test starts with a server that has issued nothing."""
    monkeypatch.setattr(tbenv, "_CANARY_ECHO_ISSUED", {})
    monkeypatch.setattr(tbenv, "_CANARY_ECHO_ACCOUNT_PREFIXES", set())
    monkeypatch.setattr(tbenv, "CANARY_ECHO_ENABLED", True)


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    monkeypatch.setattr(tbenv, "CANARY_ECHO_ENABLED", True)
    monkeypatch.setattr(tbenv, "WEBHOOK_RECEIVER_ENABLED", True)
    client = await aiohttp_client(tbenv.create_app())
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _log_entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


def _last(log_path):
    return _log_entries(log_path)[-1]


# --- Registry: recognition is learned from what we served ----------------


def test_unissued_key_is_foreign():
    assert tbenv._canary_echo_classify(OWN_KEY) == "foreign"


def test_issued_key_is_own():
    tbenv.canary_echo_note_issued(OWN_KEY)
    assert tbenv._canary_echo_classify(OWN_KEY) == "own"


def test_sibling_key_from_the_same_account_is_account():
    """A key this process never served, from an account it has served
    from, is the only available evidence that a harvest is being
    replayed somewhere other than where it was taken."""
    tbenv.canary_echo_note_issued(OWN_KEY)
    assert tbenv._canary_echo_classify(SAME_ACCOUNT_KEY) == "account"


def test_other_accounts_stay_foreign():
    tbenv.canary_echo_note_issued(OWN_KEY)
    assert tbenv._canary_echo_classify(FOREIGN_KEY) == "foreign"


def test_registry_is_bounded_and_evicts_oldest(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_MAX_KEYS", 16)
    for i in range(40):
        tbenv.canary_echo_note_issued(f"ASIAEXAMPLE0000{i:05d}"[:20])
    assert len(tbenv._CANARY_ECHO_ISSUED) <= 16


def test_reissuing_a_key_keeps_it_from_being_evicted(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_MAX_KEYS", 4)
    keys = [f"ASIAEXAMPLE000000{i:03d}"[:20] for i in range(4)]
    for k in keys:
        tbenv.canary_echo_note_issued(k)
    tbenv.canary_echo_note_issued(keys[0])          # touch the oldest
    tbenv.canary_echo_note_issued("ASIAEXAMPLE00000ZZZZ")  # force one eviction
    assert keys[0] in tbenv._CANARY_ECHO_ISSUED
    assert keys[1] not in tbenv._CANARY_ECHO_ISSUED


def test_prefixes_survive_eviction_of_their_keys(monkeypatch):
    """Evicting a key must not downgrade its account to `foreign` —
    that would make the classification depend on how busy the day was."""
    monkeypatch.setattr(tbenv, "CANARY_ECHO_MAX_KEYS", 16)
    tbenv.canary_echo_note_issued(OWN_KEY)
    for i in range(40):
        tbenv.canary_echo_note_issued(f"ASIAOTHERACCT{i:07d}")
    assert OWN_KEY not in tbenv._CANARY_ECHO_ISSUED
    assert tbenv._canary_echo_classify(OWN_KEY) == "account"


@pytest.mark.parametrize("junk", [
    "", "not-a-key", "ASIASHORT", "akiaexample00000aaaa",
    "ASIAEXAMPLE00000AAAAEXTRA",
])
def test_malformed_key_ids_are_not_registered(junk):
    tbenv.canary_echo_note_issued(junk)
    assert tbenv._CANARY_ECHO_ISSUED == {}


def test_aws_helper_registers_what_it_serves():
    """Renderers reach the canary through `_aws()`; registering there is
    what keeps a newly written renderer covered without it opting in."""
    tbenv._aws({"aws": {"awsAccessKeyId": OWN_KEY, "awsSecretAccessKey": "s"}})
    assert tbenv._canary_echo_classify(OWN_KEY) == "own"


def test_aws_helper_tolerates_missing_and_malformed_records():
    assert tbenv._aws({}) == {}
    assert tbenv._aws({"aws": None}) == {}
    assert tbenv._aws({"aws": {}}) == {}
    assert tbenv._aws({"aws": {"awsAccessKeyId": None}}) == {"awsAccessKeyId": None}
    assert tbenv._CANARY_ECHO_ISSUED == {}


# --- Scanner: where a key can hide --------------------------------------


def test_scan_finds_nothing_in_an_ordinary_request():
    assert tbenv.canary_echo_scan("/wp-login.php", {}, b"") == {}


def test_scan_finds_a_key_in_the_path():
    out = tbenv.canary_echo_scan(f"/api/v1/webhook/{FOREIGN_KEY}/event", {}, b"")
    assert out["canaryEchoKeyIds"] == [FOREIGN_KEY]
    assert out["canaryEchoIn"] == ["target"]
    assert out["canaryEchoCount"] == 1


def test_scan_finds_a_key_in_the_query():
    out = tbenv.canary_echo_scan(f"/admin/config?token={FOREIGN_KEY}", {}, b"")
    assert out["canaryEchoIn"] == ["target"]


def test_scan_finds_a_percent_encoded_key():
    """A key inside a query value usually arrives encoded at least once."""
    raw = "/admin/config?cmd=curl%20-H%20%27Authorization%3A%20Bearer%20" + FOREIGN_KEY + "%27"
    out = tbenv.canary_echo_scan(raw, {}, b"")
    assert out["canaryEchoKeyIds"] == [FOREIGN_KEY]


def test_scan_finds_a_key_in_a_header():
    out = tbenv.canary_echo_scan("/", {"Authorization": f"Bearer {FOREIGN_KEY}"}, b"")
    assert out["canaryEchoIn"] == ["header:authorization"]


def test_scan_finds_a_key_in_the_body():
    out = tbenv.canary_echo_scan("/", {}, b'{"key":"%s"}' % FOREIGN_KEY.encode())
    assert out["canaryEchoIn"] == ["body"]


def test_scan_reports_every_location_a_key_appeared_in():
    out = tbenv.canary_echo_scan(
        f"/x?a={FOREIGN_KEY}", {"X-Key": "AKIABBBBBBBBBBBBBBBB"}, b"ASIACCCCCCCCCCCCCCCC",
    )
    assert out["canaryEchoIn"] == ["body", "header:x-key", "target"]
    assert out["canaryEchoCount"] == 3


def test_scan_ranks_own_above_account_above_foreign():
    tbenv.canary_echo_note_issued(OWN_KEY)
    out = tbenv.canary_echo_scan(
        f"/x?a={FOREIGN_KEY}&b={SAME_ACCOUNT_KEY}&c={OWN_KEY}", {}, b"",
    )
    assert out["canaryEchoMatch"] == "own"
    assert out["canaryEchoKeyIds"][0] == OWN_KEY


def test_reported_key_ids_are_capped(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_MAX_REPORTED", 3)
    target = "/x?" + "&".join(f"k{i}=AKIA{i:016d}" for i in range(20))
    out = tbenv.canary_echo_scan(target, {}, b"")
    assert len(out["canaryEchoKeyIds"]) == 3
    assert out["canaryEchoCount"] == 20, "the cap trims the list, not the count"


def test_cap_keeps_the_interesting_keys(monkeypatch):
    """Truncation must not be able to drop an `own` match in favour of
    foreign noise that happened to sort first."""
    monkeypatch.setattr(tbenv, "CANARY_ECHO_MAX_REPORTED", 2)
    tbenv.canary_echo_note_issued(OWN_KEY)
    noise = "&".join(f"k{i}=AKIA{i:016d}" for i in range(10))
    out = tbenv.canary_echo_scan(f"/x?{noise}&own={OWN_KEY}", {}, b"")
    assert OWN_KEY in out["canaryEchoKeyIds"]


def test_body_scan_is_bounded(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_BODY_SCAN_LIMIT", 256)
    body = b"x" * 4096 + FOREIGN_KEY.encode()
    assert tbenv.canary_echo_scan("/", {}, body) == {}


def test_scan_does_not_mint_keys_out_of_longer_tokens():
    """A base64 blob that happens to contain the shape is not a key."""
    assert tbenv.canary_echo_scan(f"/x?t=PREFIX{FOREIGN_KEY}SUFFIX", {}, b"") == {}


def test_scan_is_disabled_by_its_switch(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_ENABLED", False)
    assert tbenv.canary_echo_scan(f"/x?a={FOREIGN_KEY}", {}, b"") == {}


def test_registry_is_not_written_when_disabled(monkeypatch):
    monkeypatch.setattr(tbenv, "CANARY_ECHO_ENABLED", False)
    tbenv.canary_echo_note_issued(OWN_KEY)
    assert tbenv._CANARY_ECHO_ISSUED == {}


def test_no_issuing_account_is_hardcoded():
    """The registry is empty until something is served. If a prefix were
    ever committed here, this fails — which is the point: the source is
    public, and a baked-in prefix would let anyone test a credential for
    canary-ness offline."""
    assert tbenv._CANARY_ECHO_ACCOUNT_PREFIXES == set()


# --- The observer is invisible to the client ----------------------------


async def test_echo_does_not_change_the_response(flux_client):
    """The whole design rests on this: a recognised key and an
    unrecognised one must produce identical bytes, status and headers."""
    tbenv.canary_echo_note_issued(OWN_KEY)
    known = await flux_client.get(f"/no-such-path?t={OWN_KEY}")
    unknown = await flux_client.get(f"/no-such-path?t={FOREIGN_KEY}")
    plain = await flux_client.get("/no-such-path?t=nothing-special")
    assert known.status == unknown.status == plain.status == 404
    assert await known.read() == await unknown.read() == await plain.read()
    assert known.headers.get("Content-Type") == plain.headers.get("Content-Type")


async def test_echo_is_stamped_on_an_unhandled_path(flux_client):
    tbenv.canary_echo_note_issued(OWN_KEY)
    await flux_client.get(f"/no-such-path?t={OWN_KEY}")
    entry = _last(flux_client.log_path)
    assert entry["result"] == "not-handled"
    assert entry["canaryEchoMatch"] == "own"
    assert entry["canaryEchoKeyIds"] == [OWN_KEY]


async def test_echo_is_stamped_on_a_path_another_trap_owns(flux_client):
    """Stamping happens before dispatch, so a credential echoed at an
    address some other trap answers is recorded just as well as one
    echoed into the 404. A key sent to a served path would otherwise be
    invisible."""
    await flux_client.get(f"/server-status?t={FOREIGN_KEY}")
    entry = _last(flux_client.log_path)
    assert entry["result"] == "server-status-html"
    assert entry["canaryEchoKeyIds"] == [FOREIGN_KEY]


async def test_ordinary_requests_carry_no_echo_fields(flux_client):
    await flux_client.get("/no-such-path")
    entry = _last(flux_client.log_path)
    assert "canaryEchoMatch" not in entry
    assert "canaryEchoKeyIds" not in entry


async def test_the_observer_reports_ids_and_never_secrets(flux_client):
    """Only the id joins a replay to its issuance, so the id is what the
    observer reports. The matching secret is neither matched on nor
    copied into any field this feature adds.

    Scoped to those fields on purpose: `rawTarget` and `query` record
    the request as it arrived and have always done so, which is a
    property of the request, not of what the observer chose to keep.
    """
    secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123"
    await flux_client.get(f"/no-such-path?k={FOREIGN_KEY}&s={secret}")
    entry = _last(flux_client.log_path)
    echo_fields = {k: v for k, v in entry.items() if k.startswith("canaryEcho")}
    assert echo_fields["canaryEchoKeyIds"] == [FOREIGN_KEY]
    assert secret not in json.dumps(echo_fields)


# --- Webhook receiver ---------------------------------------------------


@pytest.mark.parametrize("path,token", [
    ("/api/v1/webhook/abc123/event", "abc123"),
    ("/api/v1/webhooks/abc123/event", "abc123"),
    ("/api/webhook/abc123/event", "abc123"),
    ("/api/v2/webhook/abc123/events", "abc123"),
    ("/api/v1/webhook/abc123/callback", "abc123"),
    ("/api/v1/webhook/abc123/delivery/", "abc123"),
    ("/API/V1/WEBHOOK/abc123/EVENT", "abc123"),
    (f"/api/v1/webhook/{FOREIGN_KEY}/event", FOREIGN_KEY),
    ("/api/v1/webhook/a.b:c-d_e/event", "a.b:c-d_e"),
])
def test_delivery_addresses_are_matched(path, token):
    assert tbenv.webhook_receiver_token(path) == token


@pytest.mark.parametrize("path", [
    "/api/v1/webhook/abc123",        # the subscription, not a delivery
    "/api/v1/webhooks",              # the management collection
    "/api/v1/webhook//event",
    "/api/v1/webhook/ab/event",      # token too short to be one
    "/api/v1/webhook/abc123/event/extra",
    "/webhook/abc123/event",         # not under /api
    "/api/v1/hook/abc123/event",
    "/api/v1/webhook/abc123/event.php",
])
def test_neighbouring_shapes_are_not_claimed(path):
    assert tbenv.webhook_receiver_token(path) is None


def test_receiver_is_disabled_by_its_switch(monkeypatch):
    monkeypatch.setattr(tbenv, "WEBHOOK_RECEIVER_ENABLED", False)
    assert tbenv.webhook_receiver_token("/api/v1/webhook/abc123/event") is None


async def test_delivery_is_acknowledged(flux_client):
    resp = await flux_client.post(
        "/api/v1/webhook/abc123/event",
        data=b'{"event":"test"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 200
    doc = json.loads(await resp.text())
    assert doc["ok"] is True
    assert doc["deliveryId"] and doc["receivedAt"]


async def test_delivery_body_is_kept(flux_client):
    await flux_client.post("/api/v1/webhook/abc123/event", data=b'{"loot":"value"}')
    entry = _last(flux_client.log_path)
    assert entry["result"] == "webhook-delivery"
    assert entry["webhookToken"] == "abc123"
    assert entry["webhookBodyPreview"] == '{"loot":"value"}'
    assert entry["webhookMethod"] == "POST"


async def test_delivery_body_preview_is_bounded(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WEBHOOK_RECEIVER_BODY_PREVIEW_LIMIT", 64)
    await flux_client.post("/api/v1/webhook/abc123/event", data=b"A" * 4096)
    entry = _last(flux_client.log_path)
    assert len(entry["webhookBodyPreview"]) == 64


async def test_delivery_carrying_a_key_is_classified_on_the_same_line(flux_client):
    """The token in a delivery address is sometimes a credential. When
    it is, one line says both that a delivery arrived and whose key it
    was addressed to."""
    tbenv.canary_echo_note_issued(OWN_KEY)
    await flux_client.post(f"/api/v1/webhook/{OWN_KEY}/event", data=b"{}")
    entry = _last(flux_client.log_path)
    assert entry["result"] == "webhook-delivery"
    assert entry["webhookToken"] == OWN_KEY
    assert entry["canaryEchoMatch"] == "own"


async def test_the_acknowledgement_carries_no_credential(flux_client):
    """A receiver has no reason to hand the sender a secret, so there is
    nothing in this response that could become a fixed literal."""
    first = json.loads(await (await flux_client.post(
        "/api/v1/webhook/abc123/event", data=b"{}")).text())
    second = json.loads(await (await flux_client.post(
        "/api/v1/webhook/abc123/event", data=b"{}")).text())
    assert set(first) == {"ok", "deliveryId", "receivedAt"}
    assert first["deliveryId"] != second["deliveryId"]


async def test_receiver_needs_no_upstream_key(flux_client, monkeypatch):
    """The response contains no canary, so a deployment without an
    issuing key still answers deliveries."""
    monkeypatch.setattr(tbenv, "API_KEY", "")
    resp = await flux_client.post("/api/v1/webhook/abc123/event", data=b"{}")
    assert resp.status == 200


async def test_disabled_receiver_falls_through_to_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "WEBHOOK_RECEIVER_ENABLED", False)
    resp = await flux_client.post("/api/v1/webhook/abc123/event", data=b"{}")
    assert resp.status == 404
