"""Tests for the billing / payment-method API trap.

The trap answers an unauthenticated write to a stored-payment-method
endpoint. Two properties are load-bearing and pinned hard here:

1. A submitted card number never reaches the log or the response. Only
   its last four digits survive. If a sender ever posts a real card —
   the case that makes this trap worth building — flux must not be the
   thing that writes it to disk.
2. Nothing in the response is a fixed literal. Every identifier is
   per-request random, so the fleet does not ship one shared string.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from flux import server as tbenv


# The dictionary this trap was built for: every spelling of "add a
# payment method", posted with a card object and no authorisation.
OBSERVED_SWEEP = [
    "/api/account/change_payment",
    "/api/card",
    "/api/user/change_payment",
    "/api/v1/account",
    "/api/v1/account/billing",
    "/api/v1/account/change_payment",
    "/api/v1/account/payment-method",
    "/api/v1/billing/card",
    "/api/v1/billing/payment-methods",
    "/api/v1/billing/payment_methods",
    "/api/v1/card",
    "/api/v1/cards",
    "/api/v1/payment-methods",
    "/api/v1/payment_methods",
    "/api/v1/profile/payment",
    "/api/v1/settings/billing/update-card",
    "/api/v1/user/payment-method",
    "/api/v1/user/payment_method",
    "/billing/update-card",
    "/payment/update-card",
]

# A documented processor test number, which is what an integration
# sweep carries.
TEST_CARD_BODY = json.dumps({
    "cvc": "140",
    "number": "4242424242424242",
    "exp_month": "05",
    "exp_year": "2029",
    "name": "Audit Probe",
}).encode()

# Luhn-valid and NOT a documented test number — the materially
# different event this trap exists to distinguish.
REAL_SHAPED_PAN = "4539578763621486"
REAL_SHAPED_BODY = json.dumps({
    "number": REAL_SHAPED_PAN, "cvc": "921",
    "exp_month": "11", "exp_year": "2028",
}).encode()


@pytest.mark.parametrize("path", OBSERVED_SWEEP)
def test_observed_sweep_is_claimed(path):
    """Every path in the sweep must reach the handler — by address if the
    leaf names a payment instrument, otherwise because the body carries a
    card."""
    claimed = (
        tbenv.is_payment_api_path(path)
        or tbenv.is_payment_api_body_path(path, TEST_CARD_BODY)
    )
    assert claimed, f"sweep path not claimed: {path}"


@pytest.mark.parametrize("path", [
    "/api/v1/account", "/api/v1/accounts", "/api/v1/me", "/api/v1/users",
    "/api/v1/profile/payment", "/api/v1/account/billing", "/api/settings",
])
def test_generic_owner_paths_need_a_card_in_the_body(path):
    """A bare account endpoint is not ours to answer. The generic
    spellings are claimed only because the request carried a card — the
    discriminator is the body, not the address."""
    assert not tbenv.is_payment_api_path(path), (
        f"{path} must not be claimed on address alone"
    )
    assert not tbenv.is_payment_api_body_path(path, b"")
    assert not tbenv.is_payment_api_body_path(path, b'{"page":2}')
    assert tbenv.is_payment_api_body_path(path, TEST_CARD_BODY)


@pytest.mark.parametrize("path", [
    "/.env", "/wp-login.php", "/api/v1/users/1/posts", "/discard",
    "/api/v1/webhook/tok123/event", "/cards.php", "/index.html",
    "/api/v1/billing/payment-methods/pm_1/extra", "/graphql",
    "/api/v1/orders", "/api/v1/invoices/42/lines",
])
def test_unrelated_paths_are_never_claimed(path):
    """Neither tier may claim these, card in the body or not."""
    assert not tbenv.is_payment_api_path(path)
    assert not tbenv.is_payment_api_body_path(path, TEST_CARD_BODY)


def test_webhook_receiver_still_wins_its_own_shape():
    """The two late-chain `/api/...` traps must not overlap."""
    path = "/api/v1/webhooks/abcd1234/event"
    assert tbenv.is_webhook_receiver_path(path)
    assert not tbenv.is_payment_api_path(path)
    assert not tbenv.is_payment_api_body_path(path, TEST_CARD_BODY)


def test_luhn_and_brand():
    assert tbenv._luhn_ok("4242424242424242")
    assert tbenv._luhn_ok(REAL_SHAPED_PAN)
    assert not tbenv._luhn_ok("4242424242424243")
    assert not tbenv._luhn_ok("1234")
    assert not tbenv._luhn_ok("not-a-card")
    assert tbenv._card_brand("4242424242424242") == "visa"
    assert tbenv._card_brand("5555555555554444") == "mastercard"
    assert tbenv._card_brand("378282246310005") == "amex"


def test_card_facts_keep_only_the_last_four():
    facts = tbenv._payment_card_facts(TEST_CARD_BODY)
    assert facts["paymentCardLast4"] == "4242"
    assert facts["paymentCardBrand"] == "visa"
    assert facts["paymentCardLuhnValid"] is True
    assert facts["paymentCardTestRange"] is True
    assert facts["paymentCardholderName"] == "Audit Probe"
    # The number itself must appear nowhere in what we extracted.
    assert "4242424242424242" not in json.dumps(facts)


def test_card_facts_separate_test_range_from_luhn_valid():
    """The discriminating pair: a documented test number is an
    integration sweep, a Luhn-valid number that is not one is not."""
    facts = tbenv._payment_card_facts(REAL_SHAPED_BODY)
    assert facts["paymentCardLuhnValid"] is True
    assert facts["paymentCardTestRange"] is False
    assert facts["paymentCardLast4"] == REAL_SHAPED_PAN[-4:]
    assert REAL_SHAPED_PAN not in json.dumps(facts)


def test_card_facts_read_form_encoding_too():
    facts = tbenv._payment_card_facts(
        b"number=4242424242424242&cvc=123&exp_month=4&exp_year=2030"
    )
    assert facts["paymentCardLast4"] == "4242"
    assert facts["paymentCardTestRange"] is True


def test_body_carries_card_detects_nested_card_objects():
    assert tbenv.body_carries_card(TEST_CARD_BODY)
    assert tbenv.body_carries_card(b'{"card":{"number":"4242424242424242"}}')
    assert tbenv.body_carries_card(b"number=4111111111111111&cvv=999")
    assert not tbenv.body_carries_card(b'{"page":1,"limit":20}')
    assert not tbenv.body_carries_card(b"")
    assert not tbenv.body_carries_card(b"not json at all")


def test_redact_pans_replaces_card_shaped_runs():
    """Free-text redaction, including separator-spaced numbers."""
    out = tbenv._redact_pans('{"number":"4242424242424242"}')
    assert "4242424242424242" not in out
    assert "4242" in out
    spaced = tbenv._redact_pans("pan: 4242 4242 4242 4242 end")
    assert "4242 4242 4242 4242" not in spaced
    # A number that is not card-shaped is left alone — order ids and
    # timestamps must survive the preview intact.
    assert tbenv._redact_pans("order 12345") == "order 12345"


def test_payment_method_object_has_no_fixed_literals():
    """Every identifier is per-request random: the fleet must not ship
    one shared string."""
    a = tbenv._payment_method_object()
    b = tbenv._payment_method_object()
    assert a["id"] != b["id"]
    assert a["customer"] != b["customer"]
    assert a["card"]["fingerprint"] != b["card"]["fingerprint"]
    assert str(a["id"]).startswith("pm_")


# --- dispatch ---------------------------------------------------------


@pytest_asyncio.fixture
async def flux_client(aiohttp_client, monkeypatch, tmp_path):
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "env-canary.jsonl")
    app = tbenv.create_app()
    client = await aiohttp_client(app)
    client.log_path = tmp_path / "env-canary.jsonl"
    return client


def _entries(log_path):
    return [json.loads(line) for line in log_path.read_text().splitlines()]


async def test_post_card_is_accepted_and_logged(flux_client, monkeypatch):
    """The write the sweep came for: 201 and a created payment method."""
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.post(
        "/api/v1/billing/payment-methods",
        data=TEST_CARD_BODY,
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.9"},
    )
    assert resp.status == 201
    payload = await resp.json()
    assert payload["object"] == "payment_method"
    assert payload["card"]["last4"] == "4242"
    assert payload["card"]["brand"] == "visa"
    # The response names its follow-ups so a parsing client has a next step.
    assert payload["links"]["set_default"].endswith("/default")
    assert payload["links"]["payouts"] == "/api/v1/payouts"

    entry = _entries(flux_client.log_path)[0]
    assert entry["result"] == "payment-api-probe"
    assert entry["paymentApiAction"] == "create"
    assert entry["paymentCardLast4"] == "4242"
    assert entry["paymentCardTestRange"] is True
    assert entry["clientIp"] == "203.0.113.9"


async def test_submitted_card_number_never_reaches_the_log(flux_client, monkeypatch):
    """The invariant that matters most. A real card posted here must not
    be written to disk by flux — only its last four digits."""
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.post(
        "/api/v1/cards",
        data=REAL_SHAPED_BODY,
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status == 201
    raw_log = flux_client.log_path.read_text()
    assert REAL_SHAPED_PAN not in raw_log, "full card number leaked into the log"
    assert REAL_SHAPED_PAN[-4:] in raw_log
    # ...nor into the response body.
    assert REAL_SHAPED_PAN not in await resp.text()
    entry = _entries(flux_client.log_path)[0]
    assert entry["paymentCardLuhnValid"] is True
    assert entry["paymentCardTestRange"] is False


async def test_get_returns_a_listing(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.get(
        "/api/v1/payment_methods",
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status == 200
    payload = await resp.json()
    assert payload["object"] == "list"
    assert len(payload["data"]) == 2
    ids = {item["id"] for item in payload["data"]}
    assert len(ids) == 2, "listing must not repeat one identifier"
    assert _entries(flux_client.log_path)[0]["paymentApiAction"] == "list"


async def test_delete_is_turned_away_by_the_global_method_gate(flux_client, monkeypatch):
    """Pins the real behaviour, which is not this trap's to change.

    `handle` allows only GET/HEAD/POST, so DELETE never reaches any
    handler. The trap's delete branch is therefore unreachable today —
    it is written and tested at the unit level so that widening the gate
    is a one-line decision rather than a second implementation, but this
    test exists so nobody reads the branch and concludes DELETE works.
    """
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.delete(
        "/api/v1/payment_methods/pm_abc123",
        headers={"X-Forwarded-For": "203.0.113.12"},
    )
    assert resp.status == 405
    assert _entries(flux_client.log_path)[0]["result"] == "method-not-allowed"


async def test_delete_branch_acknowledges_when_reached(monkeypatch, tmp_path):
    """The delete branch itself, exercised directly past the gate."""
    from aiohttp.test_utils import make_mocked_request
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "log.jsonl")
    path = "/api/v1/payment_methods/pm_abc123"
    req = make_mocked_request("DELETE", path)
    resp = await tbenv._handle_payment_api(req, {}, path, b"")
    assert resp.status == 200
    payload = json.loads(resp.body)
    assert payload["deleted"] is True
    assert payload["id"] == "pm_abc123"
    entry = _entries(tmp_path / "log.jsonl")[0]
    assert entry["paymentApiAction"] == "delete"
    assert entry["paymentApiResourceId"] == "pm_abc123"


async def test_put_branch_updates_when_reached(monkeypatch, tmp_path):
    """Same for the update branch — 200 rather than 201, card echoed."""
    from aiohttp.test_utils import make_mocked_request
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    monkeypatch.setattr(tbenv, "LOG_PATH", tmp_path / "log.jsonl")
    path = "/api/v1/settings/billing/update-card"
    req = make_mocked_request("PUT", path)
    resp = await tbenv._handle_payment_api(req, {}, path, TEST_CARD_BODY)
    assert resp.status == 200
    payload = json.loads(resp.body)
    assert payload["card"]["last4"] == "4242"
    assert _entries(tmp_path / "log.jsonl")[0]["paymentApiAction"] == "update"


async def test_two_writes_share_no_identifier(flux_client, monkeypatch):
    """Per-hit uniqueness end to end, not just in the object builder."""
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    seen = set()
    for _ in range(3):
        resp = await flux_client.post(
            "/api/v1/cards", data=TEST_CARD_BODY,
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "203.0.113.13"},
        )
        payload = await resp.json()
        seen.add(payload["id"])
    assert len(seen) == 3


async def test_disabled_returns_404(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", False)
    resp = await flux_client.post(
        "/api/v1/billing/payment-methods",
        data=TEST_CARD_BODY,
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.14"},
    )
    assert resp.status == 404
    assert _entries(flux_client.log_path)[0]["result"] == "not-handled"


async def test_generic_account_path_without_a_card_still_404s(flux_client, monkeypatch):
    """The tier-B gate at dispatch, not just in the predicate: a bare
    account endpoint with no card must fall through to the 404."""
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.post(
        "/api/v1/account", data=b'{"page":1}',
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.15"},
    )
    assert resp.status == 404
    assert _entries(flux_client.log_path)[0]["result"] == "not-handled"


async def test_generic_account_path_with_a_card_is_answered(flux_client, monkeypatch):
    monkeypatch.setattr(tbenv, "PAYMENT_API_ENABLED", True)
    resp = await flux_client.post(
        "/api/v1/account", data=TEST_CARD_BODY,
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "203.0.113.16"},
    )
    assert resp.status == 201
    assert _entries(flux_client.log_path)[0]["paymentApiAction"] == "create"
