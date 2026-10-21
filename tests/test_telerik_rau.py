"""Tests for the Telerik UI RadAsyncUpload handler trap.

`Telerik.Web.UI.WebResource.axd?type=rau` is the registration check a
CVE-2019-18935 exploit makes before it fires. Three properties carry the
family and each has tests below:

* **The query parameter is the discriminator, not the path.** Bare
  `WebResource.axd` is ASP.NET's own static web-resource handler, which
  404s without a valid resource reference. So a path hit carrying no
  `type=rau` is answered 404 *on purpose* — that separates a sender doing
  the real fingerprint check from one replaying a path list, and it is
  not a renderer gap for a later sweep to "close".

* **The fingerprint body is byte-exact, including the product's typo.**
  The shipped notice misspells "succesfully". A corrected spelling is
  itself a tell, so this is the one response in the trap with no per-hit
  variation — it carries no secret, and being identical to the real
  handler is the entire point.

* **Everything opaque in the upload receipt is per-hit unique.** A fixed
  `metaData` blob or temp filename would ship one identical string from
  every sensor, so a replay could recognise the trap by it.
"""

import json

import pytest

from flux import server as tbenv


# --- registration / path matching --------------------------------------

def test_telerik_rau_enabled_by_default():
    assert tbenv.TELERIK_RAU_ENABLED


@pytest.mark.parametrize("path", [
    "/Telerik.Web.UI.WebResource.axd",
    "/telerik.web.ui.webresource.axd",
    "/TELERIK.WEB.UI.WEBRESOURCE.AXD",
    "/Telerik.Web.UI.WebResource.axd/",
])
def test_telerik_rau_matches_observed_spellings(path):
    """IIS resolves paths case-insensitively and the handler is
    registered at the application root, so these are all the same
    endpoint on a real deployment."""
    assert tbenv.is_telerik_rau_path(path)


@pytest.mark.parametrize("path", [
    "/",
    "/.env",
    "/Telerik.Web.UI.DialogHandler.aspx",
    "/Telerik.Web.UI.WebResource.axd/extra",
    "/app/Telerik.Web.UI.WebResource.axd",
    "/ScriptResource.axd",
    "/WebResource.axd",
    "/telerik.web.ui.webresource",
])
def test_telerik_rau_non_match(path):
    """Matched at the webroot only. An unbounded prefix walk on a `.axd`
    suffix would take traffic belonging to the other ASP.NET traps, and
    the observed probes spell it bare."""
    assert not tbenv.is_telerik_rau_path(path)


def test_telerik_rau_disabled_returns_false(monkeypatch):
    monkeypatch.setattr(tbenv, "TELERIK_RAU_ENABLED", False)
    assert not tbenv.is_telerik_rau_path("/Telerik.Web.UI.WebResource.axd")


# --- the `type` discriminator ------------------------------------------

@pytest.mark.parametrize("qs,expected", [
    ("type=rau", "rau"),
    ("type=RAU", "rau"),
    ("type=rau&x=1", "rau"),
    ("x=1&type=rau", "rau"),
    ("Type=rau", "rau"),
    ("type=%20rau%20", "rau"),
    ("type=cache", "cache"),
    ("type=", ""),
    ("", ""),
    ("d=abc&t=def", ""),
])
def test_telerik_rau_query_type(qs, expected):
    assert tbenv._telerik_rau_query_type(qs) == expected


def test_telerik_rau_query_type_survives_malformed_query():
    # A malformed query string must not raise — the handler still has to
    # answer, and a crash here would 500 on a path a scanner is probing.
    assert tbenv._telerik_rau_query_type("%%%&&&=") == ""


# --- the fingerprint response ------------------------------------------

def test_render_telerik_rau_registered_is_the_real_notice():
    body = tbenv.render_telerik_rau_registered().decode("utf-8")
    assert "RadAsyncUpload handler is registered" in body
    assert "it may not be accessed directly" in body


def test_render_telerik_rau_registered_keeps_the_product_typo():
    """The shipped product misspells "succesfully". A scanner that
    string-matches the notice would notice a corrected one, so the
    misspelling is load-bearing."""
    body = tbenv.render_telerik_rau_registered().decode("utf-8")
    assert "succesfully" in body
    assert "successfully" not in body


def test_render_telerik_rau_registered_is_valid_json():
    payload = json.loads(tbenv.render_telerik_rau_registered())
    assert set(payload) == {"message"}


def test_render_telerik_rau_registered_is_stable():
    """The one response in this trap that must NOT vary per hit."""
    assert (
        tbenv.render_telerik_rau_registered()
        == tbenv.render_telerik_rau_registered()
    )


# --- the upload receipt -------------------------------------------------

def test_render_telerik_rau_receipt_shape():
    payload = json.loads(tbenv.render_telerik_rau_upload_receipt("payload.dll"))
    assert set(payload) == {"fileInfo", "metaData", "tempFileName"}
    assert payload["fileInfo"]["FileName"] == "payload.dll"
    assert payload["fileInfo"]["Index"] == 0
    assert payload["fileInfo"]["ContentType"] == "application/octet-stream"
    assert payload["tempFileName"].endswith(".tmp")


def test_render_telerik_rau_receipt_echoes_the_filename():
    payload = json.loads(tbenv.render_telerik_rau_upload_receipt("sh.aspx"))
    assert payload["fileInfo"]["FileName"] == "sh.aspx"


def test_render_telerik_rau_receipt_metadata_is_per_hit_unique():
    """A fixed `metaData` would ship the same string from every sensor
    and let a replay recognise the trap."""
    seen = {
        json.loads(tbenv.render_telerik_rau_upload_receipt("p.dll"))["metaData"]
        for _ in range(20)
    }
    assert len(seen) == 20


def test_render_telerik_rau_receipt_tempfilename_is_per_hit_unique():
    seen = {
        json.loads(tbenv.render_telerik_rau_upload_receipt("p.dll"))["tempFileName"]
        for _ in range(20)
    }
    assert len(seen) == 20


def test_render_telerik_rau_receipt_metadata_is_base64():
    import base64
    payload = json.loads(tbenv.render_telerik_rau_upload_receipt("p.dll"))
    # Must decode — a client that round-trips the blob shouldn't choke.
    assert base64.b64decode(payload["metaData"])


def test_render_telerik_rau_receipt_date_is_iso_like():
    payload = json.loads(tbenv.render_telerik_rau_upload_receipt("p.dll"))
    date = payload["fileInfo"]["DateJson"]
    assert date.endswith("Z")
    assert len(date) == len("2026-01-01T00:00:00.000Z")


# --- rauPostData extraction --------------------------------------------

def test_extract_postdata_from_urlencoded_form():
    body = b"rauPostData=U2FsdGVkX1%2Babc123%3D%3D&fileName=payload.dll"
    assert tbenv._telerik_rau_extract_postdata(body) == "U2FsdGVkX1+abc123=="


def test_extract_postdata_from_multipart_part():
    body = (
        b"--X\r\n"
        b'Content-Disposition: form-data; name="rauPostData"\r\n\r\n'
        b"AAAAbbbbCCCC==\r\n"
        b"--X--\r\n"
    )
    assert tbenv._telerik_rau_extract_postdata(body) == "AAAAbbbbCCCC=="


def test_extract_postdata_is_case_insensitive_on_the_field_name():
    body = b"raupostdata=abc123&x=1"
    assert tbenv._telerik_rau_extract_postdata(body) == "abc123"


def test_extract_postdata_absent_returns_empty():
    assert tbenv._telerik_rau_extract_postdata(b"fileName=x.dll") == ""


def test_extract_postdata_empty_body_returns_empty():
    assert tbenv._telerik_rau_extract_postdata(b"") == ""


def test_extract_postdata_is_length_capped():
    body = b"rauPostData=" + b"A" * 5000
    out = tbenv._telerik_rau_extract_postdata(body)
    assert len(out) == tbenv.TELERIK_RAU_POSTDATA_PREVIEW_LIMIT


def test_extract_postdata_survives_binary_body():
    # The upload half carries a DLL; a non-UTF-8 body must not raise.
    body = b"rauPostData=abc&file=" + bytes(range(256))
    assert tbenv._telerik_rau_extract_postdata(body) == "abc"


# --- indicator tables ---------------------------------------------------

def test_gadget_indicators_are_lowercase():
    """They are matched against a lowercased body, so an uppercase entry
    would silently never fire."""
    for ind in tbenv._TELERIK_RAU_GADGET_INDICATORS:
        assert ind == ind.lower(), ind


def test_gadget_indicators_cover_the_public_chains():
    joined = b" ".join(tbenv._TELERIK_RAU_GADGET_INDICATORS)
    for needle in (b"objectdataprovider", b"windowsidentity", b"targetfolder"):
        assert needle in joined


def test_payload_extensions_are_lowercase_and_dotted():
    for ext in tbenv._TELERIK_RAU_PAYLOAD_EXTENSIONS:
        assert ext.startswith(".")
        assert ext == ext.lower()


def test_body_decode_limit_has_a_floor():
    assert tbenv.TELERIK_RAU_BODY_DECODE_LIMIT >= 512


# --- descriptor fidelity across the three spellings ---------------------
#
# Found by a live probe, not by the unit tests that preceded it: a single
# `unquote_plus` over every spelling turned each `+` in the descriptor
# into a space. The descriptor is base64, so `+` is a payload byte in the
# multipart and JSON spellings and the captured value stopped being
# decodable — which defeats the only reason to capture it. Only the
# urlencoded spelling may be `+`-decoded.

def test_extract_postdata_preserves_plus_in_multipart():
    body = (
        b"--X\r\n"
        b'Content-Disposition: form-data; name="rauPostData"\r\n\r\n'
        b"U2FsdGVkX1+abc/123==\r\n"
        b"--X--\r\n"
    )
    assert tbenv._telerik_rau_extract_postdata(body) == "U2FsdGVkX1+abc/123=="


def test_extract_postdata_preserves_plus_in_json():
    body = b'{"rauPostData":"A+B/C=="}'
    assert tbenv._telerik_rau_extract_postdata(body) == "A+B/C=="


def test_extract_postdata_decodes_plus_in_urlencoded():
    """Here `+` really is an encoded space, and `%2B` is a literal plus."""
    assert tbenv._telerik_rau_extract_postdata(b"rauPostData=a%2Bb+c&x=1") == "a+b c"


def test_extract_postdata_multipart_wins_over_urlencoded_fallback():
    """A multipart body also contains `name="rauPostData"`; the multipart
    branch must claim it so the value is not plus-mangled."""
    body = (
        b"--X\r\n"
        b'Content-Disposition: form-data; name="rauPostData"\r\n\r\n'
        b"q+q\r\n"
        b"--X--\r\n"
    )
    assert tbenv._telerik_rau_extract_postdata(body) == "q+q"


def test_extract_postdata_roundtrips_a_real_base64_descriptor():
    import base64
    blob = base64.b64encode(bytes(range(96))).decode("ascii")
    body = (
        b"--X\r\n"
        b'Content-Disposition: form-data; name="rauPostData"\r\n\r\n'
        + blob.encode("ascii") + b"\r\n--X--\r\n"
    )
    captured = tbenv._telerik_rau_extract_postdata(body)
    assert captured == blob
    assert base64.b64decode(captured) == bytes(range(96))
