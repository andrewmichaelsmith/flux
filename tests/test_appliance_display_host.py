"""No rendered page may print a host that a reverse proxy substituted.

The vendor portals interpolate the requested host into their titles and
page furniture, guarded by `host or "<vendor default>"`. That guard fires
only on an *empty* host, and what actually arrives behind a proxy which
rewrites `Host` is `127.0.0.1` — non-empty, so the guard never ran and
every portal in the fleet served the same visibly-wrong name.

The existing suites could not see it: they call each renderer with a real
hostname, which is the one input where the bug does not reproduce. So the
test here drives every renderer with the values a proxy actually
substitutes and asserts on the output.
"""

import inspect

import pytest

from flux import server as tbenv


# What a reverse proxy puts in `Host` when it rewrites it, plus the
# neighbouring shapes that are equally unusable as an appliance name.
PROXY_SUBSTITUTED_HOSTS = (
    "127.0.0.1",
    "127.0.0.1:8080",
    "localhost",
    "[::1]",
    "0.0.0.0",
    "10.0.0.5",
    "",
)

# Anything that looks like an address literal or a loopback name must not
# survive into a rendered page.
FORBIDDEN_FRAGMENTS = ("127.0.0.1", "localhost", "[::1]", "0.0.0.0", "10.0.0.5")


def _host_renderers():
    """Every `render_*` whose first parameter is named `host`."""
    for name, fn in sorted(vars(tbenv).items()):
        if not name.startswith("render_") or not callable(fn):
            continue
        try:
            params = list(inspect.signature(fn).parameters.values())
        except (TypeError, ValueError):
            continue
        if not params or params[0].name != "host":
            continue
        # Fill any further parameters that have no default with a
        # shape-only string; no renderer branches on them.
        extra = ["7.4.3" for p in params[1:] if p.default is inspect.Parameter.empty]
        yield name, fn, extra


def test_there_are_host_taking_renderers_to_check():
    """Guard against this file silently checking nothing if the
    renderers are renamed."""
    assert len(list(_host_renderers())) >= 10


@pytest.mark.parametrize("bad_host", PROXY_SUBSTITUTED_HOSTS)
def test_no_renderer_prints_a_proxy_substituted_host(bad_host, monkeypatch):
    # With no site host configured, the vendor placeholder is the answer.
    monkeypatch.setattr(tbenv, "SITE_HOST", "")
    for name, fn, extra in _host_renderers():
        out = fn(bad_host, *extra)
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
        for fragment in FORBIDDEN_FRAGMENTS:
            assert fragment not in text, f"{name} printed {fragment!r} for host={bad_host!r}"


def test_configured_site_host_is_preferred_over_the_placeholder(monkeypatch):
    """A deployment that knows its own name should print it rather than a
    generic vendor string — that is what makes the page specific."""
    monkeypatch.setattr(tbenv, "SITE_HOST", "vpn.example.com")
    assert tbenv._appliance_display_host("127.0.0.1", "bigip") == "vpn.example.com"
    assert tbenv._appliance_display_host("", "bigip") == "vpn.example.com"


def test_a_real_request_host_still_wins(monkeypatch):
    monkeypatch.setattr(tbenv, "SITE_HOST", "vpn.example.com")
    assert tbenv._appliance_display_host("gw.customer.net", "bigip") == "gw.customer.net"
    # Port is stripped, case is normalised.
    assert tbenv._appliance_display_host("GW.Customer.net:443", "bigip") == "gw.customer.net"


def test_placeholder_is_the_last_resort(monkeypatch):
    monkeypatch.setattr(tbenv, "SITE_HOST", "")
    assert tbenv._appliance_display_host("127.0.0.1", "sophos-xg") == "sophos-xg"
    assert tbenv._appliance_display_host("host.local", "sophos-xg") == "sophos-xg"
