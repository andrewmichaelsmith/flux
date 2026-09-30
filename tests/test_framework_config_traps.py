"""Framework build-config traps: next / nuxt / gatsby / bundler.

These are the repo-root config modules a JS framework's build reads, as
distinct from the runtime bundle the webapp-config-bundle traps serve. The
tests below pin three things: each body uses its own framework's syntax and
puts the canary in that framework's server-only slot; nothing
credential-shaped is fixed; and the config-chunk reference each body emits
is the one the existing chunk matcher accepts, so the chain actually closes.
"""
import re

import pytest

from flux import server as tbenv


CANARY = {
    "aws": {
        "awsAccessKeyId": "AKIAEXAMPLE",
        "awsSecretAccessKey": "SECRETEXAMPLE",
        "awsSessionToken": "TOKENEXAMPLE",
    },
    "_requestHost": "app.example.net",
    "_requestId": "abcd1234-0000-1111-2222-333344445555",
    "_clientIp": "203.0.113.7",
}

RENDERERS = {
    "next-config-js": tbenv.render_next_config_js,
    "nuxt-config-ts": tbenv.render_nuxt_config_ts,
    "gatsby-config-js": tbenv.render_gatsby_config_js,
    "bundler-config-js": tbenv.render_bundler_config_js,
}


def _trap(name):
    for trap in tbenv.CANARY_TRAPS:
        if trap.name == name:
            return trap
    raise AssertionError(f"trap {name} not registered")


# --------------------------------------------------------------- registration

@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_trap_is_registered_and_requests_the_aws_canary(name):
    trap = _trap(name)
    assert trap.canary_types == ("aws",)
    assert trap.content_type.startswith("application/javascript")
    assert trap.paths


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/next.config.js", "next-config-js"),
        ("/next.config.ts", "next-config-js"),
        ("/next.config.mjs", "next-config-js"),
        ("/next.config.cjs", "next-config-js"),
        ("/app/next.config.js", "next-config-js"),
        ("/frontend/next.config.ts", "next-config-js"),
        ("/nuxt.config.ts", "nuxt-config-ts"),
        ("/nuxt.config.js", "nuxt-config-ts"),
        ("/nuxt.config.mjs", "nuxt-config-ts"),
        ("/src/nuxt.config.ts", "nuxt-config-ts"),
        ("/gatsby-config.js", "gatsby-config-js"),
        ("/gatsby-config.ts", "gatsby-config-js"),
        ("/vite.config.js", "bundler-config-js"),
        ("/vite.config.ts", "bundler-config-js"),
        ("/svelte.config.js", "bundler-config-js"),
        ("/astro.config.mjs", "bundler-config-js"),
        ("/vue.config.js", "bundler-config-js"),
        ("/remix.config.js", "bundler-config-js"),
        ("/webpack.config.js", "bundler-config-js"),
        ("/rollup.config.mjs", "bundler-config-js"),
    ],
)
def test_observed_spellings_are_claimed_by_the_right_trap(path, expected):
    owners = [t.name for t in tbenv.CANARY_TRAPS if path in t.paths]
    assert owners == [expected], f"{path} -> {owners}"


@pytest.mark.parametrize(
    "path",
    [
        # Junk parent: the vocabulary gate must still hold.
        "/9f2a1c/next.config.js",
        "/junkdir/nuxt.config.ts",
        # Not a config module.
        "/next.config.json",
        "/nuxt.config",
        "/next.config.js.map",
        # Owned elsewhere, and must stay there.
        "/config.js",
        "/env.js",
        "/app.config.js",
    ],
)
def test_must_not_match(path):
    owners = [t.name for t in tbenv.CANARY_TRAPS if path in t.paths]
    assert expected_owner_is_not_framework_config(owners), f"{path} -> {owners}"


def expected_owner_is_not_framework_config(owners):
    return all(o not in RENDERERS for o in owners)


def test_framework_config_does_not_steal_the_runtime_bundle_paths():
    """`/config.js` and friends belong to webapp-config-bundle-js, which
    serves a browser artifact. Adding a build-config trap must not move
    them."""
    for path in ("/config.js", "/env.js", "/static/js/config.js"):
        owners = [t.name for t in tbenv.CANARY_TRAPS if path in t.paths]
        assert owners == ["webapp-config-bundle-js"], f"{path} -> {owners}"


# ------------------------------------------------------------- framework shape

def test_next_config_uses_next_syntax_and_server_only_slot():
    body = tbenv.render_next_config_js(CANARY).decode("utf-8")
    assert "module.exports = nextConfig" in body
    assert "serverRuntimeConfig" in body
    # The canary lives in the server-only half...
    server_half = body.split("publicRuntimeConfig")[0]
    assert "AKIAEXAMPLE" in server_half
    assert "SECRETEXAMPLE" in server_half
    # ...and not in the half Next ships to the browser.
    public_half = body.split("publicRuntimeConfig", 1)[1]
    assert "AKIAEXAMPLE" not in public_half
    assert "SECRETEXAMPLE" not in public_half


def test_nuxt_config_uses_nuxt_syntax_and_keeps_canary_out_of_public():
    body = tbenv.render_nuxt_config_ts(CANARY).decode("utf-8")
    assert "defineNuxtConfig(" in body
    assert "runtimeConfig" in body
    # `public:` is the browser-visible sub-object; the canary must precede it.
    assert "public:" in body
    public_block = body.split("public:", 1)[1]
    assert "AKIAEXAMPLE" not in public_block
    assert "SECRETEXAMPLE" not in public_block
    assert "AKIAEXAMPLE" in body.split("public:", 1)[0]


def test_gatsby_config_puts_canary_in_plugin_options():
    body = tbenv.render_gatsby_config_js(CANARY).decode("utf-8")
    assert "module.exports" in body
    assert "plugins:" in body
    assert "gatsby-source-s3" in body
    # The credential is a plugin option, which is where Gatsby actually
    # takes one.
    assert "accessKeyId: 'AKIAEXAMPLE'" in body
    assert "secretAccessKey: 'SECRETEXAMPLE'" in body


def test_bundler_config_uses_define_block():
    body = tbenv.render_bundler_config_js(CANARY).decode("utf-8")
    assert "defineConfig(" in body
    assert "define:" in body
    assert "JSON.stringify('AKIAEXAMPLE')" in body
    assert "JSON.stringify('SECRETEXAMPLE')" in body


@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_body_names_the_request_host_not_a_placeholder(name):
    body = RENDERERS[name](CANARY).decode("utf-8")
    assert "app.example.net" in body


# ------------------------------------------------------- nothing fixed, ever

@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_no_credential_is_fixed_across_two_renders(name):
    """The session secret is a per-hit synthetic, so two renders of the
    same path must not share it. A fixed literal would give zero
    detection on replay and fingerprint every host running this."""
    a = RENDERERS[name](CANARY).decode("utf-8")
    b = RENDERERS[name](CANARY).decode("utf-8")
    secrets_a = set(re.findall(r"[0-9a-f]{64}", a))
    secrets_b = set(re.findall(r"[0-9a-f]{64}", b))
    assert secrets_a, "expected a per-hit session secret in the body"
    assert secrets_a.isdisjoint(secrets_b), (
        f"{name} emitted the same secret twice: {secrets_a & secrets_b}"
    )


# ------------------------------------------------------------- the chain closes

@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_referenced_config_chunk_is_accepted_by_the_chunk_matcher(name):
    """The point of the reference: a request for it can only come from a
    client that parsed a body we served. That only holds if the path we
    emit is the one the matcher recognises AND the hash is the one it
    expects for that client."""
    body = RENDERERS[name](CANARY).decode("utf-8")
    refs = re.findall(r"/assets/env-config-[0-9a-f]+\.js", body)
    assert refs, f"{name} emitted no config-chunk reference"
    ref = refs[0]
    match = tbenv._SPA_CHUNK_RE.match(ref)
    assert match is not None, f"{ref} is not matched by _SPA_CHUNK_RE"
    assert match.group(1) == tbenv._spa_chunk_hash("203.0.113.7")


@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_chunk_reference_differs_per_client(name):
    """Keyed on the client address, so one client cannot hand another a
    reference that would read as 'parsed our body'."""
    a = RENDERERS[name]({**CANARY, "_clientIp": "203.0.113.7"}).decode("utf-8")
    b = RENDERERS[name]({**CANARY, "_clientIp": "198.51.100.9"}).decode("utf-8")
    ref_a = re.findall(r"/assets/env-config-[0-9a-f]+\.js", a)[0]
    ref_b = re.findall(r"/assets/env-config-[0-9a-f]+\.js", b)[0]
    assert ref_a != ref_b


@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_renderer_survives_missing_request_context(name):
    """`_clientIp` / `_requestHost` are enrichment keys; a renderer must
    not raise if a caller omits them."""
    body = RENDERERS[name]({"aws": CANARY["aws"]}).decode("utf-8")
    assert body


# ---------------------------------------------------- end-to-end over HTTP
# The unit tests above call renderers directly. These drive the real
# dispatch path, which is the only thing that proves the route reaches the
# handler and the body is what leaves the server.

from .test_server import _fake_canary, _log_entries, flux_client  # noqa: E402,F401


@pytest.fixture
def canary(monkeypatch):
    monkeypatch.setattr(tbenv, "API_KEY", "fake-key")
    monkeypatch.setattr(tbenv, "CANARY_TRAPS_ENABLED", True)
    monkeypatch.setattr(tbenv, "_get_or_issue_canary", _fake_canary)


SERVED = [
    ("/next.config.js", "next-config-js", "module.exports = nextConfig"),
    ("/next.config.ts", "next-config-js", "serverRuntimeConfig"),
    ("/app/next.config.js", "next-config-js", "serverRuntimeConfig"),
    ("/nuxt.config.ts", "nuxt-config-ts", "defineNuxtConfig("),
    ("/nuxt.config.js", "nuxt-config-ts", "runtimeConfig"),
    ("/gatsby-config.js", "gatsby-config-js", "gatsby-source-s3"),
    ("/vite.config.ts", "bundler-config-js", "defineConfig("),
    ("/svelte.config.js", "bundler-config-js", "define:"),
    ("/webpack.config.js", "bundler-config-js", "defineConfig("),
]


@pytest.mark.parametrize("path,tag,needle", SERVED)
async def test_served_over_http_with_canary(flux_client, canary, path, tag, needle):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.10"})
    assert resp.status == 200
    body = (await resp.read()).decode("utf-8")
    assert needle in body
    # The canary actually reached the body.
    assert "AKIAFAKEEXAMPLE01" in body
    assert resp.headers["Content-Type"].startswith("application/javascript")
    assert any(e.get("result") == tag for e in _log_entries(flux_client.log_path)), (
        f"expected a {tag} log line for {path}"
    )


@pytest.mark.parametrize("path", ["/9f2a1c/next.config.js", "/next.config.json"])
async def test_non_vocabulary_paths_stay_404(flux_client, canary, path):
    resp = await flux_client.get(path, headers={"X-Forwarded-For": "203.0.113.10"})
    assert resp.status == 404


async def test_the_chain_closes_over_http(flux_client, canary):
    """Serve a framework config, take the chunk path out of the body it
    actually returned, fetch that, and assert it is tagged as referenced
    rather than as a foreign hash. This is the whole point of the trap."""
    resp = await flux_client.get(
        "/nuxt.config.ts", headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status == 200
    body = (await resp.read()).decode("utf-8")
    refs = re.findall(r"/assets/env-config-[0-9a-f]+\.js", body)
    assert refs, "config body carried no chunk reference"

    chunk = await flux_client.get(refs[0], headers={"X-Forwarded-For": "203.0.113.10"})
    assert chunk.status == 200
    tags = [e.get("result") for e in _log_entries(flux_client.log_path)]
    assert "spa-config-chunk-referenced" in tags, tags[-5:]
    assert "spa-config-chunk-foreign" not in tags


async def test_a_hash_from_another_client_reads_as_foreign(flux_client, canary):
    """The discriminator has to actually discriminate: a well-formed hash
    this deployment never issued to *this* client must not read as
    'parsed our body'."""
    resp = await flux_client.get(
        "/next.config.js", headers={"X-Forwarded-For": "203.0.113.10"},
    )
    body = (await resp.read()).decode("utf-8")
    ref = re.findall(r"/assets/env-config-[0-9a-f]+\.js", body)[0]
    # Same path, different client.
    chunk = await flux_client.get(ref, headers={"X-Forwarded-For": "198.51.100.77"})
    assert chunk.status == 200
    tags = [e.get("result") for e in _log_entries(flux_client.log_path)]
    assert "spa-config-chunk-foreign" in tags, tags[-5:]
