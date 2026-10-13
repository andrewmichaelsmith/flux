"""Editor / backup leftovers across the app-config family.

The family is documented as carrying the whole `.bak` / `.old` / `.save`
/ `.orig` / `.swp` / `~` sibling set. The variants were hand-written per
path, so the set had drifted: `/config.php` carried six siblings,
`/configuration.php` three, `/settings.php` two, and
`/includes/config.php` none — one dictionary pass splitting across two
outcomes for no reason the caller could see.

These tests pin the property rather than a path list, so the next path
added to the family gets its siblings without anyone remembering to.
"""
import pytest

import flux.server as tbenv


FAMILY = tbenv._APP_CONFIG_SUFFIX_FAMILY
SUFFIXES = tbenv._APP_CONFIG_EDITOR_SUFFIXES


def _family_bases() -> list[str]:
    """Every explicitly-listed path in the family that is not itself a
    leftover spelling."""
    out = []
    for trap in tbenv.CANARY_TRAPS:
        if trap.name not in FAMILY:
            continue
        for path in trap.paths:
            low = path.lower()
            if not low.endswith(SUFFIXES):
                out.append(low)
    return out


def test_the_family_is_not_empty():
    """Guards every other test here against passing vacuously."""
    bases = _family_bases()
    assert len(bases) > 100, len(bases)
    # 57 since the provider-CLI and IaC credential traps joined. Before
    # that the niche-cloud-provider table had only two members in the
    # family, so `/.ovh.conf` answered while `/.ovh.conf.bak` 404ed — the
    # same canonical-answers/leftover-404s split that first motivated this
    # block, recurring in a table added later. 34 was the count when the
    # credential-bearing *app* config traps joined; each had been
    # hand-listing between zero and three of the leftover suffixes, so
    # `/web.config.bak` answered while `/appsettings.json.bak` 404ed.
    # 69 since the CI-pipeline, AWS-config, container/registry, key,
    # password-hash and front-end-bundle traps joined. 57 was the count
    # when the provider-CLI and IaC credential traps joined; 34 when the
    # credential-bearing *app* config traps did. Each wave was a table
    # written after this block that hand-listed some subset of the
    # leftover suffixes, which is the drift the property tests below
    # exist to stop.
    # 80 since the OCI API key file and the inference/GPU-cloud credential
    # traps joined. The OCI one is the clearest instance yet of the split
    # this block exists to end: `oci-config` was admitted here and the key
    # file its own rendered body names in `key_file=` was not, so the
    # config answered its backup copy while the key — the read that
    # actually carries the credential — answered only its canonical name.
    # 85 since the GPU/HPC cluster-scheduler lane joined (the cluster
    # launcher, batch scheduler, accounting daemon, machine-API client
    # config and bootstrap user-data). Admitted as one wave rather than
    # drip-fed because the observed sweeps walk the lane as a single
    # dictionary pass and ask for a backup sibling of a cluster config in
    # the same breath as the canonical name — the exact split the rest of
    # this comment is a history of.
    assert len(FAMILY) == 85


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_every_base_in_the_family_answers_every_documented_suffix(suffix):
    missing = [
        base for base in _family_bases()
        if tbenv._TRAP_BY_PATH.get(base + suffix) is None
    ]
    assert not missing, f"{len(missing)} bases miss `{suffix}`: {missing[:8]}"


def test_a_sibling_resolves_to_the_same_trap_as_its_base():
    """The leftover must render the same document as the original.

    A `.bak` that routed to a different renderer than its base would
    hand the same caller two different configs for the same file, which
    is a tell rather than a trap.
    """
    for base in _family_bases():
        owner = tbenv._TRAP_BY_PATH[base]
        for suffix in SUFFIXES:
            sibling = tbenv._TRAP_BY_PATH[base + suffix]
            # Siblings already owned by another trap are exempt — the
            # fill never overrides, and that is asserted separately.
            if sibling.name in FAMILY:
                assert sibling is owner, (
                    f"{base + suffix} -> {sibling.name}, base -> {owner.name}"
                )


@pytest.mark.parametrize("path,expected", [
    # Spellings observed in the wild whose base already answered the
    # same suffix — the split this change removes.
    ("/settings.php.swp", "app-config-php"),
    ("/settings.php.old", "app-config-php"),
    ("/settings.php.save", "app-config-php"),
    ("/settings.php.orig", "app-config-php"),
    ("/settings.py.old", "app-config-python"),
    ("/settings.py.swp", "app-config-python"),
    ("/local_settings.py.bak", "app-config-python"),
    ("/local_settings.py.swp", "app-config-python"),
    ("/configuration.php.swp", "app-config-php"),
    ("/include/config.php.bak", "app-config-php"),
    ("/config/config.php.bak", "app-config-php"),
    ("/config.yml.swp", "app-config-yaml"),
    ("/config.yaml.swp", "app-config-yaml"),
    ("/secrets.yml.swp", "app-config-yaml"),
])
def test_observed_leftover_spellings_route_to_their_family(path, expected):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == expected


@pytest.mark.parametrize("path,owner", [
    # Suffix spellings that belong to a framework-specific trap with its
    # own renderer. The fill uses setdefault precisely so these keep
    # their owner — it can only turn a 404 into an answer, never move an
    # existing route.
    ("/wp-config.php.bak", "wp-config"),
    ("/wp-config.php.old", "wp-config"),
    ("/wp-config.php.save", "wp-config"),
    ("/.env.bak", "env-production"),
    ("/.env.old", "env-production"),
    ("/config/database.yml.bak", "rails-database-yml"),
    ("/config/secrets.yml.bak", "rails-secrets-yml"),
    ("/.aws/credentials.bak", "aws-credentials-file"),
    ("/.aws/credentials.old", "aws-credentials-file"),
    ("/sites/default/settings.php.bak", "drupal-settings-php"),
    ("/app/etc/env.php.bak", "magento-env"),
])
def test_the_fill_never_steals_an_existing_route(path, owner):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} lost its route entirely"
    assert trap.name == owner, f"{path} moved to {trap.name}"


def test_leftovers_do_not_stack():
    """No scanner asks for `/config.php.bak.old`, and generating them
    would multiply the table for nothing."""
    for path in tbenv._TRAP_BY_PATH:
        stacked = sum(1 for s in SUFFIXES if path.endswith(s))
        assert stacked <= 1, path
    assert "/config.php.bak.old" not in tbenv._TRAP_BY_PATH
    assert "/config.php.bak~" not in tbenv._TRAP_BY_PATH


def test_the_fill_only_touches_the_documented_family():
    """A base outside the family must not have gained siblings from this
    change — those traps curate their own suffix lists."""
    # Jenkinsfile carries exactly the one leftover it always listed.
    assert tbenv._TRAP_BY_PATH.get("/jenkinsfile.bak") is not None
    assert tbenv._TRAP_BY_PATH.get("/jenkinsfile.swp") is None
    assert tbenv._TRAP_BY_PATH.get("/jenkinsfile.orig") is None


def test_the_fill_is_idempotent_and_order_independent():
    """Re-running the fill against the built table must change nothing —
    it is a setdefault pass, so a reload cannot flip an owner."""
    before = {p: t.name for p, t in tbenv._TRAP_BY_PATH.items()}
    for trap in tbenv.CANARY_TRAPS:
        if trap.name not in FAMILY:
            continue
        for path in trap.paths:
            low = path.lower()
            if low.endswith(SUFFIXES):
                continue
            for suffix in SUFFIXES:
                tbenv._TRAP_BY_PATH.setdefault(low + suffix, trap)
    after = {p: t.name for p, t in tbenv._TRAP_BY_PATH.items()}
    assert before == after


@pytest.mark.parametrize("path,expected", [
    # The long spellings of the three leftovers this family was missing.
    # `.tmp` answered and `.temp` 404ed on the same base, from the same
    # dictionary — the split is what identified the gap.
    ("/web.config.temp", "iis-web-config"),
    ("/web.config.backup", "iis-web-config"),
    ("/web.config.copy", "iis-web-config"),
    ("/config.php.backup", "app-config-php"),
    ("/settings.py.copy", "app-config-python"),
    # Bases whose own tables listed no leftover spelling at all, so every
    # suffix 404ed while a sibling framework's answered.
    ("/appsettings.json.bak", "appsettings-json"),
    ("/appsettings.json.backup", "appsettings-json"),
    ("/auth.json.backup", "composer-auth-json"),
    ("/.npmrc.backup", "npmrc"),
    ("/.pypirc.copy", "pypirc"),
    ("/application.properties.backup", "application-properties"),
    ("/application.yml.copy", "application-yml"),
    ("/database.yml.backup", "rails-database-yml"),
    # Credential files: the leftover copy is the whole point here, since
    # an operator renames one aside before rotating the key inside it.
    ("/.aws/credentials.copy", "aws-credentials-file"),
    ("/firebase.json.backup", "firebase-json"),
    ("/gcp-credentials.json.copy", "gcp-credentials-json"),
])
def test_long_leftover_spellings_route_to_their_family(path, expected):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} is not routed"
    assert trap.name == expected


def test_no_sibling_renders_a_different_document_than_its_base():
    """A leftover whose base is owned by another trap in this family is a
    split: the same file answered two ways depending on how it was asked
    for. `/config.json` (config-json) once had its `.bak` hand-listed on
    `app-config-json`, which is exactly that.
    """
    split = []
    for trap in tbenv.CANARY_TRAPS:
        if trap.name not in FAMILY:
            continue
        for path in trap.paths:
            low = path.lower()
            for suffix in SUFFIXES:
                if not low.endswith(suffix):
                    continue
                owner = tbenv._TRAP_BY_PATH.get(low[: -len(suffix)])
                if owner is not None and owner.name != trap.name:
                    split.append((low, trap.name, owner.name))
                break
    assert not split, split


def test_the_long_and_short_leftover_spellings_agree():
    """`.tmp`/`.temp` and `.bak`/`.backup` are the same leftover. Any base
    that answers one must answer the other, or a dictionary walking both
    gets two outcomes for one file."""
    for short, long in ((".tmp", ".temp"), (".bak", ".backup")):
        for base in _family_bases():
            a = tbenv._TRAP_BY_PATH.get(base + short)
            b = tbenv._TRAP_BY_PATH.get(base + long)
            assert (a is None) == (b is None), f"{base}: {short}/{long} disagree"
            if a is not None:
                assert a.name == b.name, f"{base}: {a.name} vs {b.name}"


# --- The leftover spellings that were observed 404ing ------------------
# Each of these is a credential-bearing file whose original answered with
# a canary while the copy an operator leaves beside it did not, so one
# dictionary pass over a name and its leftover split across two
# outcomes. Pinned as paths (not just as family membership) because the
# membership is the fix and these are the spellings that proved it was
# missing.
@pytest.mark.parametrize("path,owner", [
    # Key material: the file *is* the credential.
    ("/.ssh/id_rsa~", "ssh-private-key"),
    ("/.ssh/id_dsa~", "ssh-private-key"),
    ("/server.pem.bak", "ssh-private-key"),
    # Provider CLI / SDK credential files.
    ("/.aws/config.bak", "aws-config-file"),
    ("/.ovh.conf.bak", "ovh-conf"),
    # A dump is the credential-bearing file a deploy leaves behind.
    ("/dump.sql.old", "sql-dump"),
    ("/backup.sql.old", "sql-dump"),
    # CI pipeline definitions, whose bodies carry deploy credentials.
    ("/.gitlab-ci.yml.bak", "gitlab-ci"),
    ("/.travis.yml.bak", "generic-ci-config"),
    ("/.drone.yml.bak", "generic-ci-config"),
    ("/bitbucket-pipelines.yml.bak", "bitbucket-pipelines"),
    ("/.github/workflows/main.yml.bak", "github-actions-workflow"),
])
def test_observed_leftover_spellings_now_answer(path, owner):
    trap = tbenv._TRAP_BY_PATH.get(path)
    assert trap is not None, f"{path} still 404s"
    assert trap.name == owner, f"{path} resolved to {trap.name}"
