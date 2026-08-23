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
    assert len(FAMILY) == 9


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
