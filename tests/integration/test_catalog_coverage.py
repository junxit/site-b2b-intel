"""Catalog coverage and hygiene guards.

These exist because of failures that actually happened in this catalog:

* A vendor sat in vendors.yaml with no rule pointing at it, so it could
  never be detected and nothing reported the gap.
* Three rule files shipped as ``rules: []`` while the README advertised the
  detection families they were supposed to implement.
* A suffix rule was written without a leading dot, which silently widens
  it to match attacker-registrable lookalike domains.

Each is cheap to assert and expensive to notice by hand.
"""

from __future__ import annotations

import pytest

from site_b2b_intel.fingerprints.catalog import load_catalog
from site_b2b_intel.types import KNOWN_MATCH_KINDS, KNOWN_RECORD_TYPES


def test_every_vendor_is_detectable() -> None:
    """A vendor with no rule is dead weight — it can never be detected."""
    catalog = load_catalog()
    with_rules = {r.vendor_slug for r in catalog.rules}
    undetectable = sorted(catalog.vendor_slugs() - with_rules)
    assert not undetectable, (
        f"vendors in vendors.yaml with no rule pointing at them: "
        f"{undetectable}"
    )


def test_every_rule_points_at_a_declared_vendor() -> None:
    catalog = load_catalog()
    orphans = sorted(
        {r.vendor_slug for r in catalog.rules} - catalog.vendor_slugs()
    )
    assert not orphans, f"rules referencing unknown vendors: {orphans}"


def test_all_record_types_and_match_kinds_are_known() -> None:
    for rule in load_catalog().rules:
        assert rule.record_type in KNOWN_RECORD_TYPES
        assert rule.match_kind in KNOWN_MATCH_KINDS


def test_suffix_rules_start_with_a_dot() -> None:
    """``suffix: zendesk.com`` also matches ``fakezendesk.com``.

    Anyone can register a lookalike, so a suffix rule must be anchored at a
    label boundary. Where the apex itself is a legitimate value, pair the
    dotted suffix with a separate ``exact`` rule instead of dropping the dot.
    """
    offenders = [
        f"{r.vendor_slug}:{r.record_type}:{r.pattern}"
        for r in load_catalog().rules
        if r.match_kind == "suffix" and not r.pattern.startswith(".")
    ]
    assert not offenders, (
        f"suffix rules missing a leading dot: {offenders}"
    )


@pytest.mark.parametrize(
    "record_type",
    ["TXT", "SPF", "MX", "NS", "DKIM_SELECTOR", "CAA_ISSUER", "DMARC_RUA", "CNAME"],
)
def test_advertised_detection_families_have_rules(record_type: str) -> None:
    """Every record type the README claims must actually ship rules.

    Guards the specific regression where CAA, CNAME and DMARC_RUA were
    documented as supported while their rule files were empty.
    """
    idx = load_catalog().rules_by_record_type()
    assert idx.get(record_type), (
        f"record type {record_type} is advertised but has zero rules"
    )


def test_no_duplicate_rule_keys() -> None:
    """Duplicates are silently deduped by the DB's UNIQUE constraint."""
    seen: set[tuple[str, str, str, str]] = set()
    dupes: list[tuple[str, str, str, str]] = []
    for r in load_catalog().rules:
        key = (r.vendor_slug, r.record_type, r.match_kind, r.pattern)
        if key in seen:
            dupes.append(key)
        seen.add(key)
    assert not dupes, f"duplicate rule keys: {dupes}"
