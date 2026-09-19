"""Tests for the YAML catalog loader + seeder."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from site_b2b_intel.db import repository as repo
from site_b2b_intel.fingerprints.catalog import load_catalog, seed_catalog


def test_default_catalog_loads() -> None:
    catalog = load_catalog()
    assert len(catalog.vendors) >= 10
    assert len(catalog.rules) >= 20
    slugs = catalog.vendor_slugs()
    assert {"google-workspace", "microsoft-365", "cloudflare", "stripe"} <= slugs


def test_rules_indexed_by_record_type() -> None:
    idx = load_catalog().rules_by_record_type()
    assert "TXT" in idx
    assert "MX" in idx
    assert "NS" in idx
    assert "SPF" in idx
    assert "DKIM_SELECTOR" in idx


def test_orphan_rule_raises(tmp_path: Path) -> None:
    (tmp_path / "vendors.yaml").write_text(
        "vendors:\n  - slug: known\n    name: Known\n    category: test\n"
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "bad.yaml").write_text(
        'rules:\n  - vendor: unknown\n    record_type: TXT\n'
        '    match_kind: prefix\n    pattern: "foo="\n    confidence: high\n'
    )
    with pytest.raises(ValueError, match="unknown vendor"):
        load_catalog(tmp_path)


class TestSeed:
    def test_seed_inserts_vendors_and_rules(
        self, db: sqlite3.Connection
    ) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)

        vendors = repo.list_vendors(db)
        assert {v["slug"] for v in vendors} == catalog.vendor_slugs()

        rules = repo.list_rules(db, enabled_only=True)
        assert len(rules) == len(catalog.rules)

    def test_seed_is_idempotent(self, db: sqlite3.Connection) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)
        first_vendor_count = len(repo.list_vendors(db))
        first_rule_count = len(repo.list_rules(db, enabled_only=True))

        seed_catalog(db, catalog)
        assert len(repo.list_vendors(db)) == first_vendor_count
        assert len(repo.list_rules(db, enabled_only=True)) == first_rule_count

    def test_reseed_soft_deletes_removed_rule(
        self, db: sqlite3.Connection
    ) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)
        before = len(repo.list_rules(db, enabled_only=True))

        # Re-seed with one rule removed
        from site_b2b_intel.types import Rule

        trimmed_rules = catalog.rules[:-1]
        trimmed = type(catalog)(vendors=catalog.vendors, rules=trimmed_rules)
        seed_catalog(db, trimmed)

        after_active = len(repo.list_rules(db, enabled_only=True))
        after_all = len(repo.list_rules(db, enabled_only=False))
        assert after_active == before - 1
        assert after_all == before  # nothing hard-deleted


def test_vendor_profile_appended_on_change(
    db: sqlite3.Connection, tmp_path: Path
) -> None:
    (tmp_path / "vendors.yaml").write_text(
        "vendors:\n"
        "  - slug: acme\n"
        "    name: Acme\n"
        "    category: test\n"
        "    profile:\n"
        "      website: https://acme.example\n"
        "      source: manual\n"
    )
    (tmp_path / "rules").mkdir()
    catalog = load_catalog(tmp_path)
    seed_catalog(db, catalog)

    vid = repo.get_vendor_by_slug(db, "acme")["id"]
    first = repo.latest_profile(db, vid)
    assert first["website"] == "https://acme.example"

    # Re-seed with no change → no new profile row
    seed_catalog(db, catalog)
    rows = db.execute(
        "SELECT COUNT(*) AS n FROM vendor_profile WHERE vendor_id=?", (vid,)
    ).fetchone()
    assert rows["n"] == 1

    # Update profile → new row appended
    (tmp_path / "vendors.yaml").write_text(
        "vendors:\n"
        "  - slug: acme\n"
        "    name: Acme\n"
        "    category: test\n"
        "    profile:\n"
        "      website: https://acme.example\n"
        "      phone: '+1-555-0100'\n"
        "      source: manual\n"
    )
    catalog2 = load_catalog(tmp_path)
    seed_catalog(db, catalog2)
    rows = db.execute(
        "SELECT COUNT(*) AS n FROM vendor_profile WHERE vendor_id=?", (vid,)
    ).fetchone()
    assert rows["n"] == 2
