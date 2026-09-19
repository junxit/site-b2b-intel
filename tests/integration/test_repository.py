"""Smoke tests for the DB repository — verifies schema applies and round-trips."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from site_b2b_intel.db import repository as repo


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestVendorAndRule:
    def test_upsert_vendor_idempotent(self, db: sqlite3.Connection) -> None:
        a = repo.upsert_vendor(
            db, slug="cloudflare", name="Cloudflare", category="cdn"
        )
        b = repo.upsert_vendor(
            db, slug="cloudflare", name="Cloudflare", category="cdn"
        )
        assert a == b

    def test_upsert_vendor_updates_name(self, db: sqlite3.Connection) -> None:
        repo.upsert_vendor(db, slug="x", name="X Co", category="cdn")
        repo.upsert_vendor(db, slug="x", name="X Inc", category="cdn")
        row = repo.get_vendor_by_slug(db, "x")
        assert row is not None
        assert row["name"] == "X Inc"

    def test_upsert_rule_round_trips(self, db: sqlite3.Connection) -> None:
        vid = repo.upsert_vendor(
            db, slug="cf", name="Cloudflare", category="cdn"
        )
        rid = repo.upsert_rule(
            db,
            vendor_id=vid,
            record_type="NS",
            match_kind="suffix",
            pattern=".cloudflare.com",
            confidence="high",
        )
        assert rid > 0
        rules = repo.list_rules(db)
        assert len(rules) == 1
        assert rules[0]["pattern"] == ".cloudflare.com"

    def test_soft_delete_rules_not_in(self, db: sqlite3.Connection) -> None:
        vid = repo.upsert_vendor(db, slug="cf", name="Cloudflare", category="cdn")
        keep = repo.upsert_rule(
            db,
            vendor_id=vid,
            record_type="NS",
            match_kind="suffix",
            pattern=".cloudflare.com",
            confidence="high",
        )
        gone = repo.upsert_rule(
            db,
            vendor_id=vid,
            record_type="NS",
            match_kind="suffix",
            pattern=".old.example",
            confidence="medium",
        )
        affected = repo.soft_delete_rules_not_in(db, [keep])
        assert affected == 1
        active = repo.list_rules(db, enabled_only=True)
        all_ = repo.list_rules(db, enabled_only=False)
        assert {r["id"] for r in active} == {keep}
        assert {r["id"] for r in all_} == {keep, gone}


class TestScanAndDetection:
    def test_scan_records_detection_roundtrip(
        self, db: sqlite3.Connection
    ) -> None:
        vid = repo.upsert_vendor(
            db, slug="google-workspace", name="Google Workspace", category="productivity"
        )
        rid = repo.upsert_rule(
            db,
            vendor_id=vid,
            record_type="MX",
            match_kind="suffix",
            pattern="aspmx.l.google.com",
            confidence="high",
        )
        when = _now()
        sid = repo.insert_scan(
            db,
            domain="stripe.com",
            domain_normalized="stripe.com",
            scanned_at=when,
        )
        rec_id = repo.insert_dns_record(
            db,
            scan_id=sid,
            record_type="MX",
            name="stripe.com",
            value="aspmx.l.google.com",
            ttl=300,
        )
        did = repo.insert_detection(
            db,
            scan_id=sid,
            vendor_id=vid,
            rule_id=rid,
            confidence="high",
        )
        repo.insert_detection_evidence(
            db, detection_id=did, dns_record_id=rec_id
        )
        repo.upsert_observation(
            db,
            domain_normalized="stripe.com",
            vendor_id=vid,
            seen_at=when,
        )

        # Re-read via the report path
        results = repo.detections_for_scan(db, sid)
        assert len(results) == 1
        r = results[0]
        assert r["vendor_slug"] == "google-workspace"
        assert r["evidence_values"] == "aspmx.l.google.com"

        obs = repo.observations_for_domain(db, "stripe.com")
        assert len(obs) == 1
        assert obs[0]["first_seen"] == when

    def test_observation_first_seen_is_monotonic(
        self, db: sqlite3.Connection
    ) -> None:
        vid = repo.upsert_vendor(
            db, slug="cf", name="Cloudflare", category="cdn"
        )
        early = "2024-01-01T00:00:00Z"
        late = "2025-06-01T00:00:00Z"

        # Insert late first, then early — first_seen should move to early.
        repo.upsert_observation(
            db,
            domain_normalized="example.com",
            vendor_id=vid,
            seen_at=late,
        )
        repo.upsert_observation(
            db,
            domain_normalized="example.com",
            vendor_id=vid,
            seen_at=early,
        )
        rows = repo.observations_for_domain(db, "example.com")
        assert rows[0]["first_seen"] == early
        assert rows[0]["last_seen"] == late
        assert rows[0]["detection_count"] == 2

    def test_domains_for_vendor_is_inverse_of_observations(
        self, db: sqlite3.Connection
    ) -> None:
        vid = repo.upsert_vendor(
            db, slug="cf", name="Cloudflare", category="cdn"
        )
        for dom, when in (
            ("a.com", "2026-01-01T00:00:00Z"),
            ("b.com", "2026-03-01T00:00:00Z"),
            ("c.com", "2026-02-01T00:00:00Z"),
        ):
            repo.upsert_observation(
                db, domain_normalized=dom, vendor_id=vid, seen_at=when
            )

        rows = repo.domains_for_vendor(db, "cf")
        # Most recently seen first.
        assert [r["domain_normalized"] for r in rows] == [
            "b.com",
            "c.com",
            "a.com",
        ]

    def test_domains_for_vendor_limit(self, db: sqlite3.Connection) -> None:
        vid = repo.upsert_vendor(db, slug="cf", name="CF", category="cdn")
        for dom in ("a.com", "b.com", "c.com"):
            repo.upsert_observation(
                db, domain_normalized=dom, vendor_id=vid, seen_at=_now()
            )
        assert len(repo.domains_for_vendor(db, "cf", limit=2)) == 2

    def test_domains_for_vendor_since(self, db: sqlite3.Connection) -> None:
        vid = repo.upsert_vendor(db, slug="cf", name="CF", category="cdn")
        repo.upsert_observation(
            db, domain_normalized="old.com", vendor_id=vid,
            seen_at="2024-01-01T00:00:00Z",
        )
        repo.upsert_observation(
            db, domain_normalized="new.com", vendor_id=vid,
            seen_at="2026-01-01T00:00:00Z",
        )
        rows = repo.domains_for_vendor(
            db, "cf", since="2025-01-01T00:00:00Z"
        )
        assert [r["domain_normalized"] for r in rows] == ["new.com"]

    def test_domains_for_unknown_vendor_is_empty(
        self, db: sqlite3.Connection
    ) -> None:
        assert repo.domains_for_vendor(db, "nope") == []

    def test_detection_idempotent(self, db: sqlite3.Connection) -> None:
        vid = repo.upsert_vendor(
            db, slug="cf", name="Cloudflare", category="cdn"
        )
        rid = repo.upsert_rule(
            db,
            vendor_id=vid,
            record_type="NS",
            match_kind="suffix",
            pattern=".cloudflare.com",
            confidence="high",
        )
        sid = repo.insert_scan(
            db,
            domain="x.com",
            domain_normalized="x.com",
            scanned_at=_now(),
        )
        a = repo.insert_detection(
            db, scan_id=sid, vendor_id=vid, rule_id=rid, confidence="high"
        )
        b = repo.insert_detection(
            db, scan_id=sid, vendor_id=vid, rule_id=rid, confidence="high"
        )
        assert a == b
