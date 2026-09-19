"""Tests for the JSON/CSV serialization layer.

Builds scan rows directly through the repository rather than going via a
resolver — this is about payload shape, not DNS.
"""

from __future__ import annotations

import json
import sqlite3
from io import StringIO

import pytest

from site_b2b_intel.db import repository as repo
from site_b2b_intel.reports.serialize import (
    CSV_COLUMNS,
    SCHEMA_VERSION,
    domain_payload,
    payload_to_csv_rows,
    payload_to_json,
    scan_payload,
    write_csv,
)
from site_b2b_intel.types import ScanFlag

WHEN = "2026-01-15T10:00:00.000000Z"


def _seed(db: sqlite3.Connection, *, flags: int = 0) -> int:
    """Create one scan with two vendors, one of them multi-signal."""
    gw = repo.upsert_vendor(
        db, slug="google-workspace", name="Google Workspace",
        category="productivity",
    )
    cf = repo.upsert_vendor(
        db, slug="cloudflare", name="Cloudflare", category="cdn"
    )
    # Google Workspace detected twice: once medium, once high.
    r_mx = repo.upsert_rule(
        db, vendor_id=gw, record_type="MX", match_kind="exact",
        pattern="aspmx.l.google.com", confidence="high",
    )
    r_dkim = repo.upsert_rule(
        db, vendor_id=gw, record_type="DKIM_SELECTOR", match_kind="exact",
        pattern="google", confidence="medium",
    )
    r_ns = repo.upsert_rule(
        db, vendor_id=cf, record_type="NS", match_kind="suffix",
        pattern=".ns.cloudflare.com", confidence="high",
    )

    scan_id = repo.insert_scan(
        db, domain="https://acme.test/x", domain_normalized="acme.test",
        scanned_at=WHEN, resolver_used="1.1.1.1", dns_seconds=1.5,
        flags=flags,
    )
    mx_rec = repo.insert_dns_record(
        db, scan_id=scan_id, record_type="MX", name="acme.test",
        value="aspmx.l.google.com", ttl=300,
    )
    dkim_rec = repo.insert_dns_record(
        db, scan_id=scan_id, record_type="DKIM_SELECTOR",
        name="google._domainkey.acme.test", value="google", ttl=300,
    )
    ns_rec = repo.insert_dns_record(
        db, scan_id=scan_id, record_type="NS", name="acme.test",
        value="a.ns.cloudflare.com", ttl=86400,
    )

    for rule_id, vid, conf, rec in (
        (r_mx, gw, "high", mx_rec),
        (r_dkim, gw, "medium", dkim_rec),
        (r_ns, cf, "high", ns_rec),
    ):
        det = repo.insert_detection(
            db, scan_id=scan_id, vendor_id=vid, rule_id=rule_id,
            confidence=conf,
        )
        repo.insert_detection_evidence(
            db, detection_id=det, dns_record_id=rec
        )
        repo.upsert_observation(
            db, domain_normalized="acme.test", vendor_id=vid, seen_at=WHEN
        )
    return scan_id


class TestPayloadShape:
    def test_top_level_keys(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        p = scan_payload(db, sid)
        assert p["schema_version"] == SCHEMA_VERSION
        assert p["tool"]["name"] == "site-b2b-intel"
        assert p["domain"] == "acme.test"
        assert p["input"] == "https://acme.test/x"
        assert p["scan"]["id"] == sid
        assert p["scan"]["resolver_used"] == "1.1.1.1"

    def test_vendors_sorted_by_name(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        names = [v["name"] for v in scan_payload(db, sid)["vendors"]]
        assert names == sorted(names, key=str.lower)

    def test_flags_serialize_as_names_not_bitfield(
        self, db: sqlite3.Connection
    ) -> None:
        sid = _seed(db, flags=ScanFlag.NO_MX)
        flags = scan_payload(db, sid)["scan"]["flags"]
        assert flags == ["NO_MX"]
        assert not isinstance(flags, int)

    def test_no_flags_is_empty_list(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        assert scan_payload(db, sid)["scan"]["flags"] == []

    def test_vendor_confidence_is_max_over_signals(
        self, db: sqlite3.Connection
    ) -> None:
        """Google Workspace has a high MX and a medium DKIM signal."""
        sid = _seed(db)
        gw = next(
            v
            for v in scan_payload(db, sid)["vendors"]
            if v["slug"] == "google-workspace"
        )
        assert len(gw["signals"]) == 2
        assert {s["confidence"] for s in gw["signals"]} == {"high", "medium"}
        assert gw["confidence"] == "high"

    def test_evidence_is_nested_not_concatenated(
        self, db: sqlite3.Connection
    ) -> None:
        sid = _seed(db)
        cf = next(
            v
            for v in scan_payload(db, sid)["vendors"]
            if v["slug"] == "cloudflare"
        )
        ev = cf["signals"][0]["evidence"]
        assert ev == [
            {
                "record_type": "NS",
                "name": "acme.test",
                "value": "a.ns.cloudflare.com",
            }
        ]

    def test_records_excluded_by_default(
        self, db: sqlite3.Connection
    ) -> None:
        sid = _seed(db)
        assert "records" not in scan_payload(db, sid)

    def test_include_records(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        p = scan_payload(db, sid, include_records=True)
        assert len(p["records"]) == 3

    def test_unknown_scan_id_raises(self, db: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            scan_payload(db, 9999)


class TestDomainPayload:
    def test_never_scanned_domain(self, db: sqlite3.Connection) -> None:
        p = domain_payload(db, "never-seen.test")
        assert p["scan"] is None
        assert p["vendors"] == []
        assert p["schema_version"] == SCHEMA_VERSION

    def test_returns_latest_scan(self, db: sqlite3.Connection) -> None:
        _seed(db)
        p = domain_payload(db, "acme.test")
        assert p["scan"]["scanned_at"] == WHEN


class TestJson:
    def test_round_trips(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        text = payload_to_json(scan_payload(db, sid))
        assert json.loads(text)["domain"] == "acme.test"


class TestCsv:
    def test_one_row_per_signal(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        rows = payload_to_csv_rows(scan_payload(db, sid))
        # 3 detections total, even though only 2 vendors.
        assert len(rows) == 3

    def test_columns_match_header(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        rows = payload_to_csv_rows(scan_payload(db, sid))
        assert set(rows[0]) == set(CSV_COLUMNS)

    def test_write_csv_header(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        buf = StringIO()
        write_csv(payload_to_csv_rows(scan_payload(db, sid)), buf)
        lines = buf.getvalue().strip().splitlines()
        assert lines[0] == ",".join(CSV_COLUMNS)
        assert len(lines) == 4  # header + 3 signals

    def test_write_csv_without_header(self, db: sqlite3.Connection) -> None:
        sid = _seed(db)
        buf = StringIO()
        write_csv(
            payload_to_csv_rows(scan_payload(db, sid)), buf, header=False
        )
        assert len(buf.getvalue().strip().splitlines()) == 3

    def test_empty_payload_yields_no_rows(
        self, db: sqlite3.Connection
    ) -> None:
        assert payload_to_csv_rows(domain_payload(db, "nope.test")) == []
