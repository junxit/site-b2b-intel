"""Tests for the scanner with a fake resolver — no network required."""

from __future__ import annotations

import sqlite3
from collections import defaultdict

import pytest

from site_b2b_intel.db import repository as repo
from site_b2b_intel.fingerprints.catalog import load_catalog, seed_catalog
from site_b2b_intel.scan.scanner import (
    UnseededCatalogError,
    collect_records,
    scan_domain,
)
from site_b2b_intel.types import NXDOMAIN, ParsedRecord


class FakeResolver:
    """Replays canned responses for ``(name, record_type)`` pairs."""

    dkim_selectors = ("google", "selector1", "k1", "mandrill", "s1", "smtpapi")
    cname_probes = ("www", "shop", "status", "support")
    last_used = "fake://"

    def __init__(self, answers: dict[tuple[str, str], list[ParsedRecord]] | None = None):
        self.answers: dict[tuple[str, str], list[ParsedRecord]] = answers or {}
        self.nxdomains: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, record_type: str) -> list[ParsedRecord]:
        self.calls.append((name, record_type))
        if name in self.nxdomains:
            raise NXDOMAIN(f"{name}: NXDOMAIN (fake)")
        return self.answers.get((name, record_type), [])


def _stripe_like_resolver() -> FakeResolver:
    """A resolver wired up to look like stripe.com's likely public surface.

    Real values change over time; the test only cares that the matcher
    fires on the rules we shipped in the seed YAML.
    """
    answers: dict[tuple[str, str], list[ParsedRecord]] = defaultdict(list)
    # Apex MX → Google Workspace
    answers[("stripe.com", "MX")] = [
        ParsedRecord("MX", "stripe.com", "aspmx.l.google.com", 300),
        ParsedRecord("MX", "stripe.com", "alt1.aspmx.l.google.com", 300),
    ]
    # Apex TXT — SPF includes Google + verification token
    answers[("stripe.com", "TXT")] = [
        ParsedRecord(
            "TXT",
            "stripe.com",
            "v=spf1 include:_spf.google.com include:amazonses.com ~all",
            300,
        ),
        ParsedRecord(
            "TXT",
            "stripe.com",
            "stripe-verification=abc123",
            300,
        ),
    ]
    # NS → Cloudflare
    answers[("stripe.com", "NS")] = [
        ParsedRecord("NS", "stripe.com", "ns1.ns.cloudflare.com", 86400),
        ParsedRecord("NS", "stripe.com", "ns2.ns.cloudflare.com", 86400),
    ]
    # CAA — two authorized issuers plus an iodef that must NOT become a vendor
    answers[("stripe.com", "CAA")] = [
        ParsedRecord("CAA", "stripe.com", "0 issue amazon.com", 300),
        ParsedRecord(
            "CAA", "stripe.com", '0 issuewild "digicert.com; policy=ev"', 300
        ),
        ParsedRecord(
            "CAA", "stripe.com", "0 iodef mailto:security@stripe.com", 300
        ),
    ]
    # DMARC
    answers[("_dmarc.stripe.com", "TXT")] = [
        ParsedRecord(
            "TXT",
            "_dmarc.stripe.com",
            "v=DMARC1; p=reject; rua=mailto:dmarc@stripe.com",
            300,
        ),
    ]
    # DKIM selectors — google present
    answers[("google._domainkey.stripe.com", "TXT")] = [
        ParsedRecord(
            "TXT", "google._domainkey.stripe.com", "v=DKIM1; k=rsa; p=MIGfMA...", 3600
        ),
    ]
    # CNAME probes — status. delegates to Statuspage
    answers[("status.stripe.com", "CNAME")] = [
        ParsedRecord(
            "CNAME", "status.stripe.com", "stripe.statuspage.io", 300
        ),
    ]
    return FakeResolver(answers)


class TestCollectRecords:
    def test_apex_probes_run(self) -> None:
        resolver = _stripe_like_resolver()
        records, flags, error = collect_records(resolver, "stripe.com")
        assert error is None
        assert flags == 0
        record_types = {r.record_type for r in records}
        assert {"MX", "TXT", "NS", "SPF", "DMARC_RUA", "DKIM_SELECTOR"} <= record_types

    def test_spf_includes_emitted(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        spf_values = sorted(r.value for r in records if r.record_type == "SPF")
        assert spf_values == ["_spf.google.com", "amazonses.com"]

    def test_dmarc_rua_emitted(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        rua = [r for r in records if r.record_type == "DMARC_RUA"]
        assert len(rua) == 1
        assert rua[0].value == "stripe.com"

    def test_dkim_selector_emitted(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        dkim = [r for r in records if r.record_type == "DKIM_SELECTOR"]
        assert {r.value for r in dkim} == {"google"}

    def test_caa_issuer_emitted(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        issuers = {
            r.value for r in records if r.record_type == "CAA_ISSUER"
        }
        # iodef is a reporting address, not a CA — it must not appear.
        assert issuers == {"amazon.com", "digicert.com"}

    def test_raw_caa_preserved_alongside_issuer(self) -> None:
        """The derived record must not replace the auditable original."""
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        raw = [r for r in records if r.record_type == "CAA"]
        assert len(raw) == 3
        assert any("iodef" in r.value for r in raw)
        assert any(r.value.startswith("0 issuewild") for r in raw)

    def test_nxdomain_returns_error(self) -> None:
        resolver = FakeResolver()
        resolver.nxdomains.add("nope.example")
        records, flags, error = collect_records(resolver, "nope.example")
        assert records == []
        assert error == "NXDOMAIN"

    def test_cname_probe_emitted(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(resolver, "stripe.com")
        cnames = [r for r in records if r.record_type == "CNAME"]
        assert len(cnames) == 1
        assert cnames[0].value == "stripe.statuspage.io"
        assert cnames[0].name == "status.stripe.com"
        assert cnames[0].source == "cname-probe"

    def test_dead_cname_probe_does_not_abort_scan(self) -> None:
        """A CNAME aimed at a decommissioned target raises NXDOMAIN.

        That must not be mistaken for the apex not existing — otherwise one
        stale `shop.` record makes a live domain look nonexistent and the
        whole scan is silently lost.
        """
        resolver = _stripe_like_resolver()
        resolver.nxdomains.add("shop.stripe.com")
        records, flags, error = collect_records(resolver, "stripe.com")
        assert error is None
        assert len(records) > 0
        # The surviving probe still landed.
        assert any(r.record_type == "CNAME" for r in records)

    def test_probing_disabled_issues_no_cname_queries(self) -> None:
        resolver = _stripe_like_resolver()
        records, _, _ = collect_records(
            resolver, "stripe.com", cname_probes=()
        )
        assert not [c for c in resolver.calls if c[1] == "CNAME"]
        assert not [r for r in records if r.record_type == "CNAME"]

    def test_probe_count_matches_label_count(self) -> None:
        resolver = _stripe_like_resolver()
        collect_records(resolver, "stripe.com")
        cname_calls = [c for c in resolver.calls if c[1] == "CNAME"]
        assert len(cname_calls) == len(FakeResolver.cname_probes)

    def test_no_mx_sets_flag(self) -> None:
        from site_b2b_intel.types import ScanFlag

        resolver = FakeResolver({("noemail.example", "A"): [
            ParsedRecord("A", "noemail.example", "203.0.113.1", 60),
        ]})
        records, flags, error = collect_records(resolver, "noemail.example")
        assert error is None
        assert flags & ScanFlag.NO_MX


class TestScanDomain:
    def test_stripe_detects_expected_vendors(
        self, db: sqlite3.Connection
    ) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)

        resolver = _stripe_like_resolver()
        scan_id = scan_domain(db, resolver, catalog, "stripe.com")

        rows = repo.detections_for_scan(db, scan_id)
        slugs = {r["vendor_slug"] for r in rows}
        # Should at minimum detect:
        # - google-workspace via MX + SPF + DKIM selector
        # - stripe via TXT verification
        # - cloudflare via NS
        # - aws-ses via SPF include amazonses.com
        assert "google-workspace" in slugs
        assert "stripe" in slugs
        assert "cloudflare" in slugs
        assert "aws-ses" in slugs

    def test_url_input_normalized(self, db: sqlite3.Connection) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)
        resolver = _stripe_like_resolver()
        scan_id = scan_domain(db, resolver, catalog, "https://x.stripe.com/foo")
        scan_row = db.execute(
            "SELECT * FROM scan WHERE id = ?", (scan_id,)
        ).fetchone()
        assert scan_row["domain"] == "https://x.stripe.com/foo"
        assert scan_row["domain_normalized"] == "stripe.com"

    def test_rescan_observation_count_grows(
        self, db: sqlite3.Connection
    ) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)
        resolver = _stripe_like_resolver()
        scan_domain(db, resolver, catalog, "stripe.com")
        scan_domain(db, resolver, catalog, "stripe.com")

        obs = repo.observations_for_domain(db, "stripe.com")
        # Every observation should have detection_count >= 2 now
        assert all(o["detection_count"] >= 2 for o in obs)

    def test_unseeded_db_raises_instead_of_silently_finding_nothing(
        self, db: sqlite3.Connection
    ) -> None:
        """Regression: scanning an unseeded DB reported success with zero
        vendors.

        Detections are matched against the in-memory YAML catalog but
        persisted by DB row id. With no vendors in the database every
        detection mapped to nothing and was dropped by a bare `continue`,
        so a scan that resolved 40+ records looked like a clean run that
        simply found no vendors. Failing loudly is the whole point.
        """
        catalog = load_catalog()
        # Deliberately NOT seeded.
        resolver = _stripe_like_resolver()
        with pytest.raises(UnseededCatalogError, match="no vendor catalog"):
            scan_domain(db, resolver, catalog, "stripe.com")

    def test_nxdomain_persists_scan_with_error(
        self, db: sqlite3.Connection
    ) -> None:
        catalog = load_catalog()
        seed_catalog(db, catalog)
        resolver = FakeResolver()
        resolver.nxdomains.add("does-not-exist-12345.com")
        scan_id = scan_domain(db, resolver, catalog, "does-not-exist-12345.com")
        row = db.execute(
            "SELECT * FROM scan WHERE id = ?", (scan_id,)
        ).fetchone()
        assert row["error"] == "NXDOMAIN"
        rows = repo.detections_for_scan(db, scan_id)
        assert rows == []
