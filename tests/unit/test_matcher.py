"""Tests for the fingerprint matcher."""

from __future__ import annotations

import pytest

from site_b2b_intel.fingerprints.matcher import match
from site_b2b_intel.types import Confidence, ParsedRecord, Rule


def _rule(
    record_type: str,
    match_kind: str,
    pattern: str,
    *,
    slug: str = "v",
    enabled: bool = True,
    confidence: Confidence = Confidence.HIGH,
) -> Rule:
    return Rule(
        rule_id=None,
        vendor_slug=slug,
        record_type=record_type,
        match_kind=match_kind,
        pattern=pattern,
        confidence=confidence,
        enabled=enabled,
    )


def _rec(
    record_type: str, value: str, *, name: str = "example.com"
) -> ParsedRecord:
    return ParsedRecord(record_type=record_type, name=name, value=value)


class TestMatchKinds:
    def test_exact(self) -> None:
        rules = {"SPF": [_rule("SPF", "exact", "_spf.google.com")]}
        recs = [
            _rec("SPF", "_spf.google.com"),
            _rec("SPF", "_spf.other.com"),
        ]
        dets = match(recs, rules)
        assert len(dets) == 1
        assert dets[0].record.value == "_spf.google.com"

    def test_prefix(self) -> None:
        rules = {"TXT": [_rule("TXT", "prefix", "google-site-verification=")]}
        recs = [
            _rec("TXT", "google-site-verification=abc123"),
            _rec("TXT", "v=spf1 ..."),
        ]
        dets = match(recs, rules)
        assert len(dets) == 1

    def test_suffix(self) -> None:
        rules = {"MX": [_rule("MX", "suffix", "aspmx.l.google.com")]}
        recs = [
            _rec("MX", "alt1.aspmx.l.google.com"),
            _rec("MX", "mx.example.com"),
        ]
        dets = match(recs, rules)
        assert len(dets) == 1

    def test_contains(self) -> None:
        rules = {"SPF": [_rule("SPF", "contains", "mailgun.org")]}
        recs = [
            _rec("SPF", "subdomain.mailgun.org.other"),
            _rec("SPF", "foo.bar"),
        ]
        dets = match(recs, rules)
        assert len(dets) == 1

    def test_regex(self) -> None:
        rules = {
            "NS": [_rule("NS", "regex", r"\.awsdns-\d+\.(com|net|org|co\.uk)$")]
        }
        recs = [
            _rec("NS", "ns-1234.awsdns-12.com"),
            _rec("NS", "ns-1234.awsdns-56.co.uk"),
            _rec("NS", "ns1.example.net"),
        ]
        dets = match(recs, rules)
        assert len(dets) == 2

    def test_unknown_kind_raises(self) -> None:
        rules = {"TXT": [_rule("TXT", "weird", "foo")]}
        recs = [_rec("TXT", "foo")]
        with pytest.raises(ValueError, match="unknown match_kind"):
            match(recs, rules)


class TestMultipleMatches:
    def test_one_rule_two_records(self) -> None:
        rules = {"MX": [_rule("MX", "suffix", ".outlook.com")]}
        recs = [
            _rec("MX", "a.outlook.com"),
            _rec("MX", "b.outlook.com"),
        ]
        dets = match(recs, rules)
        assert len(dets) == 2

    def test_two_rules_one_record(self) -> None:
        rules = {
            "TXT": [
                _rule(
                    "TXT",
                    "prefix",
                    "google-site-verification=",
                    slug="google",
                ),
                _rule("TXT", "contains", "verification", slug="generic"),
            ]
        }
        recs = [_rec("TXT", "google-site-verification=xyz")]
        dets = match(recs, rules)
        assert len(dets) == 2


class TestDisabledAndMissing:
    def test_disabled_rule_skipped(self) -> None:
        rule = _rule("TXT", "exact", "foo", enabled=False)
        dets = match([_rec("TXT", "foo")], {"TXT": [rule]})
        assert dets == []

    def test_no_rules_for_record_type(self) -> None:
        rules = {"TXT": [_rule("TXT", "exact", "foo")]}
        dets = match([_rec("MX", "foo")], rules)
        assert dets == []

    def test_empty_inputs(self) -> None:
        assert match([], {}) == []


class TestConfidencePassThrough:
    def test_rule_confidence_used(self) -> None:
        rule = _rule(
            "TXT", "exact", "foo", confidence=Confidence.MEDIUM
        )
        dets = match([_rec("TXT", "foo")], {"TXT": [rule]})
        assert dets[0].confidence is Confidence.MEDIUM
