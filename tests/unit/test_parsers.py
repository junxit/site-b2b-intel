"""Tests for DNS parsers (SPF / DMARC)."""

from __future__ import annotations

from site_b2b_intel.resolve.parsers import (
    mailbox_domain,
    parse_dmarc,
    parse_dmarc_rua,
    parse_spf,
)


class TestParseSpf:
    def test_single_include(self) -> None:
        assert parse_spf("v=spf1 include:_spf.google.com -all") == [
            "_spf.google.com"
        ]

    def test_multiple_includes(self) -> None:
        v = (
            "v=spf1 include:_spf.google.com include:mailgun.org "
            "include:sendgrid.net ~all"
        )
        assert parse_spf(v) == ["_spf.google.com", "mailgun.org", "sendgrid.net"]

    def test_include_and_redirect(self) -> None:
        v = "v=spf1 include:_spf.google.com redirect=spf.parent.com"
        assert parse_spf(v) == ["_spf.google.com", "spf.parent.com"]

    def test_with_qualifier(self) -> None:
        assert parse_spf("v=spf1 +include:_spf.google.com -all") == [
            "_spf.google.com"
        ]

    def test_no_includes(self) -> None:
        assert parse_spf("v=spf1 ip4:192.0.2.0/24 -all") == []

    def test_not_spf(self) -> None:
        assert parse_spf("v=DMARC1; p=none") == []


class TestParseDmarc:
    def test_basic(self) -> None:
        v = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
        tags = parse_dmarc(v)
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "reject"
        assert tags["rua"] == "mailto:dmarc@example.com"
        assert tags["pct"] == "100"

    def test_case_insensitive_tags(self) -> None:
        tags = parse_dmarc("v=DMARC1; P=quarantine; RUA=mailto:r@x.com")
        assert tags["p"] == "quarantine"
        assert tags["rua"] == "mailto:r@x.com"

    def test_trailing_semicolon(self) -> None:
        tags = parse_dmarc("v=DMARC1; p=none;")
        assert tags == {"v": "DMARC1", "p": "none"}

    def test_not_dmarc(self) -> None:
        assert parse_dmarc("v=spf1 ...") == {}

    def test_whitespace_tolerant(self) -> None:
        tags = parse_dmarc("  v=DMARC1 ;  p = none  ")
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "none"


class TestParseDmarcRua:
    def test_single(self) -> None:
        assert parse_dmarc_rua("mailto:dmarc@example.com") == [
            "dmarc@example.com"
        ]

    def test_multiple(self) -> None:
        v = "mailto:a@one.com,mailto:b@two.com, mailto:c@three.com"
        assert parse_dmarc_rua(v) == [
            "a@one.com",
            "b@two.com",
            "c@three.com",
        ]

    def test_without_scheme(self) -> None:
        assert parse_dmarc_rua("a@one.com") == ["a@one.com"]

    def test_empty(self) -> None:
        assert parse_dmarc_rua("") == []


class TestMailboxDomain:
    def test_basic(self) -> None:
        assert mailbox_domain("dmarc@dmarcian.com") == "dmarcian.com"

    def test_uppercase_lowered(self) -> None:
        assert mailbox_domain("d@EXAMPLE.COM") == "example.com"

    def test_no_at_returns_none(self) -> None:
        assert mailbox_domain("not-a-mailbox") is None
