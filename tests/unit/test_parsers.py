"""Tests for DNS parsers (SPF / DMARC)."""

from __future__ import annotations

from site_b2b_intel.resolve.parsers import (
    caa_issuer_domain,
    mailbox_domain,
    parse_caa,
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


class TestParseCaa:
    def test_issue(self) -> None:
        assert parse_caa("0 issue letsencrypt.org") == (
            0,
            "issue",
            "letsencrypt.org",
        )

    def test_issuewild(self) -> None:
        assert parse_caa("0 issuewild digicert.com") == (
            0,
            "issuewild",
            "digicert.com",
        )

    def test_critical_flag_preserved(self) -> None:
        flags, tag, _ = parse_caa("128 issue sectigo.com")
        assert flags == 128
        assert tag == "issue"

    def test_tag_lowercased(self) -> None:
        assert parse_caa("0 ISSUE letsencrypt.org")[1] == "issue"

    def test_quotes_stripped(self) -> None:
        assert parse_caa('0 issue "letsencrypt.org"')[2] == "letsencrypt.org"

    def test_too_few_fields(self) -> None:
        assert parse_caa("0 issue") is None
        assert parse_caa("garbage") is None

    def test_non_numeric_flags(self) -> None:
        assert parse_caa("x issue letsencrypt.org") is None


class TestCaaIssuerDomain:
    def test_issue(self) -> None:
        assert caa_issuer_domain("0 issue letsencrypt.org") == "letsencrypt.org"

    def test_issuewild(self) -> None:
        assert caa_issuer_domain("0 issuewild digicert.com") == "digicert.com"

    def test_parameters_stripped(self) -> None:
        assert (
            caa_issuer_domain('0 issue "digicert.com; policy=ev"')
            == "digicert.com"
        )

    def test_validationmethods_stripped(self) -> None:
        assert (
            caa_issuer_domain(
                "0 issue letsencrypt.org;validationmethods=dns-01"
            )
            == "letsencrypt.org"
        )

    def test_lowercased(self) -> None:
        assert caa_issuer_domain("0 issue LetsEncrypt.ORG") == "letsencrypt.org"

    def test_iodef_ignored(self) -> None:
        # A reporting URI is not a CA. Treating it as one would invent a
        # detection for a vendor the domain does not actually use.
        assert caa_issuer_domain("0 iodef mailto:security@example.com") is None
        assert caa_issuer_domain("0 iodef https://example.com/caa") is None

    def test_no_issuance_permitted(self) -> None:
        # RFC 8659: `;` authorizes nobody.
        assert caa_issuer_domain('0 issue ";"') is None
        assert caa_issuer_domain("0 issue ;") is None

    def test_malformed(self) -> None:
        assert caa_issuer_domain("garbage") is None
        assert caa_issuer_domain("") is None
