"""Unit tests for site_b2b_intel.normalize."""

from __future__ import annotations

import pytest

from site_b2b_intel.normalize import (
    extract_spf_target,
    split_spf_mechanisms,
    to_registrable_domain,
)


class TestToRegistrableDomain:
    def test_bare_domain(self) -> None:
        assert to_registrable_domain("stripe.com") == "stripe.com"

    def test_uppercase(self) -> None:
        assert to_registrable_domain("STRIPE.COM") == "stripe.com"

    def test_subdomain_stripped(self) -> None:
        assert to_registrable_domain("api.stripe.com") == "stripe.com"

    def test_deep_subdomain(self) -> None:
        assert to_registrable_domain("a.b.c.stripe.com") == "stripe.com"

    def test_url(self) -> None:
        assert (
            to_registrable_domain("https://x.stripe.com/foo?bar=1")
            == "stripe.com"
        )

    def test_url_with_port(self) -> None:
        assert to_registrable_domain("https://stripe.com:8443/") == "stripe.com"

    def test_email(self) -> None:
        assert to_registrable_domain("user@stripe.com") == "stripe.com"

    def test_email_in_url_path(self) -> None:
        # weird but legal-ish: bare domain followed by path
        assert to_registrable_domain("stripe.com/foo") == "stripe.com"

    def test_multipart_public_suffix(self) -> None:
        assert to_registrable_domain("example.co.uk") == "example.co.uk"
        assert to_registrable_domain("api.example.co.uk") == "example.co.uk"

    def test_punycode_roundtrip(self) -> None:
        assert to_registrable_domain("bücher.de") == "xn--bcher-kva.de"

    def test_trailing_dot(self) -> None:
        assert to_registrable_domain("stripe.com.") == "stripe.com"

    def test_whitespace(self) -> None:
        assert to_registrable_domain("  stripe.com  ") == "stripe.com"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            to_registrable_domain("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError):
            to_registrable_domain("   ")

    def test_no_public_suffix_raises(self) -> None:
        with pytest.raises(ValueError):
            to_registrable_domain("localhost")

    def test_bare_tld_raises(self) -> None:
        with pytest.raises(ValueError):
            to_registrable_domain("com")


class TestSplitSpfMechanisms:
    def test_simple(self) -> None:
        assert split_spf_mechanisms("v=spf1 include:_spf.google.com -all") == [
            "include:_spf.google.com",
            "-all",
        ]

    def test_multiple_includes(self) -> None:
        result = split_spf_mechanisms(
            "v=spf1 include:_spf.google.com include:mailgun.org ~all"
        )
        assert result == [
            "include:_spf.google.com",
            "include:mailgun.org",
            "~all",
        ]

    def test_empty_after_version(self) -> None:
        assert split_spf_mechanisms("v=spf1") == []

    def test_not_an_spf_record(self) -> None:
        assert split_spf_mechanisms("not an spf record") == []
        assert split_spf_mechanisms("v=DMARC1; p=none") == []

    def test_extra_whitespace_collapsed(self) -> None:
        assert split_spf_mechanisms("v=spf1   include:foo   -all") == [
            "include:foo",
            "-all",
        ]


class TestExtractSpfTarget:
    def test_include(self) -> None:
        assert (
            extract_spf_target("include:_spf.google.com") == "_spf.google.com"
        )

    def test_redirect(self) -> None:
        assert extract_spf_target("redirect=spf.example.com") == "spf.example.com"

    def test_qualifier_prefix(self) -> None:
        for q in "+-~?":
            assert (
                extract_spf_target(f"{q}include:_spf.google.com")
                == "_spf.google.com"
            )

    def test_non_target_mechanism(self) -> None:
        assert extract_spf_target("-all") is None
        assert extract_spf_target("ip4:192.0.2.0/24") is None
        assert extract_spf_target("a") is None
        assert extract_spf_target("mx") is None
        assert extract_spf_target("ptr") is None

    def test_empty(self) -> None:
        assert extract_spf_target("") is None
