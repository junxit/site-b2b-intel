"""Shared type contracts.

Protocols, dataclasses, and string literals referenced from more than one
subpackage live here. This module has no runtime dependencies on any other
module in the package so it can be imported from anywhere without cycles.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, get_args, runtime_checkable

# Record types the scanner produces. Two groups:
#
#   * Resolved directly from DNS — the value is the record's own content.
#   * Synthesized by the scanner from the contents of a resolved record, so
#     the matcher can target a single meaningful token with a simple rule
#     rather than re-parsing a compound string. For example a TXT record
#     holding `v=spf1 include:_spf.google.com ~all` also yields an `SPF`
#     record whose value is just `_spf.google.com`.
#
# The raw record is always persisted alongside anything derived from it, so
# the audit trail survives.
RecordType = Literal[
    # Resolved directly
    "A",
    "AAAA",
    "TXT",
    "MX",
    "NS",
    "CNAME",
    "CAA",
    # Synthesized by the scanner
    "SPF",
    "DMARC_RUA",
    "DKIM_SELECTOR",
    "AWSSES_VERIFY",
    "CAA_ISSUER",
]

#: Every valid `record_type`, derived from :data:`RecordType` so the Literal
#: stays the single source of truth. The catalog loader validates YAML rules
#: against this — a typo like `record_type: DMARC` would otherwise produce a
#: rule that silently never matches anything.
KNOWN_RECORD_TYPES: frozenset[str] = frozenset(get_args(RecordType))

MatchKind = Literal["prefix", "suffix", "contains", "exact", "regex"]

#: Every valid `match_kind`, kept in sync with :data:`MatchKind`.
KNOWN_MATCH_KINDS: frozenset[str] = frozenset(get_args(MatchKind))


class Confidence(str, Enum):
    """How strong a fingerprint match is.

    Stored as TEXT in SQLite so rule authors can write `confidence: high`
    in YAML without knowing the numeric scale.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanFlag:
    """Bit flags packed into `scan.flags`."""

    NO_MX = 1 << 0
    WILDCARD_SUSPECTED = 1 << 1
    DNSSEC_FAIL = 1 << 2


@dataclass(frozen=True, slots=True)
class ParsedRecord:
    """A normalized DNS record observation.

    Attributes:
        record_type: One of RecordType. For records that were parsed out of
            a TXT (SPF, DMARC, DKIM), this is the synthetic type, not 'TXT'.
        name: The DNS name queried, e.g. 'example.com' or
            '_dmarc.example.com' or 'google._domainkey.example.com'.
        value: Normalized value. For MX, the exchange host (no priority).
            For TXT, the concatenated string per RFC 7208 §3.3.
        ttl: Time-to-live in seconds if the resolver returned one.
        source: How this record was obtained:
            'direct'        — top-level query for `name`.
            'spf-include'   — pulled in via SPF `include:` / `redirect=`.
            'cname-target'  — followed from a CNAME chain.
        parent_record_id: For derived records, the DB id of the record they
            came from. Filled in after persistence; None pre-persist.
    """

    record_type: str
    name: str
    value: str
    ttl: int | None = None
    source: str = "direct"
    parent_record_id: int | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    """A fingerprint rule that identifies a vendor.

    Attributes:
        rule_id: DB row id; None for rules just loaded from YAML.
        vendor_slug: Vendor identifier (stable across runs, e.g.
            'google-workspace').
        record_type: Which record type this rule applies to.
        match_kind: How `pattern` is compared against the record value.
        pattern: The pattern, interpreted per `match_kind`. For 'regex' this
            is an uncompiled Python regex.
        confidence: How strong a match is considered.
        enabled: Whether this rule is active. Disabled rules are kept in the
            DB so historical detections can still be resolved.
    """

    rule_id: int | None
    vendor_slug: str
    record_type: str
    match_kind: str
    pattern: str
    confidence: Confidence
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class Detection:
    """A Rule fired against a ParsedRecord.

    Carries enough info to persist a `detection` row + its
    `detection_evidence` link.
    """

    rule: Rule
    record: ParsedRecord
    confidence: Confidence


class ResolverError(Exception):
    """Base class for DNS resolution failures the scanner should surface."""


class NXDOMAIN(ResolverError):
    """The domain does not exist (negative answer from the authoritative side)."""


class ResolverTimeout(ResolverError):
    """All configured upstreams timed out for this query."""


@runtime_checkable
class Resolver(Protocol):
    """Resolves DNS records for a domain.

    Implementations may swap in mocks (for tests) or async backends later.
    """

    def query(self, name: str, record_type: str) -> list[ParsedRecord]:
        """Query a single record type for a name.

        Returns an empty list if the name exists but has no records of the
        requested type (e.g. domain has no MX). NXDOMAIN raises; transient
        failures are retried internally and only escalate to a
        ResolverTimeout after all upstreams are exhausted.

        Args:
            name: Fully qualified DNS name. Caller is responsible for any
                normalization (punycode, lowercasing).
            record_type: One of RecordType. Note: SPF/DMARC/DKIM are queried
                as TXT under the hood; pass 'TXT' here.

        Raises:
            NXDOMAIN: The name does not exist.
            ResolverTimeout: All upstreams exhausted without an answer.
        """
        ...
