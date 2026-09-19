"""End-to-end scan orchestration: resolve → parse → match → persist.

Composes the resolver, parsers, matcher, and repository inside a single
SQLite transaction. Idempotent at the rule level (detection rows dedupe
on ``(scan_id, vendor_id, rule_id)``); each call inserts a fresh ``scan``
row so re-running over time produces history rather than overwriting.
"""

from __future__ import annotations

import sqlite3
import time
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

from site_b2b_intel.db import repository as repo
from site_b2b_intel.fingerprints.catalog import VendorCatalog
from site_b2b_intel.fingerprints.matcher import match
from site_b2b_intel.normalize import to_registrable_domain
from site_b2b_intel.resolve.parsers import (
    caa_issuer_domain,
    mailbox_domain,
    parse_dmarc,
    parse_dmarc_rua,
    parse_spf,
)
from site_b2b_intel.resolve.resolver import (
    DEFAULT_CNAME_PROBES,
    DEFAULT_DKIM_SELECTORS,
)
from site_b2b_intel.types import (
    NXDOMAIN,
    Detection,
    ParsedRecord,
    Resolver,
    ResolverTimeout,
    ScanFlag,
)


class UnseededCatalogError(RuntimeError):
    """Raised when scanning against a database with no vendor catalog.

    ``open_db`` creates the database and applies the schema on demand, so
    it is easy to end up with a structurally valid but empty catalog. That
    state would otherwise produce a successful-looking scan with zero
    detections, which is far worse than an error.
    """


def _now_iso() -> str:
    return (
        datetime.now(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def collect_records(
    resolver: Resolver,
    domain: str,
    *,
    cname_probes: Iterable[str] | None = None,
) -> tuple[list[ParsedRecord], int, str | None]:
    """Probe DNS for a domain and synthesize derived record types.

    Queries the apex for A/AAAA/NS/MX/TXT/CAA, then probes well-known
    subdomains for DMARC, AWS SES verification, and known DKIM selectors.
    Parses SPF and DMARC out of TXT and emits synthetic ``SPF``,
    ``DMARC_RUA``, ``DKIM_SELECTOR``, and ``AWSSES_VERIFY`` records the
    matcher can target directly.

    Args:
        resolver: Any :class:`Resolver` implementation. Real
            :class:`DnsResolver` for network scans, mocks for tests.
        domain: Already-normalized registrable domain.
        cname_probes: Subdomain labels to probe for CNAMEs. Defaults to
            the resolver's own list. Pass ``()`` to skip probing entirely
            — that saves ~15 queries per domain, which matters when
            batch-scanning.

    Returns:
        ``(records, flags, error)`` — ``flags`` is a bitfield of
        :class:`ScanFlag` values; ``error`` is non-None only on hard
        failure (``'NXDOMAIN'``).
    """
    records: list[ParsedRecord] = []
    flags = 0

    # Apex queries
    for rt in ("A", "AAAA", "NS", "MX", "TXT", "CAA"):
        try:
            recs = resolver.query(domain, rt)
        except NXDOMAIN:
            return [], 0, "NXDOMAIN"
        except ResolverTimeout:
            continue
        records.extend(recs)
        if rt == "MX" and not recs:
            flags |= ScanFlag.NO_MX

    # Derive SPF mechanisms from apex TXT
    for rec in list(records):
        if (
            rec.record_type == "TXT"
            and rec.value.lower().startswith("v=spf1")
        ):
            for target in parse_spf(rec.value):
                records.append(
                    ParsedRecord(
                        record_type="SPF",
                        name=rec.name,
                        value=target,
                        ttl=rec.ttl,
                        source="spf-include",
                    )
                )

    # Derive the authorized CA from each CAA record. The raw CAA row is kept
    # alongside so the flags and the issue/issuewild distinction survive for
    # audit; only the derived record carries a bare issuer domain that simple
    # exact/suffix rules can match.
    for rec in list(records):
        if rec.record_type == "CAA":
            issuer = caa_issuer_domain(rec.value)
            if issuer:
                records.append(
                    ParsedRecord(
                        record_type="CAA_ISSUER",
                        name=rec.name,
                        value=issuer,
                        ttl=rec.ttl,
                        source="caa-parse",
                    )
                )

    # _dmarc.<domain> TXT
    try:
        dmarc_recs = resolver.query(f"_dmarc.{domain}", "TXT")
    except (NXDOMAIN, ResolverTimeout):
        dmarc_recs = []
    for rec in dmarc_recs:
        records.append(rec)
        if rec.value.lower().startswith("v=dmarc1"):
            tags = parse_dmarc(rec.value)
            for mailbox in parse_dmarc_rua(tags.get("rua", "")):
                md = mailbox_domain(mailbox)
                if md:
                    records.append(
                        ParsedRecord(
                            record_type="DMARC_RUA",
                            name=rec.name,
                            value=md,
                            ttl=rec.ttl,
                            source="dmarc-rua",
                        )
                    )

    # _amazonses.<domain> TXT — presence => AWS SES verified domain
    try:
        ses = resolver.query(f"_amazonses.{domain}", "TXT")
    except (NXDOMAIN, ResolverTimeout):
        ses = []
    if ses:
        records.append(
            ParsedRecord(
                record_type="AWSSES_VERIFY",
                name=f"_amazonses.{domain}",
                value="present",
                ttl=ses[0].ttl,
                source="awsses-probe",
            )
        )

    # Probed DKIM selectors
    selectors = getattr(resolver, "dkim_selectors", DEFAULT_DKIM_SELECTORS)
    for selector in selectors:
        sname = f"{selector}._domainkey.{domain}"
        try:
            recs = resolver.query(sname, "TXT")
        except (NXDOMAIN, ResolverTimeout):
            continue
        if recs:
            records.append(
                ParsedRecord(
                    record_type="DKIM_SELECTOR",
                    name=sname,
                    value=selector,
                    ttl=recs[0].ttl,
                    source="dkim-probe",
                )
            )

    # CNAME probes on common SaaS subdomains.
    probes = (
        tuple(cname_probes)
        if cname_probes is not None
        else getattr(resolver, "cname_probes", DEFAULT_CNAME_PROBES)
    )
    for label in probes:
        pname = f"{label}.{domain}"
        try:
            cnames = resolver.query(pname, "CNAME")
        except (NXDOMAIN, ResolverTimeout):
            # Most probe labels simply don't exist, and a CNAME aimed at a
            # decommissioned target also surfaces as NXDOMAIN. Neither says
            # anything about the apex, so this must never abort the scan —
            # otherwise one stale `shop.` record makes a live domain look
            # nonexistent.
            continue
        for rec in cnames:
            records.append(
                ParsedRecord(
                    record_type="CNAME",
                    name=rec.name,
                    value=rec.value,
                    ttl=rec.ttl,
                    source="cname-probe",
                )
            )

    return records, flags, None


def scan_domain(
    conn: sqlite3.Connection,
    resolver: Resolver,
    catalog: VendorCatalog,
    domain_input: str,
    *,
    cname_probes: Iterable[str] | None = None,
) -> int:
    """End-to-end scan of one domain.

    Wraps record collection, matching, and persistence in a single SQLite
    transaction.

    Args:
        conn: Open SQLite connection. The function manages its own
            transaction.
        resolver: A :class:`Resolver` implementation (real or fake).
        catalog: A seeded :class:`VendorCatalog`. The DB must already have
            its vendors and rules — rules are looked up by
            ``(vendor_id, record_type, match_kind, pattern)``.
        domain_input: Raw domain / URL / email. Normalized to a
            registrable domain before resolution.
        cname_probes: Forwarded to :func:`collect_records`. Pass ``()`` to
            skip CNAME probing.

    Returns:
        The ``scan.id`` of the newly inserted scan row.
    """
    domain_normalized = to_registrable_domain(domain_input)
    started = time.monotonic()
    now = _now_iso()

    vendor_ids = {row["slug"]: row["id"] for row in repo.list_vendors(conn)}
    if not vendor_ids:
        # Detections are matched against the in-memory YAML catalog but
        # persisted by DB row id. With an unseeded database every one of
        # them maps to nothing and gets dropped, so the scan "succeeds"
        # while reporting zero vendors. Refuse instead of losing the data.
        raise UnseededCatalogError(
            "the database has no vendor catalog, so every detection would "
            "be discarded. Run `b2b-intel init` (or call seed_catalog) "
            "before scanning."
        )

    records, flags, error = collect_records(
        resolver, domain_normalized, cname_probes=cname_probes
    )
    elapsed = time.monotonic() - started

    rule_id_map: dict[tuple[int, str, str, str], int] = {}
    for row in repo.list_rules(conn, enabled_only=True):
        key = (
            row["vendor_id"],
            row["record_type"],
            row["match_kind"],
            row["pattern"],
        )
        rule_id_map[key] = row["id"]

    detections = match(records, catalog.rules_by_record_type())

    with conn:
        scan_id = repo.insert_scan(
            conn,
            domain=domain_input,
            domain_normalized=domain_normalized,
            scanned_at=now,
            resolver_used=getattr(resolver, "last_used", None),
            dns_seconds=elapsed,
            flags=flags,
            error=error,
        )

        record_db_ids: dict[int, int] = {}
        for rec in records:
            rid = repo.insert_dns_record(
                conn,
                scan_id=scan_id,
                record_type=rec.record_type,
                name=rec.name,
                value=rec.value,
                ttl=rec.ttl,
                source=rec.source,
            )
            record_db_ids[id(rec)] = rid

        # Group detections by rule key so multiple matching records collapse
        # into one detection with multi-record evidence.
        grouped: dict[tuple[str, str, str, str], list[Detection]] = (
            defaultdict(list)
        )
        for det in detections:
            grouped[
                (
                    det.rule.vendor_slug,
                    det.rule.record_type,
                    det.rule.match_kind,
                    det.rule.pattern,
                )
            ].append(det)

        for key, group in grouped.items():
            vendor_slug, record_type, match_kind, pattern = key
            vendor_id = vendor_ids.get(vendor_slug)
            if vendor_id is None:
                continue
            rule_id = rule_id_map.get(
                (vendor_id, record_type, match_kind, pattern)
            )
            if rule_id is None:
                continue

            det_id = repo.insert_detection(
                conn,
                scan_id=scan_id,
                vendor_id=vendor_id,
                rule_id=rule_id,
                confidence=group[0].confidence.value,
            )
            for det in group:
                rec_db_id = record_db_ids.get(id(det.record))
                if rec_db_id is not None:
                    repo.insert_detection_evidence(
                        conn,
                        detection_id=det_id,
                        dns_record_id=rec_db_id,
                    )

            repo.upsert_observation(
                conn,
                domain_normalized=domain_normalized,
                vendor_id=vendor_id,
                seen_at=now,
            )
            repo.upsert_rule_observation(
                conn,
                domain_normalized=domain_normalized,
                vendor_id=vendor_id,
                rule_id=rule_id,
                seen_at=now,
            )

    return scan_id
