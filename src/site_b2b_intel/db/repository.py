"""Pure CRUD against the SQLite schema.

Every function takes a connection and performs a single logical write or
read. No transaction management here — callers wrap a batch of calls in
``with conn:`` when they want atomicity.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable


# ---------- Vendors ----------


def upsert_vendor(
    conn: sqlite3.Connection,
    *,
    slug: str,
    name: str,
    category: str,
) -> int:
    """Insert or update a vendor by slug. Returns the vendor row id."""
    conn.execute(
        """
        INSERT INTO vendor (slug, name, category)
        VALUES (?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            name = excluded.name,
            category = excluded.category
        """,
        (slug, name, category),
    )
    row = conn.execute(
        "SELECT id FROM vendor WHERE slug = ?", (slug,)
    ).fetchone()
    return int(row["id"])


def get_vendor_by_slug(
    conn: sqlite3.Connection, slug: str
) -> sqlite3.Row | None:
    """Look up a vendor by slug, or None."""
    return conn.execute(
        "SELECT * FROM vendor WHERE slug = ?", (slug,)
    ).fetchone()


def list_vendors(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """All vendors, ordered by display name."""
    return conn.execute("SELECT * FROM vendor ORDER BY name").fetchall()


# ---------- Vendor profiles (versioned contact info) ----------


def latest_profile(
    conn: sqlite3.Connection, vendor_id: int
) -> sqlite3.Row | None:
    """The most recently effective profile for a vendor, or None."""
    return conn.execute(
        """
        SELECT * FROM vendor_profile
        WHERE vendor_id = ?
        ORDER BY valid_from DESC
        LIMIT 1
        """,
        (vendor_id,),
    ).fetchone()


def insert_profile(
    conn: sqlite3.Connection,
    *,
    vendor_id: int,
    valid_from: str,
    website: str | None = None,
    support_email: str | None = None,
    sales_email: str | None = None,
    phone: str | None = None,
    headquarters: str | None = None,
    source: str | None = None,
) -> None:
    """Append a new profile row.

    No-op if a profile with the same ``valid_from`` already exists for this
    vendor (reseed idempotency).
    """
    conn.execute(
        """
        INSERT INTO vendor_profile
            (vendor_id, valid_from, website, support_email, sales_email,
             phone, headquarters, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vendor_id, valid_from) DO NOTHING
        """,
        (
            vendor_id,
            valid_from,
            website,
            support_email,
            sales_email,
            phone,
            headquarters,
            source,
        ),
    )


# ---------- Fingerprint rules ----------


def upsert_rule(
    conn: sqlite3.Connection,
    *,
    vendor_id: int,
    record_type: str,
    match_kind: str,
    pattern: str,
    confidence: str,
) -> int:
    """Upsert a rule by (vendor, record_type, match_kind, pattern).

    Re-enables a previously soft-deleted rule with the same key. Returns the
    rule row id.
    """
    conn.execute(
        """
        INSERT INTO fingerprint_rule
            (vendor_id, record_type, match_kind, pattern, confidence, enabled)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(vendor_id, record_type, match_kind, pattern) DO UPDATE SET
            confidence = excluded.confidence,
            enabled = 1
        """,
        (vendor_id, record_type, match_kind, pattern, confidence),
    )
    row = conn.execute(
        """
        SELECT id FROM fingerprint_rule
        WHERE vendor_id = ?
          AND record_type = ?
          AND match_kind = ?
          AND pattern = ?
        """,
        (vendor_id, record_type, match_kind, pattern),
    ).fetchone()
    return int(row["id"])


def soft_delete_rules_not_in(
    conn: sqlite3.Connection, keep_ids: Iterable[int]
) -> int:
    """Set ``enabled=0`` on every active rule whose id isn't in ``keep_ids``.

    Used by reseed to retire rules that were removed from YAML. Historical
    detections still reference the rule by id so they remain reportable.

    Returns the count of rows affected.
    """
    keep = list(keep_ids)
    if not keep:
        cur = conn.execute(
            "UPDATE fingerprint_rule SET enabled = 0 WHERE enabled = 1"
        )
    else:
        placeholders = ",".join("?" * len(keep))
        cur = conn.execute(
            f"UPDATE fingerprint_rule SET enabled = 0 "
            f"WHERE enabled = 1 AND id NOT IN ({placeholders})",
            keep,
        )
    return cur.rowcount


def list_rules(
    conn: sqlite3.Connection, *, enabled_only: bool = True
) -> list[sqlite3.Row]:
    """List rules joined to their vendor."""
    sql = """
        SELECT r.*, v.slug AS vendor_slug, v.name AS vendor_name
        FROM fingerprint_rule r
        JOIN vendor v ON v.id = r.vendor_id
    """
    if enabled_only:
        sql += " WHERE r.enabled = 1"
    sql += " ORDER BY v.slug, r.record_type, r.pattern"
    return conn.execute(sql).fetchall()


# ---------- Scans, records, detections ----------


def insert_scan(
    conn: sqlite3.Connection,
    *,
    domain: str,
    domain_normalized: str,
    scanned_at: str,
    resolver_used: str | None = None,
    dns_seconds: float | None = None,
    flags: int = 0,
    error: str | None = None,
) -> int:
    """Insert a scan row, returning the row id."""
    cur = conn.execute(
        """
        INSERT INTO scan
            (domain, domain_normalized, scanned_at, resolver_used,
             dns_seconds, flags, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            domain,
            domain_normalized,
            scanned_at,
            resolver_used,
            dns_seconds,
            flags,
            error,
        ),
    )
    return int(cur.lastrowid or 0)


def insert_dns_record(
    conn: sqlite3.Connection,
    *,
    scan_id: int,
    record_type: str,
    name: str,
    value: str,
    ttl: int | None = None,
    source: str = "direct",
    parent_record_id: int | None = None,
) -> int:
    """Insert a single normalized DNS record observation. Returns row id."""
    cur = conn.execute(
        """
        INSERT INTO dns_record
            (scan_id, record_type, name, value, ttl, source, parent_record_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            record_type,
            name,
            value,
            ttl,
            source,
            parent_record_id,
        ),
    )
    return int(cur.lastrowid or 0)


def insert_detection(
    conn: sqlite3.Connection,
    *,
    scan_id: int,
    vendor_id: int,
    rule_id: int,
    confidence: str,
) -> int:
    """Insert a detection row, returning the row id.

    Idempotent on ``(scan_id, vendor_id, rule_id)``; if a duplicate exists,
    returns the existing id.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO detection
            (scan_id, vendor_id, rule_id, confidence)
        VALUES (?, ?, ?, ?)
        """,
        (scan_id, vendor_id, rule_id, confidence),
    )
    row = conn.execute(
        """
        SELECT id FROM detection
        WHERE scan_id = ? AND vendor_id = ? AND rule_id = ?
        """,
        (scan_id, vendor_id, rule_id),
    ).fetchone()
    return int(row["id"])


def insert_detection_evidence(
    conn: sqlite3.Connection, *, detection_id: int, dns_record_id: int
) -> None:
    """Link a dns_record as evidence for a detection. Idempotent."""
    conn.execute(
        """
        INSERT OR IGNORE INTO detection_evidence
            (detection_id, dns_record_id)
        VALUES (?, ?)
        """,
        (detection_id, dns_record_id),
    )


# ---------- Aggregations ----------


def upsert_observation(
    conn: sqlite3.Connection,
    *,
    domain_normalized: str,
    vendor_id: int,
    seen_at: str,
) -> None:
    """Maintain the (domain, vendor) first_seen/last_seen aggregate.

    On insert: stores ``seen_at`` for both bounds and count=1.
    On conflict: ``first_seen`` is moved earlier if needed, ``last_seen``
    later, count incremented.
    """
    conn.execute(
        """
        INSERT INTO domain_vendor_observation
            (domain_normalized, vendor_id, first_seen, last_seen, detection_count)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(domain_normalized, vendor_id) DO UPDATE SET
            first_seen = MIN(first_seen, excluded.first_seen),
            last_seen = MAX(last_seen, excluded.last_seen),
            detection_count = detection_count + 1
        """,
        (domain_normalized, vendor_id, seen_at, seen_at),
    )


def upsert_rule_observation(
    conn: sqlite3.Connection,
    *,
    domain_normalized: str,
    vendor_id: int,
    rule_id: int,
    seen_at: str,
) -> None:
    """Same as :func:`upsert_observation` but keyed on the specific rule."""
    conn.execute(
        """
        INSERT INTO domain_vendor_rule_observation
            (domain_normalized, vendor_id, rule_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(domain_normalized, vendor_id, rule_id) DO UPDATE SET
            first_seen = MIN(first_seen, excluded.first_seen),
            last_seen = MAX(last_seen, excluded.last_seen)
        """,
        (domain_normalized, vendor_id, rule_id, seen_at, seen_at),
    )


# ---------- Read paths for reports ----------


def latest_scan_for(
    conn: sqlite3.Connection, domain_normalized: str
) -> sqlite3.Row | None:
    """The most recent scan row for a domain, or None."""
    return conn.execute(
        """
        SELECT * FROM scan
        WHERE domain_normalized = ?
        ORDER BY scanned_at DESC
        LIMIT 1
        """,
        (domain_normalized,),
    ).fetchone()


def get_scan(conn: sqlite3.Connection, scan_id: int) -> sqlite3.Row | None:
    """Fetch one scan row by id."""
    return conn.execute(
        "SELECT * FROM scan WHERE id = ?", (scan_id,)
    ).fetchone()


def detections_for_scan_raw(
    conn: sqlite3.Connection, scan_id: int
) -> list[sqlite3.Row]:
    """Detections for a scan, one row each, joined to vendor and rule.

    Unlike :func:`detections_for_scan` this does not collapse evidence with
    GROUP_CONCAT, so structured output can nest evidence properly instead
    of re-splitting a delimited string.
    """
    return conn.execute(
        """
        SELECT
            d.id AS detection_id,
            d.confidence,
            v.slug AS vendor_slug,
            v.name AS vendor_name,
            v.category AS vendor_category,
            r.record_type,
            r.match_kind,
            r.pattern
        FROM detection d
        JOIN vendor v ON v.id = d.vendor_id
        JOIN fingerprint_rule r ON r.id = d.rule_id
        WHERE d.scan_id = ?
        ORDER BY v.name, r.record_type, r.pattern
        """,
        (scan_id,),
    ).fetchall()


def detection_evidence_for_scan(
    conn: sqlite3.Connection, scan_id: int
) -> list[sqlite3.Row]:
    """Every evidence record for a scan's detections, one row per record."""
    return conn.execute(
        """
        SELECT
            de.detection_id,
            rec.record_type,
            rec.name,
            rec.value
        FROM detection_evidence de
        JOIN detection d ON d.id = de.detection_id
        JOIN dns_record rec ON rec.id = de.dns_record_id
        WHERE d.scan_id = ?
        ORDER BY de.detection_id, rec.name, rec.value
        """,
        (scan_id,),
    ).fetchall()


def detections_for_scan(
    conn: sqlite3.Connection, scan_id: int
) -> list[sqlite3.Row]:
    """All detections for a scan, joined to vendor + rule + evidence."""
    return conn.execute(
        """
        SELECT
            d.id AS detection_id,
            d.confidence,
            v.slug AS vendor_slug,
            v.name AS vendor_name,
            v.category AS vendor_category,
            r.record_type,
            r.match_kind,
            r.pattern,
            GROUP_CONCAT(rec.value, ' | ') AS evidence_values,
            GROUP_CONCAT(rec.name, ' | ') AS evidence_names
        FROM detection d
        JOIN vendor v ON v.id = d.vendor_id
        JOIN fingerprint_rule r ON r.id = d.rule_id
        LEFT JOIN detection_evidence de ON de.detection_id = d.id
        LEFT JOIN dns_record rec ON rec.id = de.dns_record_id
        WHERE d.scan_id = ?
        GROUP BY d.id
        ORDER BY v.name, r.record_type
        """,
        (scan_id,),
    ).fetchall()


def observations_for_domain(
    conn: sqlite3.Connection, domain_normalized: str
) -> list[sqlite3.Row]:
    """All (vendor, first_seen, last_seen) tuples for a domain."""
    return conn.execute(
        """
        SELECT
            o.first_seen,
            o.last_seen,
            o.detection_count,
            v.slug AS vendor_slug,
            v.name AS vendor_name,
            v.category AS vendor_category
        FROM domain_vendor_observation o
        JOIN vendor v ON v.id = o.vendor_id
        WHERE o.domain_normalized = ?
        ORDER BY o.first_seen
        """,
        (domain_normalized,),
    ).fetchall()


def dns_records_for_scan(
    conn: sqlite3.Connection, scan_id: int
) -> list[sqlite3.Row]:
    """All raw DNS records persisted for a scan."""
    return conn.execute(
        """
        SELECT * FROM dns_record
        WHERE scan_id = ?
        ORDER BY record_type, name, value
        """,
        (scan_id,),
    ).fetchall()
