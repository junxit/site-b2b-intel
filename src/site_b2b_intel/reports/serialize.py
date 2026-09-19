"""Structured serialization of scan results.

Builds a plain-dict payload that the Rich renderer, the JSON writer and the
CSV writer all consume. Keeping one builder means the three output formats
cannot drift apart, and query logic is written once rather than per format.

The JSON payload carries ``schema_version``; bump :data:`SCHEMA_VERSION`
whenever the shape changes incompatibly so downstream consumers can refuse
input they don't understand.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from typing import Any, TextIO

from site_b2b_intel import __version__
from site_b2b_intel.db import repository as repo
from site_b2b_intel.types import Confidence, ScanFlag

#: Incremented on incompatible changes to the payload shape.
SCHEMA_VERSION = 1

#: Column order for CSV output. One row per *signal*, not per vendor — a
#: flat shape is what makes `scan -f domains.txt --format csv` directly
#: loadable into a spreadsheet or dataframe.
CSV_COLUMNS: tuple[str, ...] = (
    "domain",
    "scanned_at",
    "vendor_slug",
    "vendor_name",
    "category",
    "confidence",
    "record_type",
    "match_kind",
    "pattern",
    "evidence",
    "first_seen",
    "last_seen",
)


def _empty_payload(domain: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "site-b2b-intel", "version": __version__},
        "domain": domain,
        "input": domain,
        "scan": None,
        "vendors": [],
    }


def _build(
    conn: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    include_records: bool,
) -> dict[str, Any]:
    scan_id = scan["id"]
    domain = scan["domain_normalized"]

    detections = repo.detections_for_scan_raw(conn, scan_id)
    observations = {
        o["vendor_slug"]: o
        for o in repo.observations_for_domain(conn, domain)
    }

    evidence_by_detection: dict[int, list[dict[str, Any]]] = {}
    for row in repo.detection_evidence_for_scan(conn, scan_id):
        evidence_by_detection.setdefault(row["detection_id"], []).append(
            {
                "record_type": row["record_type"],
                "name": row["name"],
                "value": row["value"],
            }
        )

    vendors: dict[str, dict[str, Any]] = {}
    for d in detections:
        slug = d["vendor_slug"]
        entry = vendors.get(slug)
        if entry is None:
            obs = observations.get(slug)
            entry = {
                "slug": slug,
                "name": d["vendor_name"],
                "category": d["vendor_category"],
                "confidence": d["confidence"],
                "first_seen": obs["first_seen"] if obs else None,
                "last_seen": obs["last_seen"] if obs else None,
                "detection_count": obs["detection_count"] if obs else 0,
                "signals": [],
            }
            vendors[slug] = entry
        elif (
            Confidence(d["confidence"]).rank
            > Confidence(entry["confidence"]).rank
        ):
            # Headline confidence is the strongest signal for this vendor,
            # not whichever happened to be read first.
            entry["confidence"] = d["confidence"]

        entry["signals"].append(
            {
                "record_type": d["record_type"],
                "match_kind": d["match_kind"],
                "pattern": d["pattern"],
                "confidence": d["confidence"],
                "evidence": evidence_by_detection.get(d["detection_id"], []),
            }
        )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "site-b2b-intel", "version": __version__},
        "domain": domain,
        "input": scan["domain"],
        "scan": {
            "id": scan_id,
            "scanned_at": scan["scanned_at"],
            "resolver_used": scan["resolver_used"],
            "dns_seconds": scan["dns_seconds"],
            # Names, not the raw bitfield — the packing is an internal
            # storage detail no consumer should have to decode.
            "flags": ScanFlag.names(scan["flags"]),
            "error": scan["error"],
        },
        "vendors": sorted(vendors.values(), key=lambda v: v["name"].lower()),
    }

    if include_records:
        payload["records"] = [
            {
                "record_type": r["record_type"],
                "name": r["name"],
                "value": r["value"],
                "ttl": r["ttl"],
                "source": r["source"],
            }
            for r in repo.dns_records_for_scan(conn, scan_id)
        ]

    return payload


def scan_payload(
    conn: sqlite3.Connection,
    scan_id: int,
    *,
    include_records: bool = False,
) -> dict[str, Any]:
    """Build the payload for one specific scan.

    Args:
        conn: Open DB connection.
        scan_id: The scan to serialize.
        include_records: Also emit every raw DNS record observed. Off by
            default — it roughly triples payload size and is only useful
            when auditing why a detection fired.

    Returns:
        A JSON-serializable dict.

    Raises:
        KeyError: No scan with that id.
    """
    scan = repo.get_scan(conn, scan_id)
    if scan is None:
        raise KeyError(f"no scan with id {scan_id}")
    return _build(conn, scan, include_records=include_records)


def domain_payload(
    conn: sqlite3.Connection,
    domain_normalized: str,
    *,
    include_records: bool = False,
) -> dict[str, Any]:
    """Build the payload for a domain's most recent scan.

    Returns a payload with ``scan: null`` and no vendors if the domain has
    never been scanned, rather than raising — callers render that as an
    empty result.
    """
    scan = repo.latest_scan_for(conn, domain_normalized)
    if scan is None:
        return _empty_payload(domain_normalized)
    return _build(conn, scan, include_records=include_records)


def payload_to_json(payload: dict[str, Any], *, indent: int | None = 2) -> str:
    """Render a payload as JSON text."""
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def payload_to_csv_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a payload to one row per detection signal.

    Deliberately a different shape from the JSON: CSV consumers want a
    rectangle, so the vendor fields repeat across that vendor's signals
    rather than nesting.
    """
    rows: list[dict[str, Any]] = []
    domain = payload.get("domain")
    scan = payload.get("scan") or {}
    scanned_at = scan.get("scanned_at")

    for v in payload.get("vendors", []):
        for s in v["signals"]:
            rows.append(
                {
                    "domain": domain,
                    "scanned_at": scanned_at,
                    "vendor_slug": v["slug"],
                    "vendor_name": v["name"],
                    "category": v["category"],
                    "confidence": s["confidence"],
                    "record_type": s["record_type"],
                    "match_kind": s["match_kind"],
                    "pattern": s["pattern"],
                    "evidence": ";".join(
                        e["value"] for e in s["evidence"]
                    ),
                    "first_seen": v["first_seen"],
                    "last_seen": v["last_seen"],
                }
            )
    return rows


def write_csv(
    rows: list[dict[str, Any]], fh: TextIO, *, header: bool = True
) -> None:
    """Write flattened rows as CSV.

    Args:
        rows: Output of :func:`payload_to_csv_rows`.
        fh: Destination text stream.
        header: Emit the header row. Set False for all but the first
            domain when streaming a batch scan into one CSV.
    """
    writer = csv.DictWriter(
        fh, fieldnames=list(CSV_COLUMNS), extrasaction="ignore"
    )
    if header:
        writer.writeheader()
    writer.writerows(rows)
