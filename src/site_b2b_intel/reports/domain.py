"""Rich-formatted per-domain report.

Reads the latest scan + observation aggregates and prints a table grouped
by vendor, with first_seen / last_seen across all scans of the domain.
"""

from __future__ import annotations

import sqlite3

from rich.console import Console
from rich.table import Table

from site_b2b_intel.db import repository as repo


def render_domain_report(
    conn: sqlite3.Connection,
    domain_normalized: str,
    *,
    console: Console | None = None,
) -> None:
    """Print the report for one domain.

    Args:
        conn: Open DB connection.
        domain_normalized: Registrable domain. The caller is responsible
            for normalization.
        console: Optional Rich console; one is created if omitted.
    """
    console = console or Console()

    scan = repo.latest_scan_for(conn, domain_normalized)
    if scan is None:
        console.print(
            f"[yellow]No scans found for {domain_normalized}.[/yellow] "
            f"Run [bold]b2b-intel scan {domain_normalized}[/bold] first."
        )
        return

    header = (
        f"\n[bold]{domain_normalized}[/bold] — "
        f"latest scan {scan['scanned_at']}"
    )
    if scan["resolver_used"] and scan["dns_seconds"] is not None:
        header += (
            f"  ([cyan]{scan['resolver_used']}[/cyan], "
            f"{scan['dns_seconds']:.2f}s)"
        )
    console.print(header)

    if scan["error"]:
        console.print(f"  [red]error: {scan['error']}[/red]\n")
        return

    detections = repo.detections_for_scan(conn, scan["id"])
    observations = {
        o["vendor_slug"]: o
        for o in repo.observations_for_domain(conn, domain_normalized)
    }

    if not detections:
        console.print("\n[yellow]No vendors detected in this scan.[/yellow]\n")
        return

    by_vendor: dict[str, list[sqlite3.Row]] = {}
    for d in detections:
        by_vendor.setdefault(d["vendor_slug"], []).append(d)

    table = Table(
        title=f"Detected vendors ({len(by_vendor)})",
        show_lines=True,
    )
    table.add_column("Vendor", style="bold")
    table.add_column("Category")
    table.add_column("First seen")
    table.add_column("Last seen")
    table.add_column("Signals", overflow="fold")

    sorted_slugs = sorted(
        by_vendor.keys(), key=lambda s: by_vendor[s][0]["vendor_name"]
    )
    for slug in sorted_slugs:
        dets = by_vendor[slug]
        first = dets[0]
        obs = observations.get(slug)
        signals = "\n".join(
            f"{d['record_type']} {d['match_kind']}={d['pattern']}"
            for d in dets
        )
        table.add_row(
            first["vendor_name"],
            first["vendor_category"],
            obs["first_seen"] if obs else "—",
            obs["last_seen"] if obs else "—",
            signals,
        )

    console.print(table)
    console.print()
