"""Rich-formatted per-domain report.

Renders the payload built by :mod:`site_b2b_intel.reports.serialize` rather
than querying the DB itself, so the table, the JSON and the CSV are always
describing the same data and the query logic exists in one place.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from rich.console import Console
from rich.table import Table

from site_b2b_intel.reports.serialize import domain_payload


def _short(ts: str | None) -> str:
    """Trim an ISO timestamp to minute precision for display.

    Full microsecond timestamps are what the DB stores and what JSON
    emits, but in a terminal table they just force ellipsis truncation.
    """
    if not ts:
        return "—"
    return ts[:16].replace("T", " ")


def render_payload(
    payload: dict[str, Any], *, console: Console | None = None
) -> None:
    """Print a serialized payload as a Rich table.

    Args:
        payload: Output of :func:`serialize.domain_payload` or
            :func:`serialize.scan_payload`.
        console: Optional Rich console; one is created if omitted.
    """
    console = console or Console()
    domain = payload["domain"]
    scan = payload.get("scan")

    if scan is None:
        console.print(
            f"[yellow]No scans found for {domain}.[/yellow] "
            f"Run [bold]b2b-intel scan {domain}[/bold] first."
        )
        return

    header = f"\n[bold]{domain}[/bold] — latest scan {_short(scan['scanned_at'])}"
    if scan.get("resolver_used") and scan.get("dns_seconds") is not None:
        header += (
            f"  ([cyan]{scan['resolver_used']}[/cyan], "
            f"{scan['dns_seconds']:.2f}s)"
        )
    console.print(header)

    if scan.get("flags"):
        console.print(f"  [dim]flags: {', '.join(scan['flags'])}[/dim]")

    if scan.get("error"):
        console.print(f"  [red]error: {scan['error']}[/red]\n")
        return

    vendors = payload.get("vendors", [])
    if not vendors:
        console.print("\n[yellow]No vendors detected in this scan.[/yellow]\n")
        return

    table = Table(
        title=f"Detected vendors ({len(vendors)})", show_lines=True
    )
    table.add_column("Vendor", style="bold")
    table.add_column("Category")
    table.add_column("Conf")
    table.add_column("First seen")
    table.add_column("Last seen")
    table.add_column("Signals", overflow="fold")

    for v in vendors:
        signals = "\n".join(
            f"{s['record_type']} {s['match_kind']}={s['pattern']}"
            for s in v["signals"]
        )
        table.add_row(
            v["name"],
            v["category"],
            v["confidence"],
            _short(v["first_seen"]),
            _short(v["last_seen"]),
            signals,
        )

    console.print(table)
    console.print()


def render_domain_report(
    conn: sqlite3.Connection,
    domain_normalized: str,
    *,
    console: Console | None = None,
) -> None:
    """Fetch and print the most recent scan for a domain.

    Args:
        conn: Open DB connection.
        domain_normalized: Registrable domain; the caller normalizes.
        console: Optional Rich console.
    """
    render_payload(
        domain_payload(conn, domain_normalized), console=console
    )
