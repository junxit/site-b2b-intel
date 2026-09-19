"""``b2b-intel`` command-line interface.

Thin wrapper over the library — every command opens a DB, loads the
catalog, and delegates to a function elsewhere. Keep business logic out.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from site_b2b_intel import __version__
from site_b2b_intel.config import get_settings
from site_b2b_intel.db import repository as repo
from site_b2b_intel.db.connection import open_db
from site_b2b_intel.fingerprints.catalog import load_catalog, seed_catalog
from site_b2b_intel.normalize import to_registrable_domain
from site_b2b_intel.reports.domain import render_payload
from site_b2b_intel.reports.serialize import (
    SCHEMA_VERSION,
    domain_payload,
    payload_to_csv_rows,
    payload_to_json,
    scan_payload,
    write_csv,
)
from site_b2b_intel.resolve.resolver import DnsResolver
from site_b2b_intel.scan.scanner import scan_domain

app = typer.Typer(
    help="DNS-based B2B vendor intelligence.",
    no_args_is_help=True,
)
vendors_app = typer.Typer(help="Inspect the vendor catalog.")
rules_app = typer.Typer(help="Inspect fingerprint rules.")
app.add_typer(vendors_app, name="vendors")
app.add_typer(rules_app, name="rules")

console = Console()
#: Progress and errors go here whenever stdout is carrying machine-readable
#: output, so `b2b-intel scan x.com --format json | jq` is never polluted.
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    """How to render results on stdout."""

    table = "table"
    json = "json"
    csv = "csv"


def _make_resolver() -> DnsResolver:
    s = get_settings()
    return DnsResolver(
        upstreams=s.resolvers, timeout=s.dns_timeout, qps=s.rate_limit_qps
    )


@app.command()
def init() -> None:
    """Create the DB at the configured path and seed vendors + rules."""
    settings = get_settings()
    catalog = load_catalog()
    with open_db(settings.db_path) as conn:
        seed_catalog(conn, catalog)
        n_vendors = len(repo.list_vendors(conn))
        n_rules = len(repo.list_rules(conn, enabled_only=True))
    console.print(
        f"[green]✓[/green] DB ready at [bold]{settings.db_path}[/bold]\n"
        f"  {n_vendors} vendors, {n_rules} active rules"
    )


@app.command()
def scan(
    domain: Annotated[
        str, typer.Argument(help="Domain, URL, or email (single scan)")
    ] = "",
    file: Annotated[
        Path | None,
        typer.Option(
            "--file", "-f", help="Batch scan: one domain per line"
        ),
    ] = None,
    no_probe: Annotated[
        bool,
        typer.Option(
            "--no-probe",
            help=(
                "Skip CNAME subdomain probing. Saves ~15 DNS queries per "
                "domain (roughly halves scan time) at the cost of CNAME-"
                "based detections. Worth it when batch-scanning at volume."
            ),
        ),
    ] = False,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-o",
            help="table for humans; json or csv for pipelines",
        ),
    ] = OutputFormat.table,
    include_records: Annotated[
        bool,
        typer.Option(
            "--include-records",
            help=(
                "Include every raw DNS record in JSON output. Roughly "
                "triples payload size; useful when auditing why a "
                "detection fired."
            ),
        ),
    ] = False,
) -> None:
    """Scan one domain (or a file of domains)."""
    targets = _resolve_targets(domain, file)
    settings = get_settings()
    catalog = load_catalog()
    resolver = _make_resolver()
    probes: tuple[str, ...] | None = () if no_probe else None
    # Keep stdout clean for anything machine-readable.
    status = console if output_format is OutputFormat.table else err_console

    payloads: list[dict[str, Any]] = []
    with open_db(settings.db_path) as conn:
        for tgt in targets:
            try:
                scan_id = scan_domain(
                    conn, resolver, catalog, tgt, cname_probes=probes
                )
            except Exception as exc:  # noqa: BLE001
                status.print(f"[red]✗[/red] {tgt}: {exc}")
                continue
            payload = scan_payload(
                conn, scan_id, include_records=include_records
            )
            payloads.append(payload)
            status.print(
                f"[green]✓[/green] {tgt} → {len(payload['vendors'])} "
                f"vendors (scan #{scan_id})"
            )

    if output_format is OutputFormat.table:
        for payload in payloads:
            render_payload(payload, console=console)
    elif output_format is OutputFormat.json:
        # Always the same envelope, single domain or batch, so consumers
        # never have to branch on cardinality.
        sys.stdout.write(
            payload_to_json(
                {
                    "schema_version": SCHEMA_VERSION,
                    "tool": {
                        "name": "site-b2b-intel",
                        "version": __version__,
                    },
                    "results": payloads,
                }
            )
            + "\n"
        )
    else:
        rows = [r for p in payloads for r in payload_to_csv_rows(p)]
        write_csv(rows, sys.stdout)


def _resolve_targets(domain: str, file: Path | None) -> list[str]:
    if file is not None:
        if not file.exists():
            console.print(f"[red]File not found:[/red] {file}")
            raise typer.Exit(2)
        return [
            line.strip()
            for line in file.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if domain:
        return [domain]
    console.print("[red]Provide a domain or --file[/red]")
    raise typer.Exit(2)


@app.command()
def report(
    domain: Annotated[
        str, typer.Argument(help="Domain (URL/email also accepted)")
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-o",
            help="table for humans; json or csv for pipelines",
        ),
    ] = OutputFormat.table,
    include_records: Annotated[
        bool,
        typer.Option(
            "--include-records",
            help="Include every raw DNS record in JSON output",
        ),
    ] = False,
) -> None:
    """Show the most recent scan + first/last-seen for a domain."""
    settings = get_settings()
    normalized = to_registrable_domain(domain)
    with open_db(settings.db_path) as conn:
        payload = domain_payload(
            conn, normalized, include_records=include_records
        )

    if output_format is OutputFormat.table:
        render_payload(payload, console=console)
    elif output_format is OutputFormat.json:
        sys.stdout.write(payload_to_json(payload) + "\n")
    else:
        write_csv(payload_to_csv_rows(payload), sys.stdout)


@app.command()
def reseed() -> None:
    """Re-apply the YAML catalog. Soft-deletes rules removed from YAML."""
    settings = get_settings()
    catalog = load_catalog()
    with open_db(settings.db_path) as conn:
        seed_catalog(conn, catalog)
        active = repo.list_rules(conn, enabled_only=True)
        all_ = repo.list_rules(conn, enabled_only=False)
    console.print(
        f"[green]✓[/green] Reseed complete. "
        f"{len(active)} active, {len(all_) - len(active)} soft-deleted."
    )


@vendors_app.command("list")
def vendors_list() -> None:
    """List all vendors."""
    settings = get_settings()
    with open_db(settings.db_path) as conn:
        vendors = repo.list_vendors(conn)
    table = Table(title=f"Vendors ({len(vendors)})")
    table.add_column("Slug", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    for v in vendors:
        table.add_row(v["slug"], v["name"], v["category"])
    console.print(table)


@vendors_app.command("show")
def vendors_show(slug: str) -> None:
    """Show a single vendor with its profile and rules."""
    settings = get_settings()
    with open_db(settings.db_path) as conn:
        v = repo.get_vendor_by_slug(conn, slug)
        if v is None:
            console.print(f"[red]No vendor with slug {slug!r}[/red]")
            raise typer.Exit(2)
        profile = repo.latest_profile(conn, v["id"])
        rules = [
            r
            for r in repo.list_rules(conn, enabled_only=False)
            if r["vendor_slug"] == slug
        ]

    console.print(f"\n[bold]{v['name']}[/bold] ([cyan]{v['slug']}[/cyan])")
    console.print(f"  Category:  {v['category']}")
    if profile:
        console.print(f"  Website:   {profile['website'] or '—'}")
        console.print(
            f"  Support:   {profile['support_email'] or '—'}"
        )
        console.print(f"  Sales:     {profile['sales_email'] or '—'}")
        console.print(f"  Phone:     {profile['phone'] or '—'}")
        console.print(f"  HQ:        {profile['headquarters'] or '—'}")
        console.print(
            f"  As of:     [dim]{profile['valid_from']}[/dim]"
        )

    if rules:
        t = Table(title=f"Rules ({len(rules)})", show_lines=False)
        t.add_column("Type")
        t.add_column("Kind")
        t.add_column("Pattern", overflow="fold")
        t.add_column("Conf")
        t.add_column("On?")
        for r in rules:
            t.add_row(
                r["record_type"],
                r["match_kind"],
                r["pattern"],
                r["confidence"],
                "[green]✓[/green]" if r["enabled"] else "[dim]✗[/dim]",
            )
        console.print(t)


@rules_app.command("list")
def rules_list(
    show_all: Annotated[
        bool,
        typer.Option(
            "--all/--enabled-only",
            help="Show soft-deleted rules too",
        ),
    ] = False,
) -> None:
    """List fingerprint rules."""
    settings = get_settings()
    with open_db(settings.db_path) as conn:
        rules = repo.list_rules(conn, enabled_only=not show_all)
    table = Table(title=f"Rules ({len(rules)})")
    table.add_column("Vendor", style="cyan")
    table.add_column("Type")
    table.add_column("Kind")
    table.add_column("Pattern", overflow="fold")
    table.add_column("Conf")
    for r in rules:
        table.add_row(
            r["vendor_slug"],
            r["record_type"],
            r["match_kind"],
            r["pattern"],
            r["confidence"],
        )
    console.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()
