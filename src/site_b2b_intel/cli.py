"""``b2b-intel`` command-line interface.

Thin wrapper over the library — every command opens a DB, loads the
catalog, and delegates to a function elsewhere. Keep business logic out.
"""

from __future__ import annotations

import csv
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
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


def _ensure_catalog(
    conn: sqlite3.Connection, catalog: Any, *, status: Console
) -> None:
    """Make sure the database actually has a catalog to match against.

    ``open_db`` creates the database and applies the schema for any
    command, so running ``scan`` before ``init`` yields a structurally
    valid but empty catalog. Detections are matched against the YAML
    in memory and then persisted by DB row id, so an empty database
    silently discards every one of them and the scan reports zero
    vendors while looking like it succeeded.

    An empty vendor table is unambiguous — a seeded database always has
    vendors — so seeding here is safe and cannot clobber deliberate local
    state. A partially stale catalog only warns, since that may well be
    intentional.
    """
    if not repo.list_vendors(conn):
        status.print(
            "[dim]No catalog in the database yet — seeding from YAML.[/dim]"
        )
        seed_catalog(conn, catalog)
        return

    db_rules = len(repo.list_rules(conn, enabled_only=True))
    yaml_rules = len(catalog.rules)
    if db_rules != yaml_rules:
        status.print(
            f"[yellow]⚠[/yellow]  Catalog drift: YAML defines "
            f"{yaml_rules} rules, the database has {db_rules}. Rules "
            f"missing from the database are ignored during matching — "
            f"run [bold]b2b-intel reseed[/bold] to sync."
        )


@contextmanager
def _seeded_db(status: Console | None = None) -> Iterator[sqlite3.Connection]:
    """Open the configured database, seeding the catalog if it's empty.

    Every command except ``init`` and ``reseed`` goes through here, so no
    command can operate against an unseeded catalog and report a
    confidently wrong empty result.
    """
    settings = get_settings()
    with open_db(settings.db_path) as conn:
        _ensure_catalog(conn, load_catalog(), status=status or console)
        yield conn


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
    catalog = load_catalog()
    resolver = _make_resolver()
    probes: tuple[str, ...] | None = () if no_probe else None
    # Keep stdout clean for anything machine-readable.
    status = console if output_format is OutputFormat.table else err_console

    payloads: list[dict[str, Any]] = []
    with _seeded_db(status) as conn:
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
    normalized = to_registrable_domain(domain)
    status = console if output_format is OutputFormat.table else err_console
    with _seeded_db(status) as conn:
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
    with _seeded_db() as conn:
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
    with _seeded_db() as conn:
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


@vendors_app.command("domains")
def vendors_domains(
    slug: Annotated[str, typer.Argument(help="Vendor slug")],
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", help="Cap the number of domains"),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Only domains last seen at or after this ISO timestamp",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-o", help="table, json or csv"),
    ] = OutputFormat.table,
) -> None:
    """List the scanned domains observed using a vendor.

    The inverse of `report`: instead of "what does this company use?",
    answers "who uses this vendor?" — across everything scanned so far.
    """
    status = console if output_format is OutputFormat.table else err_console
    with _seeded_db(status) as conn:
        vendor = repo.get_vendor_by_slug(conn, slug)
        if vendor is None:
            err_console.print(f"[red]No vendor with slug {slug!r}[/red]")
            raise typer.Exit(2)
        rows = repo.domains_for_vendor(
            conn, slug, limit=limit, since=since
        )

    if output_format is OutputFormat.table:
        table = Table(
            title=f"Domains using {vendor['name']} ({len(rows)})"
        )
        table.add_column("Domain", style="bold")
        table.add_column("First seen")
        table.add_column("Last seen")
        table.add_column("Times seen", justify="right")
        for r in rows:
            table.add_row(
                r["domain_normalized"],
                r["first_seen"][:16].replace("T", " "),
                r["last_seen"][:16].replace("T", " "),
                str(r["detection_count"]),
            )
        console.print(table)
        if not rows:
            console.print(
                f"[dim]Nothing scanned yet uses {vendor['name']}.[/dim]"
            )
        return

    records = [
        {
            "domain": r["domain_normalized"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "detection_count": r["detection_count"],
        }
        for r in rows
    ]
    if output_format is OutputFormat.json:
        sys.stdout.write(
            payload_to_json(
                {
                    "schema_version": SCHEMA_VERSION,
                    "tool": {
                        "name": "site-b2b-intel",
                        "version": __version__,
                    },
                    "vendor": {
                        "slug": vendor["slug"],
                        "name": vendor["name"],
                        "category": vendor["category"],
                    },
                    "domains": records,
                }
            )
            + "\n"
        )
    else:
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=[
                "domain",
                "first_seen",
                "last_seen",
                "detection_count",
            ],
        )
        writer.writeheader()
        writer.writerows(records)


@rules_app.command("validate")
def rules_validate() -> None:
    """Check the YAML catalog for problems before they reach the DB.

    Catches the failure modes that are otherwise invisible: a rule that can
    never match, a vendor that can never be detected, or a suffix rule
    loose enough to match an attacker-registered lookalike. Run this before
    opening a rule pull request.
    """
    try:
        catalog = load_catalog()
    except Exception as exc:  # noqa: BLE001
        err_console.print("[red]✗ catalog failed to load[/red]")
        err_console.print(str(exc))
        raise typer.Exit(1) from exc

    problems: list[str] = []

    with_rules = {r.vendor_slug for r in catalog.rules}
    for slug in sorted(catalog.vendor_slugs() - with_rules):
        problems.append(
            f"vendor {slug!r} has no rules, so it can never be detected"
        )

    seen: set[tuple[str, str, str, str]] = set()
    for r in catalog.rules:
        key = (r.vendor_slug, r.record_type, r.match_kind, r.pattern)
        if key in seen:
            problems.append(
                f"duplicate rule {r.vendor_slug}:{r.record_type}:"
                f"{r.pattern!r} (silently deduped on seed)"
            )
        seen.add(key)

    for r in catalog.rules:
        if r.match_kind == "suffix" and not r.pattern.startswith("."):
            problems.append(
                f"suffix rule {r.vendor_slug}:{r.pattern!r} has no leading "
                f"dot, so it also matches lookalikes such as "
                f"'evil{r.pattern}'"
            )

    if problems:
        for p in problems:
            err_console.print(f"  [red]✗[/red] {p}")
        err_console.print(
            f"\n[red]{len(problems)} problem(s) found.[/red]"
        )
        raise typer.Exit(1)

    by_type = catalog.rules_by_record_type()
    console.print(
        f"[green]✓[/green] catalog OK — {len(catalog.vendors)} vendors, "
        f"{len(catalog.rules)} rules across {len(by_type)} record types"
    )
    for rt in sorted(by_type):
        console.print(f"    {rt:<16} {len(by_type[rt]):>3}")


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
    with _seeded_db() as conn:
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
