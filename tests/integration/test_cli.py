"""CLI smoke tests.

Deliberately avoids anything that touches the network — `scan` is covered
by the scanner tests with a fake resolver. These assert the command wiring,
exit codes, and that machine-readable output is actually parseable.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from site_b2b_intel.cli import app
from site_b2b_intel.config import get_settings

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point every CLI invocation at a throwaway DB.

    get_settings is lru_cached, so the cache must be cleared or the first
    test's path leaks into all the others.
    """
    monkeypatch.setenv("B2B_INTEL_DB_PATH", str(tmp_path / "cli.db"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestRulesValidate:
    def test_shipped_catalog_is_valid(self) -> None:
        result = runner.invoke(app, ["rules", "validate"])
        assert result.exit_code == 0, result.output
        assert "catalog OK" in result.output


class TestInitAndVendors:
    def test_init_seeds(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0, result.output
        assert "vendors" in result.output

    def test_vendors_list(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["vendors", "list"])
        assert result.exit_code == 0
        assert "google-workspace" in result.output

    def test_vendors_show_unknown_exits_nonzero(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["vendors", "show", "not-a-vendor"])
        assert result.exit_code == 2

    def test_vendors_domains_unknown_exits_nonzero(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["vendors", "domains", "not-a-vendor"])
        assert result.exit_code == 2

    def test_vendors_domains_empty_is_ok(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["vendors", "domains", "cloudflare"])
        assert result.exit_code == 0


class TestReportFormats:
    """A never-scanned domain still has to produce well-formed output."""

    def test_json_is_parseable(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(
            app, ["report", "never-scanned.com", "--format", "json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == 1
        assert payload["domain"] == "never-scanned.com"
        assert payload["scan"] is None
        assert payload["vendors"] == []

    def test_csv_has_header(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(
            app, ["report", "never-scanned.com", "--format", "csv"]
        )
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.stdout)))
        assert rows[0][0] == "domain"

    def test_table_is_default(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["report", "never-scanned.com"])
        assert result.exit_code == 0
        assert "No scans found" in result.output


class TestCatalogGuard:
    """Regression: `scan` before `init` silently found zero vendors.

    open_db creates the database for any command but only `init` seeds it,
    so a first-time user running `scan` got a structurally valid empty
    catalog, a scan that resolved everything correctly, and "0 vendors"
    with a success marker.
    """

    def test_report_on_unseeded_db_seeds_it(self) -> None:
        # `report` touches the DB without ever calling init.
        result = runner.invoke(app, ["report", "never-scanned.com"])
        assert result.exit_code == 0
        # And the catalog is now present for the next command.
        listing = runner.invoke(app, ["vendors", "list"])
        assert "google-workspace" in listing.output

    def test_drift_warning_when_db_lags_yaml(
        self, tmp_path: Path
    ) -> None:
        from site_b2b_intel.db import repository as repo
        from site_b2b_intel.db.connection import open_db
        from site_b2b_intel.config import get_settings

        runner.invoke(app, ["init"])
        # Simulate a YAML edit that was never reseeded by disabling a rule.
        with open_db(get_settings().db_path) as conn:
            rule_id = repo.list_rules(conn)[0]["id"]
            conn.execute(
                "UPDATE fingerprint_rule SET enabled=0 WHERE id=?",
                (rule_id,),
            )
            conn.commit()

        result = runner.invoke(app, ["report", "never-scanned.com"])
        assert result.exit_code == 0
        assert "drift" in result.output.lower()


class TestScanArgumentHandling:
    def test_no_target_exits_nonzero(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 2

    def test_missing_file_exits_nonzero(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["scan", "--file", "/nope/absent.txt"])
        assert result.exit_code == 2
