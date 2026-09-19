"""Load and persist the YAML-authored vendor + fingerprint catalog.

``load_catalog`` reads ``fingerprints/data/vendors.yaml`` and every file in
``fingerprints/data/rules/*.yaml``, validates them with Pydantic, and returns
a :class:`VendorCatalog`. ``seed_catalog`` pushes that catalog into a SQLite
DB via the repository layer (idempotent — safe to re-run).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from site_b2b_intel.db import repository as repo
from site_b2b_intel.types import (
    KNOWN_MATCH_KINDS,
    KNOWN_RECORD_TYPES,
    Confidence,
    Rule,
)

_DATA_DIR = Path(__file__).parent / "data"


class VendorProfile(BaseModel):
    """Versioned contact metadata for a vendor."""

    model_config = ConfigDict(extra="forbid")

    website: str | None = None
    support_email: str | None = None
    sales_email: str | None = None
    phone: str | None = None
    headquarters: str | None = None
    source: str | None = None


class Vendor(BaseModel):
    """A SaaS vendor entry from vendors.yaml."""

    model_config = ConfigDict(extra="forbid")

    slug: str
    name: str
    category: str
    profile: VendorProfile | None = None


class _RuleEntry(BaseModel):
    """Raw rule entry as authored in YAML.

    Validation here is deliberately strict. A rule with a misspelled
    ``record_type`` or ``match_kind`` is not a runtime error — it simply
    never matches anything, which is invisible until someone notices a
    vendor is undetectable. Failing at load turns a silent gap into a
    loud one.
    """

    model_config = ConfigDict(extra="forbid")

    vendor: str  # slug reference into vendors.yaml
    record_type: str
    match_kind: str
    pattern: str
    confidence: Confidence

    @field_validator("record_type")
    @classmethod
    def _known_record_type(cls, v: str) -> str:
        if v not in KNOWN_RECORD_TYPES:
            raise ValueError(
                f"unknown record_type {v!r}; expected one of "
                f"{', '.join(sorted(KNOWN_RECORD_TYPES))}"
            )
        return v

    @field_validator("match_kind")
    @classmethod
    def _known_match_kind(cls, v: str) -> str:
        if v not in KNOWN_MATCH_KINDS:
            raise ValueError(
                f"unknown match_kind {v!r}; expected one of "
                f"{', '.join(sorted(KNOWN_MATCH_KINDS))}"
            )
        return v

    @model_validator(mode="after")
    def _regex_compiles(self) -> _RuleEntry:
        """A malformed regex would otherwise raise mid-scan, per record."""
        if self.match_kind == "regex":
            try:
                re.compile(self.pattern)
            except re.error as e:
                raise ValueError(
                    f"invalid regex pattern {self.pattern!r}: {e}"
                ) from e
        return self


class _RulesFile(BaseModel):
    rules: list[_RuleEntry] = []  # noqa: RUF012


class _VendorsFile(BaseModel):
    vendors: list[Vendor]


@dataclass(frozen=True, slots=True)
class VendorCatalog:
    """Vendors + fingerprint rules loaded from disk.

    Rules carry ``rule_id=None`` until they're persisted by
    :func:`seed_catalog`.
    """

    vendors: list[Vendor]
    rules: list[Rule]

    def vendor_slugs(self) -> set[str]:
        return {v.slug for v in self.vendors}

    def rules_by_record_type(self) -> dict[str, list[Rule]]:
        """Index rules by ``record_type`` for cheap lookup in the matcher."""
        idx: dict[str, list[Rule]] = {}
        for r in self.rules:
            idx.setdefault(r.record_type, []).append(r)
        return idx


def load_catalog(data_dir: Path | None = None) -> VendorCatalog:
    """Load and validate the YAML catalog.

    Args:
        data_dir: Optional override for the YAML data directory. Defaults to
            the bundled ``fingerprints/data/``.

    Returns:
        A :class:`VendorCatalog`. Rule ids are None pending persistence.

    Raises:
        ValueError: A rule references a vendor slug not declared in
            ``vendors.yaml``.
    """
    base = data_dir or _DATA_DIR

    vendors_data = yaml.safe_load((base / "vendors.yaml").read_text())
    vf = _VendorsFile.model_validate(vendors_data)

    known_slugs = {v.slug for v in vf.vendors}

    rules: list[Rule] = []
    rules_dir = base / "rules"
    if rules_dir.exists():
        for path in sorted(rules_dir.glob("*.yaml")):
            data = yaml.safe_load(path.read_text())
            if data is None:
                continue
            rf = _RulesFile.model_validate(data)
            for entry in rf.rules:
                if entry.vendor not in known_slugs:
                    raise ValueError(
                        f"{path.name}: rule references unknown vendor "
                        f"{entry.vendor!r}; add it to vendors.yaml"
                    )
                rules.append(
                    Rule(
                        rule_id=None,
                        vendor_slug=entry.vendor,
                        record_type=entry.record_type,
                        match_kind=entry.match_kind,
                        pattern=entry.pattern,
                        confidence=entry.confidence,
                        enabled=True,
                    )
                )

    return VendorCatalog(vendors=vf.vendors, rules=rules)


def seed_catalog(conn: sqlite3.Connection, catalog: VendorCatalog) -> None:
    """Push the catalog into the DB. Idempotent.

    For each vendor:
      * Upserts the row.
      * Appends a new ``vendor_profile`` if the contact fields differ from
        the current latest profile (no-op otherwise).

    For each rule:
      * Upserts by (vendor, record_type, match_kind, pattern), re-enabling
        any previously soft-deleted match.

    After all rules are upserted, any active rule not present in the YAML
    is soft-deleted (``enabled=0``) so historical detections remain
    resolvable.
    """
    now = datetime.now(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    vendor_ids: dict[str, int] = {}

    with conn:
        for v in catalog.vendors:
            vid = repo.upsert_vendor(
                conn, slug=v.slug, name=v.name, category=v.category
            )
            vendor_ids[v.slug] = vid

            if v.profile is None:
                continue

            latest = repo.latest_profile(conn, vid)
            incoming = (
                v.profile.website,
                v.profile.support_email,
                v.profile.sales_email,
                v.profile.phone,
                v.profile.headquarters,
                v.profile.source,
            )
            current = (
                (
                    latest["website"],
                    latest["support_email"],
                    latest["sales_email"],
                    latest["phone"],
                    latest["headquarters"],
                    latest["source"],
                )
                if latest is not None
                else None
            )
            if current != incoming:
                repo.insert_profile(
                    conn,
                    vendor_id=vid,
                    valid_from=now,
                    website=v.profile.website,
                    support_email=v.profile.support_email,
                    sales_email=v.profile.sales_email,
                    phone=v.profile.phone,
                    headquarters=v.profile.headquarters,
                    source=v.profile.source,
                )

        rule_ids: list[int] = []
        for r in catalog.rules:
            rid = repo.upsert_rule(
                conn,
                vendor_id=vendor_ids[r.vendor_slug],
                record_type=r.record_type,
                match_kind=r.match_kind,
                pattern=r.pattern,
                confidence=r.confidence.value,
            )
            rule_ids.append(rid)

        repo.soft_delete_rules_not_in(conn, rule_ids)
