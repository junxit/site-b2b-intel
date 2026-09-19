"""Apply fingerprint rules to parsed DNS records.

Pure function: takes parsed records + a rule index, returns detections.
No I/O, no DB, no DNS resolution — designed so the scanner can compose it
inside a single SQLite transaction.
"""

from __future__ import annotations

import re
from functools import lru_cache

from site_b2b_intel.types import Detection, ParsedRecord, Rule


@lru_cache(maxsize=512)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _match_one(rule: Rule, value: str) -> bool:
    kind = rule.match_kind
    pat = rule.pattern
    if kind == "exact":
        return value == pat
    if kind == "prefix":
        return value.startswith(pat)
    if kind == "suffix":
        return value.endswith(pat)
    if kind == "contains":
        return pat in value
    if kind == "regex":
        return _compile_regex(pat).search(value) is not None
    raise ValueError(f"unknown match_kind: {kind!r}")


def match(
    records: list[ParsedRecord],
    rules_by_type: dict[str, list[Rule]],
) -> list[Detection]:
    """Apply rules to records, returning every (rule, record) match.

    A single rule can match multiple records (e.g. two MX entries both
    ending in ``.outlook.com``). Each match produces a separate
    :class:`Detection`; the caller is responsible for grouping evidence
    when persisting.

    Args:
        records: Parsed DNS records to evaluate.
        rules_by_type: Rules indexed by ``record_type``. Built once per
            scan from :meth:`VendorCatalog.rules_by_record_type`.

    Returns:
        A list of detections, possibly empty. Order is stable — records in
        input order, then rules in the order they appear in the index.
    """
    out: list[Detection] = []
    for rec in records:
        rules = rules_by_type.get(rec.record_type, [])
        for rule in rules:
            if not rule.enabled:
                continue
            if _match_one(rule, rec.value):
                out.append(
                    Detection(
                        rule=rule,
                        record=rec,
                        confidence=rule.confidence,
                    )
                )
    return out
