"""Pure parsers for structured DNS record values.

These take strings (already extracted from dnspython rdata) and return
structured output. They're separate from the resolver so they can be
exercised with synthetic input in unit tests.
"""

from __future__ import annotations

from site_b2b_intel.normalize import extract_spf_target, split_spf_mechanisms


def parse_spf(value: str) -> list[str]:
    """Extract ``include:`` / ``redirect=`` targets from an SPF record.

    Args:
        value: Full SPF record value, e.g.
            ``'v=spf1 include:_spf.google.com include:mailgun.org ~all'``.

    Returns:
        Target hosts in source order. Empty list if the input isn't SPF
        or has no include / redirect directives.
    """
    targets: list[str] = []
    for mech in split_spf_mechanisms(value):
        t = extract_spf_target(mech)
        if t:
            targets.append(t)
    return targets


def parse_dmarc(value: str) -> dict[str, str]:
    """Parse a DMARC record into a ``tag -> value`` dict.

    Tag names are lowercased; values are unmodified. Common tags include
    ``v``, ``p``, ``rua``, ``ruf``, ``sp``, ``adkim``, ``aspf``, ``pct``,
    ``fo``.

    Args:
        value: Full DMARC record value, starting with ``v=DMARC1``.

    Returns:
        Dict of tag → value. Empty if the input isn't a DMARC record.
    """
    s = value.strip()
    if not s.lower().startswith("v=dmarc1"):
        return {}

    tags: dict[str, str] = {}
    for chunk in s.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        k, _, v = chunk.partition("=")
        tags[k.strip().lower()] = v.strip()
    return tags


def parse_dmarc_rua(rua_value: str) -> list[str]:
    """Split a DMARC ``rua=`` value into its mailbox URIs.

    ``rua`` may contain multiple comma-separated ``mailto:`` URIs.

    Args:
        rua_value: The value of the ``rua`` tag.

    Returns:
        Mailbox addresses with the ``mailto:`` scheme stripped.
    """
    out: list[str] = []
    for raw in rua_value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if raw.lower().startswith("mailto:"):
            raw = raw[len("mailto:") :]
        out.append(raw)
    return out


def mailbox_domain(mailbox: str) -> str | None:
    """Return the domain part of an email mailbox, lowercased.

    Returns ``None`` if the input has no ``@``.
    """
    if "@" not in mailbox:
        return None
    return mailbox.rsplit("@", 1)[1].lower()
