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


def parse_caa(value: str) -> tuple[int, str, str] | None:
    """Split a rendered CAA record into its ``(flags, tag, value)`` triple.

    Args:
        value: A CAA record as rendered by the resolver, e.g.
            ``'0 issue letsencrypt.org'``.

    Returns:
        ``(flags, lowercased_tag, value)``, or ``None`` if the input does
        not parse as a CAA triple.

    Examples:
        >>> parse_caa('0 issue letsencrypt.org')
        (0, 'issue', 'letsencrypt.org')
        >>> parse_caa('128 issuewild digicert.com')
        (128, 'issuewild', 'digicert.com')
        >>> parse_caa('garbage') is None
        True
    """
    parts = value.strip().split(None, 2)
    if len(parts) < 3:
        return None
    flags_s, tag, rest = parts
    try:
        flags = int(flags_s)
    except ValueError:
        return None
    return flags, tag.lower(), rest.strip().strip('"').strip()


def caa_issuer_domain(value: str) -> str | None:
    """Return the certificate authority a CAA record authorizes, if any.

    Only ``issue`` and ``issuewild`` name a CA. ``iodef`` carries a
    reporting URI rather than an issuer — treating it as one would
    manufacture false CA detections, so it is ignored.

    Per RFC 8659, a value of ``;`` means *no issuance permitted*. It
    authorizes nobody, so it yields ``None`` rather than an empty issuer.

    Args:
        value: A CAA record as rendered by the resolver.

    Returns:
        The lowercased issuer domain with any CAA parameters stripped, or
        ``None`` if this record names no CA.

    Examples:
        >>> caa_issuer_domain('0 issue letsencrypt.org')
        'letsencrypt.org'
        >>> caa_issuer_domain('0 issuewild "digicert.com; policy=ev"')
        'digicert.com'
        >>> caa_issuer_domain('0 iodef mailto:sec@example.com') is None
        True
        >>> caa_issuer_domain('0 issue ";"') is None
        True
    """
    parsed = parse_caa(value)
    if parsed is None:
        return None
    _flags, tag, raw = parsed
    if tag not in {"issue", "issuewild"}:
        return None
    # CAA parameters trail a semicolon: `ca.example; account=12345`
    issuer = raw.split(";", 1)[0].strip().strip('"').strip()
    return issuer.lower() if issuer else None
