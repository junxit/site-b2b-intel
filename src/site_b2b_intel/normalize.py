"""Pure normalization helpers — no I/O, no module-level state beyond the
suffix-list extractor.

Used by both the input layer (CLI accepts URL / email / bare domain) and the
parser layer (SPF tokenization). Lives outside `resolve/` and `fingerprints/`
to keep those modules acyclic.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

# Build a TLDExtract that never tries to fetch the public suffix list from
# the network. We rely on the bundled snapshot — accurate enough for the
# domains we'll see, and avoids surprise HTTP calls during testing.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

_STRIP_AFTER = re.compile(r"[/?#:]")


def to_registrable_domain(input_: str) -> str:
    """Coerce a domain / URL / email into a registrable domain.

    Args:
        input_: A bare domain (``'stripe.com'``), URL
            (``'https://x.stripe.com/foo'``), or email
            (``'user@stripe.com'``). May contain mixed case or IDN.

    Returns:
        Lower-cased, punycoded registrable domain such as ``'stripe.com'``
        or ``'xn--bcher-kva.de'``.

    Raises:
        ValueError: The input is empty, malformed, or has no public suffix
            (e.g. ``'localhost'``).

    Examples:
        >>> to_registrable_domain('https://x.stripe.com/foo')
        'stripe.com'
        >>> to_registrable_domain('user@example.co.uk')
        'example.co.uk'
        >>> to_registrable_domain('STRIPE.COM')
        'stripe.com'
    """
    if not input_ or not input_.strip():
        raise ValueError("empty domain input")

    candidate = input_.strip()

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    elif "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]

    candidate = _STRIP_AFTER.split(candidate, maxsplit=1)[0]
    candidate = candidate.lower().strip(".")

    if not candidate:
        raise ValueError(f"could not extract a domain from {input_!r}")

    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"invalid IDN in {input_!r}: {e}") from e

    extracted = _extract(candidate)
    if not extracted.domain or not extracted.suffix:
        raise ValueError(f"no registrable domain in {input_!r}")

    return f"{extracted.domain}.{extracted.suffix}".lower()


def split_spf_mechanisms(spf_value: str) -> list[str]:
    """Split an SPF record value into its mechanism / modifier tokens.

    Args:
        spf_value: The full SPF record, e.g.
            ``'v=spf1 include:_spf.google.com include:mailgun.org ~all'``.

    Returns:
        Whitespace-separated tokens following the ``v=spf1`` version marker.
        Qualifier prefixes (``+``, ``-``, ``~``, ``?``) are preserved.
        Returns an empty list if the input is not an SPF record.

    Examples:
        >>> split_spf_mechanisms('v=spf1 include:_spf.google.com -all')
        ['include:_spf.google.com', '-all']
    """
    tokens = spf_value.strip().split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return []
    return tokens[1:]


def extract_spf_target(mechanism: str) -> str | None:
    """Return the target domain referenced by an SPF ``include:`` or
    ``redirect=`` mechanism, if any.

    Args:
        mechanism: One token from :func:`split_spf_mechanisms`, e.g.
            ``'include:_spf.google.com'`` or ``'redirect=spf.example.com'``.

    Returns:
        The target domain name, or ``None`` if this mechanism doesn't
        reference another SPF record (``-all``, ``ip4:...``, ``mx``, etc.).

    Examples:
        >>> extract_spf_target('include:_spf.google.com')
        '_spf.google.com'
        >>> extract_spf_target('redirect=spf.example.com')
        'spf.example.com'
        >>> extract_spf_target('-all') is None
        True
    """
    if mechanism and mechanism[0] in "+-~?":
        mechanism = mechanism[1:]
    if mechanism.startswith("include:"):
        return mechanism[len("include:") :]
    if mechanism.startswith("redirect="):
        return mechanism[len("redirect=") :]
    return None
