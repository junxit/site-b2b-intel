"""DNS resolver wrapper around dnspython.

Synchronous; iterates over configured upstreams on transient failure;
per-upstream queue-time rate limiter. Maps dnspython exceptions to the
project's :class:`Resolver` Protocol contract.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable

import dns.exception
import dns.rdatatype
import dns.resolver

from site_b2b_intel.types import (
    NXDOMAIN,
    ParsedRecord,
    ResolverTimeout,
)

#: Selectors probed at ``<selector>._domainkey.<domain>`` for DKIM detection.
#: Covers the common SaaS senders; extend in YAML or via env var later.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mandrill",
    "s1",
    "s2",
    "smtpapi",
    "default",
    "dkim",
)

#: Subdomains probed for CNAME records.
#:
#: A CNAME at one of these labels is the strongest DNS-only evidence that a
#: hosted SaaS product sits behind it — `status.` delegating to
#: `*.statuspage.io` is unambiguous in a way an apex TXT token is not.
#:
#: This costs one query per label, roughly doubling a scan (~19 to ~34
#: queries, about 4s to 7s per domain at the default 5 qps). Pass
#: `cname_probes=()` — or `b2b-intel scan --no-probe` — to skip it when
#: batch-scanning at volume.
DEFAULT_CNAME_PROBES: tuple[str, ...] = (
    "www",
    "shop",
    "store",
    "support",
    "help",
    "status",
    "blog",
    "careers",
    "jobs",
    "docs",
    "pages",
    "go",
    "try",
    "links",
    "email",
)


class _TokenBucket:
    """Per-upstream queue-time rate limiter (sliding 1s window)."""

    def __init__(self, qps: float):
        self.qps = qps
        self.window: deque[float] = deque()

    def wait(self) -> None:
        if self.qps <= 0:
            return
        now = time.monotonic()
        cutoff = now - 1.0
        while self.window and self.window[0] < cutoff:
            self.window.popleft()
        if len(self.window) >= int(self.qps):
            sleep_for = 1.0 - (now - self.window[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            self.window.popleft()
        self.window.append(time.monotonic())


class DnsResolver:
    """Concrete :class:`Resolver` implementation.

    Attributes:
        upstreams: Resolver IPs tried in order on transient failure.
        timeout: Per-query timeout in seconds.
        dkim_selectors: Selectors the scanner should probe at
            ``<selector>._domainkey.<domain>``. Exposed here so the
            scanner can read it without passing it through every call.
        cname_probes: Subdomain labels the scanner should probe for CNAME
            records. Same rationale as ``dkim_selectors``.
        last_used: The resolver IP that answered the last successful query
            (or ``None`` before the first call). Useful for the scanner's
            ``resolver_used`` audit column.
    """

    def __init__(
        self,
        upstreams: list[str] | None = None,
        *,
        timeout: float = 5.0,
        qps: float = 5.0,
        dkim_selectors: Iterable[str] = DEFAULT_DKIM_SELECTORS,
        cname_probes: Iterable[str] = DEFAULT_CNAME_PROBES,
    ):
        self.upstreams = upstreams or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.timeout = timeout
        self.dkim_selectors = tuple(dkim_selectors)
        self.cname_probes = tuple(cname_probes)
        self._buckets = {ip: _TokenBucket(qps) for ip in self.upstreams}
        self.last_used: str | None = None

    def _make_resolver(self, upstream: str) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [upstream]
        r.timeout = self.timeout
        r.lifetime = self.timeout
        return r

    def query(self, name: str, record_type: str) -> list[ParsedRecord]:
        """Query a single record type, retrying across upstreams.

        Returns ``[]`` for NoAnswer (the name exists but has no records of
        the requested type — common for MX/CAA/DMARC).

        Raises:
            NXDOMAIN: The name does not exist.
            ResolverTimeout: All upstreams exhausted with transient errors.
        """
        rdtype = dns.rdatatype.from_text(record_type)
        last_err: Exception | None = None

        for upstream in self.upstreams:
            self._buckets[upstream].wait()
            resolver = self._make_resolver(upstream)
            try:
                answer = resolver.resolve(name, rdtype)
            except dns.resolver.NXDOMAIN as e:
                self.last_used = upstream
                raise NXDOMAIN(f"{name}: NXDOMAIN") from e
            except dns.resolver.NoAnswer:
                self.last_used = upstream
                return []
            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ) as e:
                last_err = e
                continue

            self.last_used = upstream
            ttl = answer.rrset.ttl if answer.rrset is not None else None
            out: list[ParsedRecord] = []
            for rdata in answer:
                value = _render_rdata(record_type, rdata)
                if value:
                    out.append(
                        ParsedRecord(
                            record_type=record_type,
                            name=name,
                            value=value,
                            ttl=ttl,
                        )
                    )
            return out

        raise ResolverTimeout(
            f"all upstreams exhausted for {name} {record_type}: "
            f"{last_err!r}"
        )


def _render_rdata(record_type: str, rdata: object) -> str:
    """Convert a dnspython rdata object into our normalized string form.

    For MX/NS/CNAME we drop the priority/trailing dot. For TXT we
    concatenate the multi-string body per RFC 7208 §3.3.
    """
    if record_type == "MX":
        return str(rdata.exchange).rstrip(".")  # type: ignore[attr-defined]
    if record_type in {"NS", "CNAME"}:
        return str(rdata.target).rstrip(".")  # type: ignore[attr-defined]
    if record_type == "TXT":
        return b"".join(rdata.strings).decode(  # type: ignore[attr-defined]
            "utf-8", errors="replace"
        )
    if record_type == "CAA":
        flags = rdata.flags  # type: ignore[attr-defined]
        tag = rdata.tag  # type: ignore[attr-defined]
        value = rdata.value  # type: ignore[attr-defined]
        tag_s = tag.decode("ascii") if isinstance(tag, bytes) else tag
        value_s = (
            value.decode("ascii") if isinstance(value, bytes) else value
        )
        return f"{flags} {tag_s} {value_s}"
    if record_type in {"A", "AAAA"}:
        return rdata.address  # type: ignore[attr-defined]
    return rdata.to_text()  # type: ignore[attr-defined]
