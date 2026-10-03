"""RIR delegated-extended file parsing for anonymous geolocation attribution.

Each Regional Internet Registry publishes a plain-text "delegated-extended"
file listing every range it has allocated, with the country code, allocation
date, and status. The files need no account, no key, and no terms acceptance --
which is exactly why they are the attribution source here, in place of a
commercial geolocation API.

What these files do and do not contain
--------------------------------------
They give **country code, registry, allocation date, and status**. They identify
the holder only by an *opaque handle* (a registry-internal identifier), not by
an organisation name. Sentinel therefore reports ``country`` from delegation
data and leaves ``org`` to WHOIS/RDAP, which are separate lookups over separate
transports. Conflating the two would be a correctness bug and would overstate
what a keyless pipeline can attribute -- a distinction the paper's gap analysis
depends on.

Record format (pipe-delimited)::

    registry|cc|type|start|value|date|status|opaque-id|...

For ``type == ipv4``, ``value`` is a **count of addresses**, not a prefix
length, and the count is not necessarily a power of two: a single record can
span several CIDR blocks. Lookup is therefore interval-based (binary search over
sorted start addresses) rather than prefix-based.
"""

from __future__ import annotations

import bisect
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.config.loader import SentinelConfig
from sentinel.http_client import DatasetUnavailable, HttpClient
from sentinel.logging_setup import get_logger, log_event

_log = get_logger("rir")

#: Statuses that represent a real delegation. ``reserved``/``available`` records
#: describe unallocated space and are skipped.
_USEFUL_STATUS: frozenset[str] = frozenset({"allocated", "assigned", "legacy"})


@dataclass(slots=True)
class DelegationRecord:
    """One allocation interval from a delegation file."""

    registry: str
    country: str
    start: int
    count: int
    version: int
    date: str | None = None
    status: str | None = None

    @property
    def end(self) -> int:
        return self.start + self.count - 1

    def contains(self, value: int) -> bool:
        return self.start <= value <= self.end

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry": self.registry,
            "country": self.country,
            "date": self.date,
            "status": self.status,
            "version": self.version,
        }


@dataclass(slots=True)
class DelegationIndex:
    """Searchable index over one or more delegation files."""

    records_v4: list[DelegationRecord] = field(default_factory=list)
    records_v6: list[DelegationRecord] = field(default_factory=list)
    _starts_v4: list[int] = field(default_factory=list, repr=False)
    _starts_v6: list[int] = field(default_factory=list, repr=False)
    sources: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records_v4) + len(self.records_v6)

    def finalize(self) -> DelegationIndex:
        """Sort records and build the binary-search key arrays."""
        self.records_v4.sort(key=lambda r: r.start)
        self.records_v6.sort(key=lambda r: r.start)
        self._starts_v4 = [r.start for r in self.records_v4]
        self._starts_v6 = [r.start for r in self.records_v6]
        return self

    def lookup(self, ip: str) -> DelegationRecord | None:
        """Find the allocation covering ``ip``, or ``None``."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None

        value = int(address)
        if address.version == 4:
            records, starts = self.records_v4, self._starts_v4
        else:
            records, starts = self.records_v6, self._starts_v6
        if not starts:
            return None

        # Rightmost record whose start is <= value; intervals do not overlap
        # within a registry, so at most one candidate can contain the address.
        index = bisect.bisect_right(starts, value) - 1
        if index < 0:
            return None
        candidate = records[index]
        return candidate if candidate.contains(value) else None


def parse_delegation_file(path: str | Path, registry_hint: str | None = None) -> DelegationIndex:
    """Parse one delegated-extended file into an index."""
    file_path = Path(path)
    index = DelegationIndex(sources=[str(file_path)])

    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line or line.startswith("#"):
                continue
            fields = line.rstrip("\n").split("|")
            if len(fields) < 7:
                continue
            registry, country, rtype, start, value, date, status = fields[:7]

            # Header and summary lines share the record shape but are not
            # allocations; both are filtered by the type/status checks.
            if rtype not in ("ipv4", "ipv6") or not country or country == "*":
                continue
            if status.strip().lower() not in _USEFUL_STATUS:
                continue

            try:
                if rtype == "ipv4":
                    start_int = int(ipaddress.IPv4Address(start))
                    count = int(value)
                    version = 4
                else:
                    start_int = int(ipaddress.IPv6Address(start))
                    # For IPv6 the value field is a prefix length.
                    count = 1 << (128 - int(value))
                    version = 6
            except (ValueError, ipaddress.AddressValueError):
                continue

            if count <= 0:
                continue

            record = DelegationRecord(
                registry=(registry or registry_hint or "unknown").strip().lower(),
                country=country.strip().upper(),
                start=start_int,
                count=count,
                version=version,
                date=date.strip() or None,
                status=status.strip().lower() or None,
            )
            (index.records_v4 if version == 4 else index.records_v6).append(record)

    index.finalize()
    log_event(
        _log,
        "delegation_parsed",
        f"{len(index)} allocation record(s) parsed from {file_path.name}",
        delegation_file=str(file_path),
        record_count=len(index),
    )
    return index


def merge_indexes(indexes: Iterable[DelegationIndex]) -> DelegationIndex:
    """Combine per-registry indexes into one."""
    merged = DelegationIndex()
    for index in indexes:
        merged.records_v4.extend(index.records_v4)
        merged.records_v6.extend(index.records_v6)
        merged.sources.extend(index.sources)
    return merged.finalize()


def load_delegation_index(
    client: HttpClient,
    config: SentinelConfig,
    registries: Iterable[str] | None = None,
    max_age_seconds: float = 86_400.0,
) -> DelegationIndex:
    """Download (or reuse cached) delegation files and build a combined index.

    A registry that cannot be fetched is skipped with a ``source_unavailable``
    event rather than failing the run: partial attribution is useful, and the
    alternative -- reaching for a registration-gated geolocation service -- is
    forbidden by policy.
    """
    wanted = (
        [r.lower() for r in registries]
        if registries is not None
        else list(config.endpoints.rir_delegations)
    )

    indexes: list[DelegationIndex] = []
    for name in wanted:
        url = config.endpoints.rir_delegations.get(name)
        if not url:
            log_event(
                _log,
                "source_unavailable",
                f"no delegation URL configured for registry {name!r}",
                registry=name,
                level=30,
            )
            continue
        try:
            path = client.download_cached(
                url,
                name=f"delegated-{name}-extended-latest",
                max_age_seconds=max_age_seconds,
                fixture=f"rir/delegated-{name}-extended-latest",
            )
        except DatasetUnavailable as exc:
            log_event(
                _log,
                "source_unavailable",
                f"delegation file for {name} unavailable: {exc}",
                registry=name,
                dataset=f"rir-delegation-{name}",
                level=30,
            )
            continue
        indexes.append(parse_delegation_file(path, registry_hint=name))

    if not indexes:
        log_event(
            _log,
            "source_unavailable",
            "no RIR delegation data available; country attribution will be null",
            dataset="rir-delegation",
            level=30,
        )
        return DelegationIndex().finalize()

    return merge_indexes(indexes)
