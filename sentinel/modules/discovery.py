"""Passive discovery: ASN -> announced prefixes via RIPEstat.

Strictly passive. Nothing in this module sends a packet to a discovered address;
it reads RIPE NCC's public routing view, which is derived from BGP data RIPE
already collects. For the subject of the study, a Sentinel passive run is
indistinguishable from no activity at all -- that is the central property the
paper claims, and it is why this module and :mod:`sentinel.modules.scanner` are
kept rigorously separate.

Expansion policy
----------------
``announced_prefixes`` returns prefixes. Turning a prefix into a host list is a
separate, opt-in step (:func:`expand_prefixes`) because it is the step with a
cost: expanding a single /16 and querying a per-IP dataset for each address
means 65 536 requests to free public infrastructure per run. That is neither
sustainable nor defensible in an ethics section, so expansion:

* is off unless explicitly requested;
* is capped by ``passive.max_hosts`` (default 1024);
* refuses prefixes broader than ``passive.min_expand_prefix_v4`` without an
  explicit force flag;
* reports truncation in the result rather than silently sampling, so the
  evaluation can state exactly what fraction of a prefix was examined.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sentinel.config.loader import SentinelConfig
from sentinel.http_client import DatasetUnavailable, HttpClient
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import utc_now_iso
from sentinel.modules.scope import validate_passive_targets

_log = get_logger("discovery")

_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

#: 16- and 32-bit private ASN ranges (RFC 6996). Not refused -- a lab study may
#: legitimately model one -- but flagged, because a private ASN has no
#: announced prefixes in the public routing view and an empty result would
#: otherwise look like a tool failure.
_PRIVATE_ASN_RANGES = ((64512, 65534), (4_200_000_000, 4_294_967_294))


class DiscoveryError(RuntimeError):
    """Discovery input was invalid, or the routing dataset was unusable."""


def normalize_asn(value: str | int) -> str:
    """Normalise an ASN to canonical ``ASnnnnn`` form.

    Accepts ``AS64500``, ``as64500``, ``64500``. Rejects anything else rather
    than guessing, so a typo surfaces before any network call.
    """
    text = str(value).strip()
    match = _ASN_RE.match(text)
    if not match:
        raise DiscoveryError(
            f"invalid ASN {value!r}; expected ASnnnnn or a bare number (e.g. AS64500)"
        )
    number = int(match.group(1))
    if not 0 < number <= 4_294_967_295:
        raise DiscoveryError(f"ASN out of range: {number}")
    return f"AS{number}"


def asn_number(asn: str) -> int:
    return int(normalize_asn(asn)[2:])


def is_private_asn(asn: str) -> bool:
    number = asn_number(asn)
    return any(low <= number <= high for low, high in _PRIVATE_ASN_RANGES)


@dataclass(slots=True)
class DiscoveryResult:
    """Outcome of a passive discovery pass."""

    asn: str | None = None
    holder: str | None = None
    prefixes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    expanded: bool = False
    truncated: bool = False
    total_addresses: int = 0
    queried_at: str = field(default_factory=utc_now_iso)
    source: str = "ripestat"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asn": self.asn,
            "holder": self.holder,
            "prefix_count": len(self.prefixes),
            "prefixes": list(self.prefixes),
            "host_count": len(self.hosts),
            "expanded": self.expanded,
            "truncated": self.truncated,
            "total_addresses": self.total_addresses,
            "rejected": [{"target": t, "reason": r} for t, r in self.rejected],
            "queried_at": self.queried_at,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# RIPEstat queries
# ---------------------------------------------------------------------------


def announced_prefixes(
    asn: str,
    client: HttpClient,
    config: SentinelConfig,
) -> list[str]:
    """Fetch the prefixes an ASN announces, per RIPEstat's routing view."""
    normalized = normalize_asn(asn)
    payload = client.get_json(
        config.endpoints.ripestat_announced_prefixes,
        params={"resource": normalized},
        fixture=f"stat.ripe.net/announced-prefixes-{normalized}.json",
    )
    records = _ripestat_data(payload, "announced-prefixes").get("prefixes") or []

    prefixes: list[str] = []
    for record in records:
        raw = record.get("prefix") if isinstance(record, dict) else record
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError:
            log_event(
                _log,
                "prefix_unparseable",
                f"skipping unparseable prefix {raw!r} from routing data",
                level=30,
            )
            continue
        if net.version == 6 and not config.passive.include_ipv6:
            continue
        prefixes.append(str(net))

    unique = sorted(set(prefixes), key=_prefix_sort_key)
    log_event(
        _log,
        "prefixes_discovered",
        f"{normalized} announces {len(unique)} prefix(es)",
        target=normalized,
        prefix_count=len(unique),
    )
    return unique


def as_holder(asn: str, client: HttpClient, config: SentinelConfig) -> str | None:
    """Fetch the AS holder string from RIPEstat.

    This is how Sentinel attributes an ASN to an organisation without any
    registration-gated service: RIPEstat's AS overview is public and anonymous.
    Returns ``None`` and logs ``source_unavailable`` if the dataset cannot
    answer -- never a substituted source.
    """
    normalized = normalize_asn(asn)
    try:
        payload = client.get_json(
            config.endpoints.ripestat_as_overview,
            params={"resource": normalized},
            fixture=f"stat.ripe.net/as-overview-{normalized}.json",
        )
    except DatasetUnavailable as exc:
        log_event(
            _log,
            "source_unavailable",
            f"AS overview unavailable for {normalized}: {exc}",
            target=normalized,
            dataset="ripestat-as-overview",
            level=30,
        )
        return None
    holder = _ripestat_data(payload, "as-overview").get("holder")
    return str(holder) if holder else None


def network_info(ip: str, client: HttpClient, config: SentinelConfig) -> dict[str, Any]:
    """Look up the covering prefix and originating ASNs for a single address."""
    try:
        payload = client.get_json(
            config.endpoints.ripestat_network_info,
            params={"resource": ip},
            fixture=f"stat.ripe.net/network-info-{ip}.json",
        )
    except DatasetUnavailable as exc:
        log_event(
            _log,
            "source_unavailable",
            f"network-info unavailable for this address: {exc}",
            target=ip,
            dataset="ripestat-network-info",
            level=30,
        )
        return {}
    data = _ripestat_data(payload, "network-info")
    return {
        "prefix": data.get("prefix"),
        "asns": [f"AS{a}" for a in (data.get("asns") or [])],
    }


def _ripestat_data(payload: Any, call: str) -> dict[str, Any]:
    """Unwrap RIPEstat's ``{status, data: {...}}`` envelope."""
    if not isinstance(payload, dict):
        raise DatasetUnavailable(f"RIPEstat {call} returned a non-object response")
    status = str(payload.get("status", "")).lower()
    if status and status != "ok":
        message = payload.get("status_message") or payload.get("messages") or status
        raise DatasetUnavailable(f"RIPEstat {call} returned status={status}: {message}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise DatasetUnavailable(f"RIPEstat {call} response has no data object")
    return data


# ---------------------------------------------------------------------------
# Bounded expansion
# ---------------------------------------------------------------------------


def expand_prefixes(
    prefixes: list[str],
    config: SentinelConfig,
    force: bool = False,
) -> tuple[list[str], bool, int]:
    """Expand prefixes to individual addresses under the passive caps.

    Returns ``(hosts, truncated, total_addresses)``. ``total_addresses`` is the
    full size of the prefix set, so the caller can report what fraction was
    actually examined -- a number the evaluation section needs and that silent
    sampling would destroy.
    """
    policy = config.passive
    floor = policy.min_expand_prefix_v4

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    total = 0
    for prefix in prefixes:
        net = ipaddress.ip_network(prefix, strict=False)
        if net.version == 6 and not policy.include_ipv6:
            continue
        if net.version == 4 and net.prefixlen < floor and not force:
            raise DiscoveryError(
                f"{net} is broader than /{floor}; expanding it would mean "
                f"{net.num_addresses:,} dataset lookups. Narrow the input, raise "
                "passive.min_expand_prefix_v4, or pass --force-expand if you "
                "have genuinely accounted for that request volume."
            )
        networks.append(net)
        total += net.num_addresses

    hosts: list[str] = []
    truncated = False
    cap = max(1, policy.max_hosts)

    for net in sorted(networks, key=lambda n: (n.version, int(n.network_address))):
        # ``hosts()`` excludes network/broadcast for IPv4 prefixes shorter than
        # /31, which is what we want: those addresses are not assignable targets.
        for address in net.hosts():
            if len(hosts) >= cap:
                truncated = True
                break
            hosts.append(str(address))
        if truncated:
            break

    if truncated:
        log_event(
            _log,
            "expansion_truncated",
            f"expansion capped at {cap} of {total:,} addresses "
            f"({100.0 * cap / total:.3f}% of the prefix set)",
            cap=cap,
            total_addresses=total,
            level=30,
        )
    return hosts, truncated, total


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def discover_asn(
    asn: str,
    client: HttpClient,
    config: SentinelConfig,
    expand: bool | None = None,
    force_expand: bool = False,
    allow_categories: Iterable[str] = (),
) -> DiscoveryResult:
    """Full passive discovery for one ASN.

    ``allow_categories`` is threaded through to the denylist so that an offline
    replay over RFC 5737 documentation ranges, or a lab study on RFC1918, can
    proceed without weakening the default-deny posture for ordinary runs.
    """
    normalized = normalize_asn(asn)
    if is_private_asn(normalized):
        log_event(
            _log,
            "private_asn",
            f"{normalized} is in a private ASN range; the public routing view "
            "will not list prefixes for it",
            target=normalized,
            level=30,
        )

    holder = as_holder(normalized, client, config)
    raw_prefixes = announced_prefixes(normalized, client, config)

    # The denylist applies to passive targets too: a routing view should never
    # hand back RFC1918 space, and if it does, that is a data-quality signal
    # worth recording rather than following.
    accepted, rejected = validate_passive_targets(raw_prefixes, allow_categories)
    for target, reason in rejected:
        log_event(
            _log,
            "prefix_rejected",
            f"routing data contained a non-routable prefix: {reason}",
            target=target,
            level=30,
        )

    result = DiscoveryResult(asn=normalized, holder=holder, prefixes=accepted, rejected=rejected)

    should_expand = config.passive.expand_hosts if expand is None else bool(expand)
    if should_expand and accepted:
        hosts, truncated, total = expand_prefixes(accepted, config, force=force_expand)
        result.hosts = hosts
        result.expanded = True
        result.truncated = truncated
        result.total_addresses = total
    else:
        result.total_addresses = sum(ipaddress.ip_network(p).num_addresses for p in accepted)

    log_event(
        _log,
        "discovery_complete",
        f"{normalized}: {len(result.prefixes)} prefix(es), {len(result.hosts)} host(s) enumerated",
        target=normalized,
        prefix_count=len(result.prefixes),
        host_count=len(result.hosts),
        expanded=result.expanded,
        truncated=result.truncated,
    )
    return result


def discover_cidrs(
    cidrs: list[str],
    config: SentinelConfig,
    expand: bool | None = None,
    force_expand: bool = False,
    allow_categories: tuple[str, ...] = (),
) -> DiscoveryResult:
    """Passive discovery from an operator-supplied CIDR list.

    ``allow_categories`` is threaded through from the scope file so a lab run on
    RFC1918 can enumerate its own ranges, while an unscoped passive run cannot.
    """
    accepted, rejected = validate_passive_targets(cidrs, allow_categories)
    result = DiscoveryResult(asn=None, prefixes=accepted, rejected=rejected, source="operator")

    should_expand = config.passive.expand_hosts if expand is None else bool(expand)
    if should_expand and accepted:
        hosts, truncated, total = expand_prefixes(accepted, config, force=force_expand)
        result.hosts = hosts
        result.expanded = True
        result.truncated = truncated
        result.total_addresses = total
    else:
        result.total_addresses = sum(ipaddress.ip_network(p).num_addresses for p in accepted)

    log_event(
        _log,
        "discovery_complete",
        f"operator input: {len(result.prefixes)} prefix(es), {len(result.hosts)} host(s)",
        prefix_count=len(result.prefixes),
        host_count=len(result.hosts),
        rejected_count=len(rejected),
    )
    return result


def _prefix_sort_key(prefix: str) -> tuple[int, int, int]:
    net = ipaddress.ip_network(prefix, strict=False)
    return (net.version, int(net.network_address), net.prefixlen)
