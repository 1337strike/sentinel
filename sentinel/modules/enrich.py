"""Zero-credential enrichment: reverse DNS, Shodan InternetDB, WHOIS/RDAP, RIR.

Every source here is anonymous and keyless. Where a field cannot be obtained
that way it is left ``None`` and a ``source_unavailable`` event is logged. There
is no fallback to a registration-gated service, and no code path that could
accept one -- that is the hard constraint the whole design is built around, and
the honest consequence is that some records are incomplete. Quantifying that
incompleteness is the point of the gap analysis (experiment E6), so papering over
it with a commercial API would destroy the result the paper reports.

Field provenance
----------------
==========  ==============================================  ===============
Field       Source                                          Needs account?
==========  ==============================================  ===============
hostnames   System resolver PTR via dnspython               no
ports       Shodan InternetDB (free, keyless)               no
cves        Shodan InternetDB ``vulns``                     no
country     RIR delegated-extended file                     no
org         ``whois`` binary, else RIR RDAP over HTTPS       no
asn         RIPEstat network-info                           no
==========  ==============================================  ===============
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from sentinel.config.loader import SentinelConfig
from sentinel.http_client import DatasetUnavailable, HttpClient
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import Host, PortState
from sentinel.modules.rir import DelegationIndex

_log = get_logger("enrich")

#: WHOIS field names that carry an organisation name, most specific first.
_WHOIS_ORG_FIELDS: tuple[str, ...] = (
    "org-name",
    "orgname",
    "organization",
    "organisation",
    "owner",
    "netname",
    "descr",
)
_WHOIS_COUNTRY_FIELDS: tuple[str, ...] = ("country",)

#: InternetDB tags that indicate an industrial asset without identifying a product.
_INDUSTRIAL_TAGS: frozenset[str] = frozenset({"ics", "scada", "industrial", "plc", "bms"})

_CPE_RE = re.compile(r"^cpe:/?(?:2\.3:)?[aho]:([^:]+):([^:]+)", re.IGNORECASE)

#: Module-level latch so a missing `whois` binary is reported once per run
#: rather than once per host.
_whois_warned = False


@dataclass(slots=True)
class EnrichmentStats:
    """Per-run coverage counters. Feeds the gap-analysis experiment directly."""

    hosts: int = 0
    reverse_dns_resolved: int = 0
    internetdb_hits: int = 0
    internetdb_misses: int = 0
    org_resolved: int = 0
    country_resolved: int = 0
    asn_resolved: int = 0
    unavailable: dict[str, int] = field(default_factory=dict)

    def mark_unavailable(self, source: str) -> None:
        self.unavailable[source] = self.unavailable.get(source, 0) + 1

    def coverage(self) -> dict[str, float]:
        """Fraction of hosts for which each field was obtained."""
        if not self.hosts:
            return {}
        return {
            "hostnames": round(self.reverse_dns_resolved / self.hosts, 4),
            "ports_internetdb": round(self.internetdb_hits / self.hosts, 4),
            "org": round(self.org_resolved / self.hosts, 4),
            "country": round(self.country_resolved / self.hosts, 4),
            "asn": round(self.asn_resolved / self.hosts, 4),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": self.hosts,
            "reverse_dns_resolved": self.reverse_dns_resolved,
            "internetdb_hits": self.internetdb_hits,
            "internetdb_misses": self.internetdb_misses,
            "org_resolved": self.org_resolved,
            "country_resolved": self.country_resolved,
            "asn_resolved": self.asn_resolved,
            "coverage": self.coverage(),
            "source_unavailable": dict(self.unavailable),
        }


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------


def reverse_dns(ip: str, config: SentinelConfig) -> list[str]:
    """Resolve PTR records for ``ip`` using the system resolver."""
    try:
        import dns.resolver
        import dns.reversename
        from dns.exception import DNSException
    except ImportError:  # pragma: no cover -- dnspython is a declared dependency
        log_event(
            _log,
            "source_unavailable",
            "dnspython is not installed; reverse DNS skipped",
            dataset="reverse-dns",
            level=30,
        )
        return []

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.timeouts.dns
    resolver.lifetime = config.timeouts.dns

    try:
        name = dns.reversename.from_address(ip)
        answers = resolver.resolve(name, "PTR")
    except DNSException:
        # NXDOMAIN is the common, uninteresting case: most addresses have no PTR.
        return []
    except ValueError:
        return []

    return sorted({str(record).rstrip(".") for record in answers if str(record).strip()})


# ---------------------------------------------------------------------------
# Shodan InternetDB (free, keyless)
# ---------------------------------------------------------------------------


def internetdb_lookup(
    ip: str,
    client: HttpClient,
    config: SentinelConfig,
) -> dict[str, Any] | None:
    """Query Shodan InternetDB for one address.

    This is the free, unauthenticated per-IP endpoint, distinct from the Shodan
    REST API (which requires a key and is therefore unusable here). A 404 means
    "nothing known", which is a legitimate answer and not an error.
    """
    url = f"{config.endpoints.shodan_internetdb.rstrip('/')}/{ip}"
    try:
        payload = client.get_json(
            url,
            fixture=f"internetdb.shodan.io/{ip}.json",
            allow_404=True,
        )
    except DatasetUnavailable as exc:
        log_event(
            _log,
            "source_unavailable",
            f"InternetDB unavailable: {exc}",
            target=ip,
            dataset="shodan-internetdb",
            level=30,
        )
        return None
    if payload is None:
        return None
    if not isinstance(payload, dict):
        log_event(
            _log,
            "source_unavailable",
            "InternetDB returned an unexpected shape",
            target=ip,
            dataset="shodan-internetdb",
            level=30,
        )
        return None
    return payload


def apply_internetdb(host: Host, payload: dict[str, Any]) -> None:
    """Fold an InternetDB record into a host.

    Dataset-reported ports are merged as observations, flagged by service name so
    a reader can tell passive dataset evidence from an active measurement. CPE
    data supplies a vendor *hint* only -- it never sets ``ics_confirmed``,
    because that verdict must rest on Sentinel's own signature match for the
    detection claim to mean anything.
    """
    existing = {(p.port, p.proto) for p in host.ports}
    for raw_port in payload.get("ports") or []:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if (port, "tcp") not in existing:
            host.ports.append(PortState(port=port, state="open", proto="tcp", service="internetdb"))
            existing.add((port, "tcp"))
    host.ports.sort(key=lambda p: (p.proto, p.port))

    for hostname in payload.get("hostnames") or []:
        text = str(hostname).strip().rstrip(".")
        if text and text not in host.hostnames:
            host.hostnames.append(text)

    for vuln in payload.get("vulns") or []:
        text = str(vuln).strip().upper()
        if text and text not in host.cves:
            host.cves.append(text)

    tags = {str(t).strip().lower() for t in (payload.get("tags") or [])}
    if tags & _INDUSTRIAL_TAGS and not host.evidence.ics_confirmed:
        host.evidence.generic_industrial = True
        host.notes.append(
            "Shodan InternetDB tags this address as industrial "
            f"({', '.join(sorted(tags & _INDUSTRIAL_TAGS))}); treated as a "
            "candidate, not a confirmation."
        )

    if host.vendor is None:
        for cpe in payload.get("cpes") or []:
            match = _CPE_RE.match(str(cpe).strip())
            if match:
                vendor, product = match.group(1), match.group(2)
                host.notes.append(
                    f"InternetDB CPE suggests {vendor}/{product}; recorded as a "
                    "hint only, not a signature match."
                )
                break

    if host.ports:
        host.evidence.open_service = True
    host.evidence.known_cves = len(host.cves)


# ---------------------------------------------------------------------------
# Organisation attribution (WHOIS binary, then RDAP)
# ---------------------------------------------------------------------------


def whois_binary_available() -> bool:
    return shutil.which("whois") is not None


def whois_lookup(ip: str, config: SentinelConfig) -> dict[str, str]:
    """Query the local ``whois`` binary for an IP object.

    Returns a possibly-empty mapping with ``org`` and ``country``. The binary is
    an optional external dependency: minimal container and VM images frequently
    omit it, in which case the caller falls back to RDAP.
    """
    global _whois_warned  # noqa: PLW0603 -- once-per-run latch

    resolved = shutil.which("whois")
    if not resolved:
        if not _whois_warned:
            _whois_warned = True
            log_event(
                _log,
                "source_unavailable",
                "whois binary not found on PATH; falling back to RDAP over HTTPS "
                "for organisation attribution",
                dataset="whois-binary",
                level=30,
            )
        return {}

    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, shell=False
            [resolved, "--", ip],
            capture_output=True,
            text=True,
            timeout=max(5.0, config.timeouts.read),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log_event(
            _log,
            "source_unavailable",
            f"whois invocation failed: {exc}",
            target=ip,
            dataset="whois-binary",
            level=30,
        )
        return {}

    return parse_whois(proc.stdout or "")


def parse_whois(text: str) -> dict[str, str]:
    """Extract organisation and country from WHOIS output.

    Field names vary by registry, so candidates are collected per key and the
    most specific one wins. ``descr``/``netname`` are last resorts: they often
    hold a network label rather than an organisation.
    """
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(("%", "#")):
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip().lower()
        val = value.strip()
        if not val or val.lower() in {"none", "n/a"}:
            continue
        if key in _WHOIS_ORG_FIELDS and key not in found:
            found[key] = val
        elif key in _WHOIS_COUNTRY_FIELDS and "country" not in found:
            found["country"] = val

    out: dict[str, str] = {}
    for field_name in _WHOIS_ORG_FIELDS:
        if field_name in found:
            out["org"] = found[field_name]
            break
    if "country" in found:
        out["country"] = found["country"].strip().upper()[:2]
    return out


def rdap_lookup(
    ip: str,
    registry: str | None,
    client: HttpClient,
    config: SentinelConfig,
) -> dict[str, str]:
    """Query a RIR RDAP endpoint for an IP object.

    Same registry data as WHOIS, over HTTPS/JSON, operated by the RIRs
    themselves: anonymous and keyless. Used when the ``whois`` binary is absent.
    The registry is taken from RIR delegation data; without it there is no
    endpoint to query and the field stays null rather than being guessed at by
    trying every registry in turn.
    """
    if not registry:
        return {}
    base = config.endpoints.rdap.get(registry.lower())
    if not base:
        return {}

    try:
        payload = client.get_json(
            f"{base.rstrip('/')}/ip/{ip}",
            fixture=f"rdap/{registry.lower()}-{ip}.json",
            allow_404=True,
        )
    except DatasetUnavailable as exc:
        log_event(
            _log,
            "source_unavailable",
            f"RDAP unavailable for registry {registry}: {exc}",
            target=ip,
            dataset=f"rdap-{registry}",
            level=30,
        )
        return {}
    if not isinstance(payload, dict):
        return {}

    out: dict[str, str] = {}
    if payload.get("country"):
        out["country"] = str(payload["country"]).strip().upper()[:2]

    org = _rdap_org_name(payload)
    if org:
        out["org"] = org
    elif payload.get("name"):
        out["org"] = str(payload["name"]).strip()
    return out


def _rdap_org_name(payload: dict[str, Any]) -> str | None:
    """Pull an organisation name out of an RDAP entity vCard array."""
    for entity in payload.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = {str(r).lower() for r in (entity.get("roles") or [])}
        if roles and not roles & {"registrant", "administrative", "technical", "abuse"}:
            continue
        vcard = entity.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
            continue
        for item in vcard[1]:
            if (
                isinstance(item, list)
                and len(item) >= 4
                and str(item[0]).lower() == "fn"
                and str(item[3]).strip()
            ):
                return str(item[3]).strip()
    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def enrich_host(
    host: Host,
    client: HttpClient,
    config: SentinelConfig,
    delegation: DelegationIndex | None = None,
    stats: EnrichmentStats | None = None,
    do_reverse_dns: bool = True,
    do_internetdb: bool = True,
    do_org: bool = True,
) -> Host:
    """Enrich one host from anonymous sources only."""
    counters = stats or EnrichmentStats()
    counters.hosts += 1

    if do_reverse_dns:
        names = reverse_dns(host.ip, config)
        if names:
            counters.reverse_dns_resolved += 1
            for name in names:
                if name not in host.hostnames:
                    host.hostnames.append(name)
        else:
            counters.mark_unavailable("reverse-dns")

    # A passive scan already queried InternetDB to discover ports, and marks
    # those ports with service="internetdb". Re-querying here would double the
    # load on free public infrastructure for no new data, so the existing record
    # counts as a hit and the request is skipped.
    already_sourced = any(p.service == "internetdb" for p in host.ports)

    if do_internetdb and already_sourced:
        counters.internetdb_hits += 1
    elif do_internetdb:
        payload = internetdb_lookup(host.ip, client, config)
        if payload:
            counters.internetdb_hits += 1
            apply_internetdb(host, payload)
        else:
            counters.internetdb_misses += 1
            counters.mark_unavailable("shodan-internetdb")

    record = delegation.lookup(host.ip) if delegation is not None else None
    if record is not None:
        host.country = record.country
        counters.country_resolved += 1
        host.notes.append(
            f"Country {record.country} from the {record.registry.upper()} "
            "delegation file (allocation status "
            f"{record.status or 'unknown'})."
        )
    else:
        counters.mark_unavailable("rir-delegation")

    if do_org and host.org is None:
        info = whois_lookup(host.ip, config)
        if not info.get("org"):
            info = {
                **rdap_lookup(host.ip, record.registry if record else None, client, config),
                **info,
            }
        if info.get("org"):
            host.org = info["org"]
            counters.org_resolved += 1
        else:
            counters.mark_unavailable("org-attribution")
        if host.country is None and info.get("country"):
            host.country = info["country"]
            counters.country_resolved += 1

    return host


def enrich_hosts(
    hosts: list[Host],
    client: HttpClient,
    config: SentinelConfig,
    delegation: DelegationIndex | None = None,
    do_reverse_dns: bool = True,
    do_internetdb: bool = True,
    do_org: bool = True,
) -> tuple[list[Host], EnrichmentStats]:
    """Enrich a host list, returning the hosts and coverage statistics."""
    stats = EnrichmentStats()
    for host in hosts:
        enrich_host(
            host,
            client,
            config,
            delegation=delegation,
            stats=stats,
            do_reverse_dns=do_reverse_dns,
            do_internetdb=do_internetdb,
            do_org=do_org,
        )

    log_event(
        _log,
        "enrichment_complete",
        f"enriched {stats.hosts} host(s); "
        f"InternetDB {stats.internetdb_hits} hit / {stats.internetdb_misses} miss",
        host_count=stats.hosts,
        internetdb_hits=stats.internetdb_hits,
        coverage=stats.coverage(),
    )
    return hosts, stats


def reset_warning_latches() -> None:
    """Reset once-per-run warning state. Used by the test suite."""
    global _whois_warned  # noqa: PLW0603 -- test hook
    _whois_warned = False
