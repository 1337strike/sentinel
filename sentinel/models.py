"""Core data model for the Sentinel pipeline.

Every stage of the pipeline (discover -> scan -> fingerprint -> enrich ->
report) reads and writes the same :class:`ScanResult` envelope, so any stage
can be run standalone against a JSON file produced by the previous one. This
is what makes the pipeline reproducible from seed data for the paper's
evaluation section.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScanMode(str, enum.Enum):
    """Execution mode. ``PASSIVE`` is the default and emits no packets to targets."""

    PASSIVE = "passive"
    ACTIVE = "active"


class RiskLevel(str, enum.Enum):
    """Exposure severity assigned by :mod:`sentinel.modules.risk`."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def severity(self) -> int:
        """Monotonic integer rank, for sorting and for diff escalation checks."""
        return _SEVERITY_RANK[self.value]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.severity < other.severity


_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class PortClass(str, enum.Enum):
    """Port taxonomy that drives rate-limit selection.

    OT ports get an order-of-magnitude lower packet budget than web ports
    because industrial controllers are routinely knocked offline by scan
    pressure -- a safety property, not a politeness one.
    """

    OT = "ot"
    WEB = "web"
    OTHER = "other"


class AlertKind(str, enum.Enum):
    """Change classes emitted by :mod:`sentinel.modules.monitor`."""

    NEW_HOST = "new_host"
    REMOVED_HOST = "removed_host"
    NEW_PORT = "new_port"
    CLOSED_PORT = "closed_port"
    BANNER_CHANGE = "banner_change"
    VERSION_CHANGE = "version_change"
    VENDOR_CHANGE = "vendor_change"
    RISK_ESCALATION = "risk_escalation"
    RISK_REDUCTION = "risk_reduction"
    AUTH_WALL_REMOVED = "auth_wall_removed"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PortState:
    """A single observed transport endpoint."""

    port: int
    state: str = "open"
    proto: str = "tcp"
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"port": self.port, "state": self.state, "proto": self.proto}
        if self.service:
            out["service"] = self.service
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PortState:
        return cls(
            port=int(raw["port"]),
            state=str(raw.get("state", "open")),
            proto=str(raw.get("proto", "tcp")),
            service=raw.get("service"),
        )


@dataclass(slots=True)
class RiskEvidence:
    """Normalised inputs to the risk function.

    Deliberately decoupled from :class:`Host` so that
    :func:`sentinel.modules.risk.score` is a pure function of explicit
    evidence. The paper's scoring model can then be audited and replayed from
    a table of evidence vectors without running the collector.
    """

    ics_confirmed: bool = False
    generic_industrial: bool = False
    auth_wall: bool = False
    pre_auth_disclosure: bool = False
    ot_protocol_exposed: bool = False
    default_cred_risk: bool = False
    open_service: bool = False
    known_cves: int = 0
    match_confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RiskEvidence:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in raw.items() if k in known})


@dataclass(slots=True)
class Host:
    """One asset observation.

    Serialises to the documented JSON schema. Fields beyond the schema
    (``evidence``, ``confidence``, ``matched_signature`` ...) are additive and
    carry the provenance needed to defend a finding during disclosure.
    """

    ip: str
    ports: list[PortState] = field(default_factory=list)
    banner: str | None = None
    title: str | None = None
    vendor: str | None = None
    product_version: str | None = None
    pre_auth_disclosure: bool = False
    auth_wall: bool = False
    risk: RiskLevel = RiskLevel.INFO
    confidence: float = 0.0
    matched_signature: str | None = None
    org: str | None = None
    asn: str | None = None
    country: str | None = None
    hostnames: list[str] = field(default_factory=list)
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_version: str | None = None
    cves: list[str] = field(default_factory=list)
    mitre_ics: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    evidence: RiskEvidence = field(default_factory=RiskEvidence)
    source: str = "unknown"
    notes: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted(p.port for p in self.ports if p.state == "open")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "ports": [p.to_dict() for p in self.ports],
            "banner": self.banner,
            "title": self.title,
            "vendor": self.vendor,
            "product_version": self.product_version,
            "pre_auth_disclosure": self.pre_auth_disclosure,
            "auth_wall": self.auth_wall,
            "risk": self.risk.value,
            "confidence": round(self.confidence, 3),
            "matched_signature": self.matched_signature,
            "org": self.org,
            "asn": self.asn,
            "country": self.country,
            "hostnames": list(self.hostnames),
            "tls_subject": self.tls_subject,
            "tls_issuer": self.tls_issuer,
            "tls_version": self.tls_version,
            "cves": list(self.cves),
            "mitre_ics": list(self.mitre_ics),
            "remediation": list(self.remediation),
            "evidence": self.evidence.to_dict(),
            "source": self.source,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Host:
        return cls(
            ip=str(raw["ip"]),
            ports=[PortState.from_dict(p) for p in raw.get("ports", [])],
            banner=raw.get("banner"),
            title=raw.get("title"),
            vendor=raw.get("vendor"),
            product_version=raw.get("product_version"),
            pre_auth_disclosure=bool(raw.get("pre_auth_disclosure", False)),
            auth_wall=bool(raw.get("auth_wall", False)),
            risk=RiskLevel(raw.get("risk", "INFO")),
            confidence=float(raw.get("confidence", 0.0)),
            matched_signature=raw.get("matched_signature"),
            org=raw.get("org"),
            asn=raw.get("asn"),
            country=raw.get("country"),
            hostnames=list(raw.get("hostnames", [])),
            tls_subject=raw.get("tls_subject"),
            tls_issuer=raw.get("tls_issuer"),
            tls_version=raw.get("tls_version"),
            cves=list(raw.get("cves", [])),
            mitre_ics=list(raw.get("mitre_ics", [])),
            remediation=list(raw.get("remediation", [])),
            evidence=RiskEvidence.from_dict(raw.get("evidence", {})),
            source=str(raw.get("source", "unknown")),
            notes=list(raw.get("notes", [])),
        )


@dataclass(slots=True)
class ScanResult:
    """Pipeline envelope -- the unit of persistence and of run-to-run diffing."""

    scan_time: str = field(default_factory=lambda: utc_now_iso())
    target_asn: str | None = None
    mode: ScanMode = ScanMode.PASSIVE
    scope_hash: str | None = None
    tool_version: str | None = None
    prefixes: list[str] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def host_index(self) -> dict[str, Host]:
        return {h.ip: h for h in self.hosts}

    def risk_histogram(self) -> dict[str, int]:
        hist = {lvl.value: 0 for lvl in RiskLevel}
        for host in self.hosts:
            hist[host.risk.value] += 1
        return hist

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time,
            "target_asn": self.target_asn,
            "mode": self.mode.value,
            "scope_hash": self.scope_hash,
            "tool_version": self.tool_version,
            "prefixes": list(self.prefixes),
            "hosts": [h.to_dict() for h in self.hosts],
            "stats": dict(self.stats),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ScanResult:
        return cls(
            scan_time=str(raw.get("scan_time", utc_now_iso())),
            target_asn=raw.get("target_asn"),
            mode=ScanMode(raw.get("mode", "passive")),
            scope_hash=raw.get("scope_hash"),
            tool_version=raw.get("tool_version"),
            prefixes=list(raw.get("prefixes", [])),
            hosts=[Host.from_dict(h) for h in raw.get("hosts", [])],
            stats=dict(raw.get("stats", {})),
        )


@dataclass(slots=True)
class Alert:
    """A single detected change between two runs."""

    kind: AlertKind
    ip: str
    severity: RiskLevel
    message: str
    before: Any = None
    after: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "ip": self.ip,
            "severity": self.severity.value,
            "message": self.message,
            "before": self.before,
            "after": self.after,
        }


@dataclass(slots=True)
class DiffReport:
    """Output of :func:`sentinel.modules.monitor.diff_runs`."""

    baseline_time: str
    current_time: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def max_severity(self) -> RiskLevel:
        if not self.alerts:
            return RiskLevel.INFO
        return max((a.severity for a in self.alerts), key=lambda r: r.severity)

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.kind.value] = counts.get(alert.kind.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_time": self.baseline_time,
            "current_time": self.current_time,
            "alert_count": len(self.alerts),
            "max_severity": self.max_severity.value,
            "by_kind": self.by_kind(),
            "alerts": [a.to_dict() for a in self.alerts],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    """Timezone-aware ISO8601 timestamp, second precision, always UTC.

    Fixed format keeps run-to-run diffs and audit records lexicographically
    sortable, which the monitor relies on when picking a baseline.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
