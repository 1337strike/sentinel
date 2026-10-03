"""Exposure risk scoring.

:func:`score` is a pure function of a :class:`~sentinel.models.RiskEvidence`
vector. No network, no filesystem, no clock. That is deliberate: the scoring
model is a claim the paper has to defend, and a pure function can be replayed
over a table of evidence vectors, exhaustively tested at its boundaries, and
audited by a reviewer who never runs the collector.

Base model (as specified)
-------------------------
=========================================  ==========
Condition                                  Level
=========================================  ==========
ICS confirmed, no authentication boundary   CRITICAL
ICS confirmed, authentication required      HIGH
Generic industrial vocabulary only          MEDIUM
Non-ICS service reachable                   LOW
No evidence                                 INFO
=========================================  ==========

One documented refinement
-------------------------
An OT protocol port that is open but whose product could not be identified
(``ot_protocol_exposed`` without ``ics_confirmed``) scores MEDIUM rather than
LOW. Rationale: a listening TCP/502 or TCP/102 endpoint is industrial *by
definition* -- those ports carry no general-purpose service -- so grading it as
an ordinary open service would understate exposure for precisely the assets this
work exists to find. Because Sentinel sends no protocol payloads it cannot
identify the vendor behind such a port, so promoting it above MEDIUM would not
be defensible either.

The refinement is explicit and switchable (``ot_exposure_is_industrial``) so the
evaluation can report results under both the literal base model and the refined
one, rather than burying a methodological choice in an ``if``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.models import Host, RiskEvidence, RiskLevel

# ---------------------------------------------------------------------------
# Remediation guidance
# ---------------------------------------------------------------------------

#: Control references: IEC 62443-3-3 system requirements and NIST SP 800-82r3
#: OT security guidance. Cited by identifier so a reader can verify the mapping.
_BASE_REMEDIATION: dict[RiskLevel, tuple[str, ...]] = {
    RiskLevel.CRITICAL: (
        "Remove the asset from direct Internet reachability now; place it behind "
        "a VPN or jump host (IEC 62443-3-3 SR 5.1 network segmentation).",
        "Treat the pre-authentication content disclosure as an incident: assume "
        "process data, topology, and tag names have been enumerated.",
        "Enable authentication on the HMI/controller web interface and rotate any "
        "factory-default accounts (NIST SP 800-82r3 s6.2.3).",
        "Review perimeter logs for prior unauthenticated access to this endpoint.",
    ),
    RiskLevel.HIGH: (
        "Remove direct Internet exposure; an authentication prompt is not a "
        "compensating control for an Internet-facing controller.",
        "Confirm the authentication boundary cannot be bypassed and that default "
        "accounts are disabled (IEC 62443-3-3 SR 1.1, SR 1.5).",
        "Apply vendor firmware updates for the identified product and subscribe "
        "to its advisory feed.",
        "Restrict source addresses to an allowlist at the perimeter firewall.",
    ),
    RiskLevel.MEDIUM: (
        "Confirm asset ownership and function, then decide whether Internet "
        "exposure is intentional.",
        "If the asset is industrial, migrate it behind the OT perimeter "
        "(NIST SP 800-82r3 s5.2 zone and conduit design).",
        "Reduce the information the service volunteers before authentication "
        "(product name, version, site identifiers).",
    ),
    RiskLevel.LOW: (
        "Verify the service is intended to be Internet-facing and is patched.",
        "Confirm it shares no network path with OT assets; if it does, treat the "
        "shared segment as the exposure.",
    ),
    RiskLevel.INFO: (
        "No actionable exposure identified. Retain the observation as a baseline "
        "for the next monitoring interval.",
    ),
}

#: Additional guidance keyed on specific evidence, appended to the base set.
_CONDITIONAL_REMEDIATION: tuple[tuple[str, str], ...] = (
    (
        "default_cred_risk",
        "This product family ships with documented default credentials. Verify "
        "they have been changed and that remote access is disabled where unused.",
    ),
    (
        "ot_protocol_exposed",
        "An industrial protocol port is reachable from the Internet. These "
        "protocols have no native authentication or integrity protection; "
        "exposure is equivalent to unauthenticated process control "
        "(MITRE ATT&CK for ICS T0886, T0855).",
    ),
)


@dataclass(slots=True)
class RiskAssessment:
    """A scored verdict with its justification."""

    level: RiskLevel
    rationale: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    refinement_applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.level.value,
            "severity": self.level.severity,
            "rationale": list(self.rationale),
            "remediation": list(self.remediation),
            "ot_refinement_applied": self.refinement_applied,
        }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score(
    evidence: RiskEvidence,
    ot_exposure_is_industrial: bool = True,
) -> RiskLevel:
    """Map an evidence vector to a risk level. Pure.

    ``pre_auth_disclosure`` and ``auth_wall`` can disagree if a caller builds the
    vector by hand; disclosure wins, because observed content outweighs an
    inferred boundary.
    """
    if evidence.ics_confirmed:
        disclosed = evidence.pre_auth_disclosure or not evidence.auth_wall
        return RiskLevel.CRITICAL if disclosed else RiskLevel.HIGH

    if evidence.generic_industrial:
        return RiskLevel.MEDIUM

    if ot_exposure_is_industrial and evidence.ot_protocol_exposed:
        return RiskLevel.MEDIUM

    if evidence.open_service:
        return RiskLevel.LOW

    return RiskLevel.INFO


def assess(
    evidence: RiskEvidence,
    ot_exposure_is_industrial: bool = True,
) -> RiskAssessment:
    """Score an evidence vector and explain the verdict."""
    level = score(evidence, ot_exposure_is_industrial)
    refinement = bool(
        level is RiskLevel.MEDIUM
        and ot_exposure_is_industrial
        and evidence.ot_protocol_exposed
        and not evidence.generic_industrial
        and not evidence.ics_confirmed
    )

    rationale = _explain(evidence, level, refinement)
    remediation = list(_BASE_REMEDIATION[level])
    for attribute, text in _CONDITIONAL_REMEDIATION:
        if getattr(evidence, attribute, False) and text not in remediation:
            remediation.append(text)
    if evidence.known_cves:
        remediation.append(
            f"{evidence.known_cves} published CVE reference(s) are associated with "
            "this product family; confirm the running firmware version against the "
            "vendor advisory before concluding it is unaffected."
        )

    return RiskAssessment(
        level=level,
        rationale=rationale,
        remediation=remediation,
        refinement_applied=refinement,
    )


def _explain(evidence: RiskEvidence, level: RiskLevel, refinement: bool) -> list[str]:
    """Human-readable justification, suitable for a disclosure email."""
    reasons: list[str] = []

    if evidence.ics_confirmed:
        reasons.append(
            f"Product identified as industrial control software with "
            f"{evidence.match_confidence:.0%} signature confidence."
        )
        if evidence.pre_auth_disclosure:
            reasons.append(
                "Operational content was served to an unauthenticated GET request: "
                "no authentication boundary is present."
            )
        elif evidence.auth_wall:
            reasons.append(
                "An authentication boundary is present, which limits but does not "
                "remove the exposure."
            )
    elif evidence.generic_industrial:
        reasons.append(
            "Industrial vocabulary was present (HMI/SCADA/BMS/DCS terminology) but "
            "no specific product could be identified, so this is treated as a "
            "candidate rather than a confirmation."
        )
    elif refinement:
        reasons.append(
            "An industrial protocol port is listening. The product could not be "
            "identified because Sentinel sends no protocol payloads, so the "
            "verdict rests on the port's exclusive industrial use."
        )
    elif evidence.open_service:
        reasons.append("A reachable service was observed with no industrial indicators.")
    else:
        reasons.append("No service responded and no indicators were observed.")

    if evidence.default_cred_risk:
        reasons.append("Product family is documented as shipping default credentials.")
    if evidence.known_cves:
        reasons.append(
            f"{evidence.known_cves} CVE reference(s) associated with the product family."
        )

    reasons.append(f"Assigned {level.value} (severity {level.severity}).")
    return reasons


# ---------------------------------------------------------------------------
# Host-level application
# ---------------------------------------------------------------------------


def apply_to_host(host: Host, ot_exposure_is_industrial: bool = True) -> Host:
    """Score a host in place from its own evidence vector.

    Evidence derivable from the port set alone is filled in here rather than in
    each collector. Both the active (masscan) and passive (dataset) paths
    produce port lists, and an open TCP/502 means the same thing whichever
    found it -- deriving it per-collector guarantees the two paths eventually
    disagree.
    """
    if host.ports:
        if not host.evidence.open_service:
            host.evidence.open_service = True
        if not host.evidence.ot_protocol_exposed:
            host.evidence.ot_protocol_exposed = any(
                _is_ot_port(p.port) for p in host.ports if p.state == "open"
            )

    assessment = assess(host.evidence, ot_exposure_is_industrial)
    host.risk = assessment.level
    host.remediation = assessment.remediation
    host.notes.extend(r for r in assessment.rationale if r not in host.notes)
    return host


def apply_to_hosts(hosts: list[Host], ot_exposure_is_industrial: bool = True) -> list[Host]:
    """Score every host, returning them ordered most-severe first.

    Deterministic ordering (severity, then confidence, then address) so that
    repeated runs over identical input produce byte-identical reports -- the
    property experiment E4 verifies.
    """
    for host in hosts:
        apply_to_host(host, ot_exposure_is_industrial)
    return sorted(
        hosts,
        key=lambda h: (-h.risk.severity, -h.confidence, _ip_key(h.ip)),
    )


def _is_ot_port(port: int) -> bool:
    """Whether a port is in the OT class.

    Imported lazily to keep this module free of configuration imports, so the
    scoring function stays trivially testable in isolation.
    """
    from sentinel.config.loader import classify_port
    from sentinel.models import PortClass

    return classify_port(port) is PortClass.OT


def _ip_key(ip: str) -> tuple[int, int]:
    import ipaddress

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0)
    return (address.version, int(address))


def histogram(hosts: list[Host]) -> dict[str, int]:
    """Count hosts per risk level, always including every level."""
    counts = {level.value: 0 for level in RiskLevel}
    for host in hosts:
        counts[host.risk.value] += 1
    return counts
