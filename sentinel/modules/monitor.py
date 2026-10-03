"""Continuous monitoring: run-to-run differencing and alerting.

The paper's title claim is *continuous* exposure monitoring, and this module is
what makes it continuous rather than a one-shot census. A single scan tells you
an asset is exposed; a diff tells you it *became* exposed, which is the signal a
defender can act on.

Alert severity is asymmetric by design. A newly-open OT port or a removed
authentication boundary is a regression and is graded on the risk it creates. A
closed port or a reduced risk level is recorded at INFO: improvements belong in
the audit trail, not in an alert queue, and grading them equally would train
operators to ignore the feed.

Nothing here sends anything outbound. Alerts are written to disk and returned to
the caller. Sentinel has no webhook, no mail relay, and no chat integration --
each would be a place for exposure data about third-party assets to leak, and
none can be configured without the credentials this tool refuses to hold.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel.config.loader import classify_port
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import (
    Alert,
    AlertKind,
    DiffReport,
    Host,
    PortClass,
    RiskLevel,
    ScanResult,
    utc_now_iso,
)

_log = get_logger("monitor")

#: Base severity per change class. Regressions are graded from the host's own
#: risk; improvements are fixed at INFO.
_SEVERITY: dict[AlertKind, RiskLevel] = {
    AlertKind.NEW_HOST: RiskLevel.MEDIUM,
    AlertKind.REMOVED_HOST: RiskLevel.INFO,
    AlertKind.NEW_PORT: RiskLevel.MEDIUM,
    AlertKind.CLOSED_PORT: RiskLevel.INFO,
    AlertKind.BANNER_CHANGE: RiskLevel.LOW,
    AlertKind.VERSION_CHANGE: RiskLevel.MEDIUM,
    AlertKind.VENDOR_CHANGE: RiskLevel.MEDIUM,
    AlertKind.RISK_ESCALATION: RiskLevel.HIGH,
    AlertKind.RISK_REDUCTION: RiskLevel.INFO,
    AlertKind.AUTH_WALL_REMOVED: RiskLevel.CRITICAL,
}


class MonitorError(RuntimeError):
    """Monitor configuration or state is unusable."""


# ---------------------------------------------------------------------------
# Differencing
# ---------------------------------------------------------------------------


def diff_runs(baseline: ScanResult, current: ScanResult) -> DiffReport:
    """Compute the change set between two runs.

    Deterministic: alerts are emitted in a stable order (address, then change
    class) so that two diffs of the same pair of runs are byte-identical, which
    experiment E4 asserts.
    """
    before = baseline.host_index()
    after = current.host_index()
    alerts: list[Alert] = []

    for ip in sorted(set(after) - set(before), key=_ip_key):
        host = after[ip]
        alerts.append(
            Alert(
                kind=AlertKind.NEW_HOST,
                ip=ip,
                severity=_max_severity(_SEVERITY[AlertKind.NEW_HOST], host.risk),
                message=(
                    f"New host observed with {len(host.open_ports)} open port(s); "
                    f"risk {host.risk.value}" + (f", vendor {host.vendor}" if host.vendor else "")
                ),
                after={"ports": host.open_ports, "risk": host.risk.value, "vendor": host.vendor},
            )
        )

    for ip in sorted(set(before) - set(after), key=_ip_key):
        host = before[ip]
        alerts.append(
            Alert(
                kind=AlertKind.REMOVED_HOST,
                ip=ip,
                severity=_SEVERITY[AlertKind.REMOVED_HOST],
                message="Host no longer responds; exposure appears to be remediated",
                before={"ports": host.open_ports, "risk": host.risk.value},
            )
        )

    for ip in sorted(set(before) & set(after), key=_ip_key):
        alerts.extend(_diff_host(before[ip], after[ip]))

    report = DiffReport(
        baseline_time=baseline.scan_time,
        current_time=current.scan_time,
        alerts=alerts,
    )
    log_event(
        _log,
        "diff_complete",
        f"{len(alerts)} change(s) between {baseline.scan_time} and {current.scan_time}",
        alert_count=len(alerts),
        max_severity=report.max_severity.value,
        by_kind=report.by_kind(),
    )
    return report


def _diff_host(before: Host, after: Host) -> list[Alert]:
    """Changes within a single host that is present in both runs."""
    alerts: list[Alert] = []
    ip = after.ip

    old_ports, new_ports = set(before.open_ports), set(after.open_ports)

    for port in sorted(new_ports - old_ports):
        is_ot = classify_port(port) is PortClass.OT
        alerts.append(
            Alert(
                kind=AlertKind.NEW_PORT,
                ip=ip,
                severity=RiskLevel.HIGH if is_ot else _SEVERITY[AlertKind.NEW_PORT],
                message=(
                    f"Port {port}/tcp is newly open"
                    + (
                        " -- this is an industrial protocol port, which carries no "
                        "native authentication"
                        if is_ot
                        else ""
                    )
                ),
                before=sorted(old_ports),
                after=sorted(new_ports),
            )
        )

    for port in sorted(old_ports - new_ports):
        alerts.append(
            Alert(
                kind=AlertKind.CLOSED_PORT,
                ip=ip,
                severity=_SEVERITY[AlertKind.CLOSED_PORT],
                message=f"Port {port}/tcp is no longer open",
                before=sorted(old_ports),
                after=sorted(new_ports),
            )
        )

    if before.auth_wall and not after.auth_wall:
        alerts.append(
            Alert(
                kind=AlertKind.AUTH_WALL_REMOVED,
                ip=ip,
                severity=_SEVERITY[AlertKind.AUTH_WALL_REMOVED],
                message=(
                    "The authentication boundary that was previously present is "
                    "gone; the interface now answers anonymous requests"
                ),
                before=True,
                after=False,
            )
        )

    if before.vendor != after.vendor and after.vendor:
        alerts.append(
            Alert(
                kind=AlertKind.VENDOR_CHANGE,
                ip=ip,
                severity=_SEVERITY[AlertKind.VENDOR_CHANGE],
                message=f"Identified product changed: {before.vendor or 'unknown'} -> {after.vendor}",
                before=before.vendor,
                after=after.vendor,
            )
        )

    if before.product_version != after.product_version and after.product_version:
        alerts.append(
            Alert(
                kind=AlertKind.VERSION_CHANGE,
                ip=ip,
                severity=_SEVERITY[AlertKind.VERSION_CHANGE],
                message=(
                    f"Product version changed: {before.product_version or 'unknown'} "
                    f"-> {after.product_version}"
                ),
                before=before.product_version,
                after=after.product_version,
            )
        )

    if _normalise_banner(before.banner) != _normalise_banner(after.banner):
        alerts.append(
            Alert(
                kind=AlertKind.BANNER_CHANGE,
                ip=ip,
                severity=_SEVERITY[AlertKind.BANNER_CHANGE],
                message="Service banner changed; the host may have been updated or replaced",
                before=before.banner,
                after=after.banner,
            )
        )

    if after.risk.severity > before.risk.severity:
        alerts.append(
            Alert(
                kind=AlertKind.RISK_ESCALATION,
                ip=ip,
                severity=after.risk,
                message=f"Risk escalated {before.risk.value} -> {after.risk.value}",
                before=before.risk.value,
                after=after.risk.value,
            )
        )
    elif after.risk.severity < before.risk.severity:
        alerts.append(
            Alert(
                kind=AlertKind.RISK_REDUCTION,
                ip=ip,
                severity=_SEVERITY[AlertKind.RISK_REDUCTION],
                message=f"Risk reduced {before.risk.value} -> {after.risk.value}",
                before=before.risk.value,
                after=after.risk.value,
            )
        )

    return alerts


def _normalise_banner(banner: str | None) -> str:
    """Collapse whitespace so cosmetic differences are not alerts."""
    if not banner:
        return ""
    return " ".join(banner.split())


def _max_severity(base: RiskLevel, host_risk: RiskLevel) -> RiskLevel:
    return base if base.severity >= host_risk.severity else host_risk


def _ip_key(ip: str) -> tuple[int, int]:
    import ipaddress

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0)
    return (address.version, int(address))


# ---------------------------------------------------------------------------
# Run storage
# ---------------------------------------------------------------------------


def load_run(path: str | Path) -> ScanResult:
    """Load a persisted run."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise MonitorError(f"run file not found: {file_path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MonitorError(f"{file_path} is not valid JSON: {exc}") from exc
    return ScanResult.from_dict(payload)


def save_run(result: ScanResult, path: str | Path) -> Path:
    """Persist a run with stable key ordering, for reproducible diffs."""
    file_path = Path(path).expanduser()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return file_path


def list_runs(runs_dir: str | Path) -> list[Path]:
    """Every stored run, oldest first.

    Ordered by the ISO timestamp embedded in the filename, which sorts
    lexicographically -- so ordering does not depend on filesystem mtime, which
    a VM snapshot restore would scramble.
    """
    directory = Path(runs_dir).expanduser()
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("run-*.json") if p.is_file())


def run_filename(result: ScanResult) -> str:
    stamp = result.scan_time.replace(":", "").replace("-", "")
    return f"run-{stamp}.json"


def latest_pair(runs_dir: str | Path) -> tuple[Path, Path] | None:
    """The two most recent runs, as ``(baseline, current)``."""
    runs = list_runs(runs_dir)
    if len(runs) < 2:
        return None
    return runs[-2], runs[-1]


# ---------------------------------------------------------------------------
# Monitor configuration
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MonitorConfig:
    """Parsed ``monitor.yaml``."""

    asn: str | None = None
    cidr_file: str | None = None
    ports: str = "ics"
    mode: str = "passive"
    scope_file: str | None = None
    runs_dir: Path = Path("out/runs")
    alerts_dir: Path = Path("out/alerts")
    rate: int | None = None
    #: Minimum severity that is written to the alert file.
    min_severity: RiskLevel = RiskLevel.LOW
    dry_run: bool = False
    expand_hosts: bool = False

    @classmethod
    def load(cls, path: str | Path) -> MonitorConfig:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            raise MonitorError(f"monitor config not found: {file_path}")
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise MonitorError(f"{file_path} is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise MonitorError(f"{file_path} must be a YAML mapping")

        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise MonitorError(f"unknown key(s) in {file_path}: {', '.join(sorted(unknown))}")

        if not raw.get("asn") and not raw.get("cidr_file"):
            raise MonitorError(f"{file_path} must set either 'asn' or 'cidr_file'")

        kwargs: dict[str, Any] = dict(raw)
        for key in ("runs_dir", "alerts_dir"):
            if key in kwargs:
                kwargs[key] = Path(str(kwargs[key])).expanduser()
        if "min_severity" in kwargs:
            kwargs["min_severity"] = RiskLevel(str(kwargs["min_severity"]).upper())
        return cls(**kwargs)


@dataclass(slots=True)
class MonitorCycle:
    """Outcome of one monitoring iteration."""

    index: int
    run_path: Path | None = None
    diff: DiffReport | None = None
    alerts_path: Path | None = None
    baseline_path: Path | None = None
    error: str | None = None
    started_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "started_at": self.started_at,
            "run": str(self.run_path) if self.run_path else None,
            "baseline": str(self.baseline_path) if self.baseline_path else None,
            "alerts_file": str(self.alerts_path) if self.alerts_path else None,
            "alert_count": len(self.diff.alerts) if self.diff else 0,
            "max_severity": self.diff.max_severity.value if self.diff else None,
            "error": self.error,
        }


def filter_alerts(report: DiffReport, min_severity: RiskLevel) -> DiffReport:
    """Drop alerts below ``min_severity``, preserving order."""
    return DiffReport(
        baseline_time=report.baseline_time,
        current_time=report.current_time,
        alerts=[a for a in report.alerts if a.severity.severity >= min_severity.severity],
    )


def write_alerts(report: DiffReport, alerts_dir: str | Path) -> Path:
    """Persist a diff report as JSON."""
    directory = Path(alerts_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = report.current_time.replace(":", "").replace("-", "")
    path = directory / f"alerts-{stamp}.json"
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_event(
        _log,
        "alerts_written",
        f"{len(report.alerts)} alert(s) written to {path}",
        alerts_file=str(path),
        alert_count=len(report.alerts),
    )
    return path


def diff_against_previous(
    current: ScanResult,
    runs_dir: str | Path,
) -> tuple[DiffReport | None, Path | None]:
    """Diff ``current`` against the most recent stored run, if there is one."""
    runs = list_runs(runs_dir)
    if not runs:
        log_event(
            _log,
            "baseline_established",
            "no previous run found; this run becomes the baseline",
        )
        return None, None
    baseline_path = runs[-1]
    baseline = load_run(baseline_path)
    return diff_runs(baseline, current), baseline_path


def sleep_until_next(interval_seconds: float, elapsed: float) -> float:
    """Seconds to sleep so cycles start on a fixed cadence.

    Subtracting the elapsed time keeps the interval meaningful when a cycle
    takes a non-trivial fraction of it; without this, a slow cycle silently
    stretches the monitoring period and the time axis of any longitudinal
    result becomes uneven.
    """
    return max(0.0, float(interval_seconds) - max(0.0, elapsed))


def wait(seconds: float) -> None:  # pragma: no cover -- trivial, patched in tests
    if seconds > 0:
        time.sleep(seconds)


def summarise_cycles(cycles: Iterable[MonitorCycle]) -> dict[str, Any]:
    """Aggregate a monitoring session for the audit log."""
    items = list(cycles)
    total_alerts = sum(len(c.diff.alerts) for c in items if c.diff)
    worst = RiskLevel.INFO
    for cycle in items:
        if cycle.diff and cycle.diff.max_severity.severity > worst.severity:
            worst = cycle.diff.max_severity
    return {
        "cycles": len(items),
        "failed_cycles": sum(1 for c in items if c.error),
        "total_alerts": total_alerts,
        "max_severity": worst.value,
        "detail": [c.to_dict() for c in items],
    }
