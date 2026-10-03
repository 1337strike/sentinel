"""Active port discovery via a masscan subprocess.

This is the only module in Sentinel that emits packets to targets, and it is
unreachable without an :class:`~sentinel.modules.scope.ActiveGrant`
grant. The grant is the first positional parameter of every public function
here, so there is no call path that skips the scope check.

masscan is an external dependency on purpose. Bundling or reimplementing a
stateless SYN scanner would mean owning the packet-rate logic that protects
fragile OT devices; delegating to a well-understood tool, with the rate clamped
on our side, is the safer engineering choice. ``docs/REPRODUCE.md`` pins the
version used for the published measurements.

Safety controls applied here, beyond the scope grant:

* **Rate clamp.** ``--max-rate`` is set from
  :meth:`~sentinel.config.loader.SentinelConfig.clamp_rate`, so a mixed
  web+OT target set is paced at the OT budget. The CLI can lower it, never
  raise it.
* **Process-level exclusions.** ``--excludefile`` carries the permanent
  denylist even though every target was already validated. Defence in depth
  against a future scope bug.
* **Argument allowlisting.** Operator-supplied extra arguments cannot override
  targets, ports, rate, or exclusions.
* **No banner payloads on OT ports.** masscan's ``--banners`` writes
  protocol-specific probe data to elicit a response. Sentinel refuses it when
  any OT port is in range: application-layer probing of industrial protocols is
  exactly the activity that has been documented to fault legacy controllers.
  Banner collection happens instead in :mod:`sentinel.modules.fingerprint`,
  which only ever *listens* on OT ports.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.config.loader import SentinelConfig, classify_port
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import Host, PortClass, PortState, utc_now_iso
from sentinel.modules.scope import ActiveGrant, ScopeViolation, require_active

_log = get_logger("scanner")


class ScannerError(RuntimeError):
    """masscan is missing, misconfigured, or failed."""


class ScannerUnavailable(ScannerError):
    """The masscan binary is not installed or not executable."""


#: Option prefixes an operator may not pass through ``scanner.extra_args``.
#: Each would subvert a safety control above.
_FORBIDDEN_EXTRA_ARGS: tuple[str, ...] = (
    "-p",
    "--ports",
    "--rate",
    "--max-rate",
    "--exclude",
    "--excludefile",
    "--include",
    "--includefile",
    "-iL",
    "-oJ",
    "-oX",
    "-oG",
    "-oL",
    "--output-file",
    "--output-format",
    "--range",
    "--ranges",
    "--banners",
    "--capture",
    "--nmap",
    "--shell",
    "--resume",
    "--conf",
    "--config",
    "--adapter-ip",
    "--source-ip",
    "--spoof-ip",
    "--router-mac",
    "--adapter-mac",
)


@dataclass(slots=True)
class ScanOutcome:
    """Result of an active scan pass."""

    hosts: list[Host] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    effective_rate: int = 0
    governing_class: str = PortClass.OT.value
    rate_clamped: bool = False
    duration_seconds: float = 0.0
    command: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    dry_run: bool = False
    rejected: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_count": len(self.hosts),
            "open_port_count": sum(len(h.ports) for h in self.hosts),
            "ports_scanned": list(self.ports),
            "target_count": len(self.targets),
            "effective_rate_pps": self.effective_rate,
            "governing_port_class": self.governing_class,
            "rate_clamped": self.rate_clamped,
            "duration_seconds": round(self.duration_seconds, 3),
            "dry_run": self.dry_run,
            "rejected": [{"target": t, "reason": r} for t, r in self.rejected],
            # The command is recorded without the target list so the audit entry
            # stays bounded; targets are identified by the scope hash instead.
            "command": [c for c in self.command if not c.startswith("/")],
        }


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def masscan_path(config: SentinelConfig) -> str:
    """Locate the masscan binary, or raise :class:`ScannerUnavailable`."""
    binary = config.scanner.binary
    resolved = shutil.which(binary)
    if not resolved:
        raise ScannerUnavailable(
            f"masscan binary {binary!r} not found on PATH. Install it "
            "(Debian/Ubuntu: 'apt install masscan'; Arch: 'pacman -S masscan') "
            "or run in --dry-run mode. masscan is an intentional external "
            "dependency and is not bundled."
        )
    return resolved


def masscan_version(config: SentinelConfig) -> str | None:
    """Return the masscan version string, for the audit record."""
    try:
        resolved = masscan_path(config)
    except ScannerUnavailable:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (proc.stdout or proc.stderr or "").splitlines():
        if "masscan" in line.lower():
            return line.strip()
    return None


def has_raw_socket_capability() -> bool:
    """Whether this process can plausibly open the raw sockets masscan needs.

    Checked up front so the failure is a clear message rather than an opaque
    permission error after the operator has already authorised a scan.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    # A non-root masscan works when granted CAP_NET_RAW; we cannot read
    # capabilities portably, so treat it as possible and let masscan decide.
    return True


def validate_extra_args(extra: Iterable[str]) -> list[str]:
    """Reject operator arguments that would defeat a safety control."""
    cleaned: list[str] = []
    for raw in extra:
        arg = str(raw).strip()
        if not arg:
            continue
        head = arg.split("=", 1)[0]
        if head in _FORBIDDEN_EXTRA_ARGS:
            raise ScannerError(
                f"scanner.extra_args may not contain {head!r}: it would override "
                "a Sentinel safety control (targets, ports, rate, exclusions, or "
                "output). Change the config field instead."
            )
        cleaned.append(arg)
    return cleaned


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def run_masscan(
    grant: ActiveGrant,
    targets: list[str],
    ports: list[int],
    config: SentinelConfig,
    requested_rate: int | None = None,
    dry_run: bool = False,
    fixture: str | Path | None = None,
) -> ScanOutcome:
    """Run masscan against ``targets``, under the authority of ``grant``.

    ``grant`` is first and required: an unauthorised caller cannot reach this
    code, because it cannot construct the type.
    """
    import time

    auth = require_active(grant, "active port scan")

    if not ports:
        raise ScannerError("no ports to scan")

    authorized, rejected = auth.filter_targets(targets)
    for target, reason in rejected:
        log_event(_log, "target_rejected", f"refusing target: {reason}", target=target, level=30)
    if not authorized:
        raise ScopeViolation(
            "no target survived scope validation; nothing will be scanned. "
            f"Rejections: {rejected}"
        )

    effective_rate, port_class, clamped = config.clamp_rate(requested_rate, ports)
    if clamped:
        log_event(
            _log,
            "rate_clamped",
            f"requested {requested_rate} pps lowered to {effective_rate} pps "
            f"({port_class.value} ceiling)",
            requested_rate=requested_rate,
            effective_rate=effective_rate,
            port_class=port_class.value,
            level=30,
        )

    ot_ports = [p for p in ports if classify_port(p) is PortClass.OT]
    if config.scanner.banners and ot_ports:
        raise ScannerError(
            "scanner.banners is enabled but the port set includes OT ports "
            f"{ot_ports}. masscan banner grabbing writes protocol probe data, "
            "which can fault legacy controllers. Collect banners with the "
            "fingerprint stage instead -- it only listens on OT ports."
        )

    outcome = ScanOutcome(
        ports=list(ports),
        targets=authorized,
        effective_rate=effective_rate,
        governing_class=port_class.value,
        rate_clamped=clamped,
        dry_run=dry_run,
        rejected=rejected,
    )

    if dry_run:
        outcome.hosts = _load_fixture_hosts(fixture, authorized, ports)
        outcome.command = ["<dry-run>", "masscan", "(not executed)"]
        log_event(
            _log,
            "scan_dry_run",
            f"dry-run produced {len(outcome.hosts)} host(s) from fixture data",
            run_scope_hash=auth.hash,
            host_count=len(outcome.hosts),
        )
        return outcome

    resolved = masscan_path(config)

    with tempfile.TemporaryDirectory(prefix="sentinel-scan-") as tmpdir:
        tmp = Path(tmpdir)
        exclude_file = tmp / "exclude.conf"
        exclude_file.write_text("\n".join(auth.exclude_file_lines()) + "\n", encoding="utf-8")
        target_file = tmp / "targets.conf"
        target_file.write_text("\n".join(authorized) + "\n", encoding="utf-8")
        out_file = tmp / "masscan.json"

        argv = [
            resolved,
            "-p",
            ",".join(str(p) for p in ports),
            "--max-rate",
            str(effective_rate),
            "--wait",
            str(config.scanner.wait_seconds),
            "--excludefile",
            str(exclude_file),
            "-iL",
            str(target_file),
            "-oJ",
            str(out_file),
        ]
        argv.extend(validate_extra_args(config.scanner.extra_args))
        outcome.command = argv

        log_event(
            _log,
            "scan_start",
            f"masscan starting: {len(authorized)} range(s), {len(ports)} port(s), "
            f"{effective_rate} pps",
            run_scope_hash=auth.hash,
            effective_rate=effective_rate,
            port_class=port_class.value,
            target_count=len(authorized),
        )

        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 -- fixed argv list, shell=False
                argv,
                capture_output=True,
                text=True,
                timeout=config.timeouts.subprocess,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"masscan exceeded the {config.timeouts.subprocess}s subprocess timeout"
            ) from exc
        except OSError as exc:
            raise ScannerError(f"could not execute masscan: {exc}") from exc
        outcome.duration_seconds = time.monotonic() - started

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            if "permission" in stderr.lower() or "operation not permitted" in stderr.lower():
                raise ScannerError(
                    "masscan needs raw socket access. Run as root, or grant the "
                    f"binary CAP_NET_RAW: setcap cap_net_raw+ep {resolved}. "
                    f"masscan said: {stderr[:400]}"
                )
            raise ScannerError(f"masscan exited {proc.returncode}: {stderr[:800]}")

        outcome.hosts = parse_masscan_json(
            out_file.read_text(encoding="utf-8") if out_file.is_file() else ""
        )

    log_event(
        _log,
        "scan_complete",
        f"masscan found {len(outcome.hosts)} responsive host(s) in "
        f"{outcome.duration_seconds:.1f}s",
        run_scope_hash=auth.hash,
        host_count=len(outcome.hosts),
        duration_seconds=round(outcome.duration_seconds, 3),
    )
    return outcome


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def parse_masscan_json(text: str) -> list[Host]:
    """Parse masscan's ``-oJ`` output into :class:`Host` records.

    masscan emits a JSON array with a trailing comma before the closing bracket,
    which is not valid JSON, so a strict parse is tried first and a tolerant
    line-oriented parse is used as a fallback. Records for the same address are
    merged, because masscan reports one record per open port.
    """
    if not text.strip():
        return []

    records: list[dict[str, Any]] = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            records = [r for r in parsed if isinstance(r, dict)]
    except json.JSONDecodeError:
        for line in text.splitlines():
            candidate = line.strip().rstrip(",")
            if not candidate.startswith("{") or not candidate.endswith("}"):
                continue
            try:
                record = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)

    merged: dict[str, Host] = {}
    for record in records:
        ip = str(record.get("ip", "")).strip()
        if not ip:
            continue
        host = merged.setdefault(ip, Host(ip=ip, source="masscan"))
        for entry in record.get("ports") or []:
            if not isinstance(entry, dict):
                continue
            try:
                port = int(entry.get("port"))
            except (TypeError, ValueError):
                continue
            state = str(entry.get("status") or entry.get("state") or "open")
            proto = str(entry.get("proto") or "tcp")
            if not any(p.port == port and p.proto == proto for p in host.ports):
                host.ports.append(PortState(port=port, state=state, proto=proto))

    for host in merged.values():
        host.ports.sort(key=lambda p: (p.proto, p.port))

    return [merged[ip] for ip in sorted(merged, key=_ip_sort_key)]


def _ip_sort_key(ip: str) -> tuple[int, int]:
    import ipaddress

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0)
    return (address.version, int(address))


def _load_fixture_hosts(
    fixture: str | Path | None,
    targets: list[str],
    ports: list[int],
) -> list[Host]:
    """Serve scan results from a fixture for ``--dry-run``.

    Without a fixture, synthesises nothing: an empty result is honest, whereas
    inventing hosts would silently corrupt an experiment that forgot to stage
    its seed data.
    """
    if fixture is None:
        log_event(
            _log,
            "fixture_absent",
            "dry-run with no scan fixture; returning an empty host set",
            level=30,
            target_count=len(targets),
            port_count=len(ports),
        )
        return []

    path = Path(fixture)
    if not path.is_file():
        raise ScannerError(f"dry-run scan fixture not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return parse_masscan_json(text)

    # Accept either a raw masscan array or a Sentinel ScanResult envelope.
    if isinstance(payload, dict) and "hosts" in payload:
        return [Host.from_dict(h) for h in payload["hosts"]]
    return parse_masscan_json(text)


# ---------------------------------------------------------------------------
# Optional nmap verification
# ---------------------------------------------------------------------------


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def verify_with_nmap(
    grant: ActiveGrant,
    ip: str,
    ports: list[int],
    config: SentinelConfig,
) -> dict[int, str]:
    """Optional service-version confirmation for a single authorized host.

    Used only to establish ground truth in the lab (experiment E1), never as a
    discovery mechanism. ``-sV`` with ``--version-intensity 2`` is deliberately
    light; no NSE scripts are run, because the default script set includes
    probes that are inappropriate for industrial endpoints.
    """
    auth = require_active(grant, "nmap service verification")
    auth.assert_in_scope(ip)

    if not nmap_available():
        raise ScannerUnavailable("nmap not found on PATH; install it or skip verification")
    if not ports:
        return {}

    rate, _, _ = config.clamp_rate(None, ports)
    argv = [
        shutil.which("nmap") or "nmap",
        "-Pn",
        "-sV",
        "--version-intensity",
        "2",
        "--script-timeout",
        "30s",
        "--max-rate",
        str(rate),
        "-p",
        ",".join(str(p) for p in sorted(set(ports))),
        "-oG",
        "-",
        ip,
    ]
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, shell=False
            argv,
            capture_output=True,
            text=True,
            timeout=min(600.0, config.timeouts.subprocess),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScannerError(f"nmap execution failed: {exc}") from exc

    services: dict[int, str] = {}
    for line in (proc.stdout or "").splitlines():
        if "Ports:" not in line:
            continue
        _, _, ports_blob = line.partition("Ports:")
        for item in ports_blob.split(","):
            fields = [f.strip() for f in item.split("/")]
            if len(fields) < 5 or fields[1] != "open":
                continue
            try:
                port = int(fields[0])
            except ValueError:
                continue
            services[port] = "/".join(f for f in fields[4:] if f)

    log_event(
        _log,
        "nmap_verify",
        f"nmap identified {len(services)} service(s)",
        target=ip,
        service_count=len(services),
    )
    return services
