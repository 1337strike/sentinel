"""Command-line interface.

Exit codes are meaningful, because a refusal and a failure must be
distinguishable by a CI job or a cron wrapper:

====  =========================================================
Code  Meaning
====  =========================================================
0     Success
1     Runtime error (dataset unreachable, bad input, tool missing)
2     **Refusal**: scope violation or missing active authorization
3     **Refusal**: credential policy violation
4     Interrupted by the operator
====  =========================================================

A code of 2 or 3 means Sentinel declined to do something, not that it broke.
Collapsing those into a generic failure would let a scheduled job retry its way
past a safety control.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from sentinel import __version__, credguard
from sentinel.config.loader import PORT_PRESETS, SentinelConfig, load_config
from sentinel.credguard import CredentialPolicyViolation
from sentinel.http_client import DatasetUnavailable, HttpClient
from sentinel.logging_setup import configure_logging, get_logger, log_event
from sentinel.models import Host, RiskLevel, ScanMode, ScanResult, utc_now_iso
from sentinel.modules import discovery, enrich, fingerprint, monitor, report, rir, risk, scanner
from sentinel.modules.audit import AuditLog, verify_chain
from sentinel.modules.scope import (
    ActiveGrant,
    ModeViolation,
    ScopeDecision,
    ScopeError,
    ScopeViolation,
    read_cidr_file,
    scope_hash,
)

_log = get_logger("cli")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED_SCOPE = 2
EXIT_REFUSED_POLICY = 3
EXIT_INTERRUPTED = 4

# Console writes to stderr so stdout stays a clean machine-readable channel.
_console = Console(stderr=True, highlight=False)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _common_parent(include_config: bool = True) -> argparse.ArgumentParser:
    """Shared options for every subcommand.

    ``include_config`` exists because ``monitor`` spells its own ``--config`` as
    the monitor definition file. That subcommand therefore opts out of the
    global flag and exposes the runtime config as ``--sentinel-config``, keeping
    the documented ``sentinel monitor --config monitor.yaml`` invocation intact.
    """
    parent = argparse.ArgumentParser(add_help=False)
    if include_config:
        parent.add_argument("--config", metavar="PATH", help="YAML config file")
    parent.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="structured log verbosity",
    )
    parent.add_argument("--log-file", metavar="PATH", help="write JSON logs here as well")
    parent.add_argument("--audit-log", metavar="PATH", help="append-only audit log path")
    parent.add_argument("--quiet", action="store_true", help="suppress log output on stderr")
    parent.add_argument(
        "--dry-run",
        action="store_true",
        help="serve every external call from fixture data; emits no network traffic",
    )
    parent.add_argument(
        "--fixture-dir",
        metavar="DIR",
        default="labs/seed",
        help="fixture root used by --dry-run (default: labs/seed)",
    )
    parent.add_argument(
        "--seed",
        type=int,
        default=None,
        help="seed the jitter source so retry timing is reproducible",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    parent = _common_parent()
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=(
            "Defensive exposure monitoring for Internet-facing ICS/SCADA assets. "
            "Passive by default: no packets are sent to any target unless both "
            "--active and --scope-file are supplied. Requires no API keys, "
            "accounts, or registration of any kind."
        ),
        epilog=(
            "Active scanning is limited to ranges you are authorized to test. "
            "See docs/ETHICS.md before using --active."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # -- scan ---------------------------------------------------------------
    scan = subparsers.add_parser(
        "scan",
        parents=[parent],
        help="discover hosts and open ports (passive by default)",
        description=(
            "PASSIVE (default): resolve an ASN to prefixes via RIPEstat and read "
            "per-address port data from Shodan InternetDB. No packets to targets. "
            "ACTIVE (--active --scope-file): measure directly with masscan."
        ),
    )
    target = scan.add_mutually_exclusive_group(required=True)
    target.add_argument("--asn", metavar="ASxxxxx", help="target autonomous system")
    target.add_argument("--cidr-file", metavar="PATH", help="newline-delimited CIDR list")
    scan.add_argument(
        "--ports",
        default="ics",
        metavar="SPEC",
        help=f"preset ({', '.join(sorted(PORT_PRESETS))}) or list like 80,443,8000-8010",
    )
    scan.add_argument("--rate", type=int, default=None, help="requested packets/sec (clamped)")
    scan.add_argument("--output", "-o", metavar="PATH", help="write the run JSON here")
    scan.add_argument(
        "--active",
        action="store_true",
        help="emit packets to targets; requires --scope-file",
    )
    scan.add_argument(
        "--scope-file",
        metavar="PATH",
        help="YAML file listing authorized CIDRs; mandatory with --active",
    )
    scan.add_argument(
        "--expand",
        action="store_true",
        help="expand prefixes to addresses for per-host passive lookup (capped)",
    )
    scan.add_argument(
        "--force-expand",
        action="store_true",
        help="allow expanding prefixes broader than the configured floor",
    )
    scan.add_argument(
        "--scan-fixture",
        metavar="PATH",
        help="masscan result fixture used by --dry-run --active",
    )
    scan.set_defaults(func=cmd_scan)

    # -- fingerprint --------------------------------------------------------
    fp = subparsers.add_parser(
        "fingerprint",
        parents=[parent],
        help="banner-grab and match ICS signatures",
        description=(
            "GET-only, unauthenticated HTTP/TLS probing plus listen-only TCP "
            "connections on industrial ports. No protocol payloads are written "
            "and no credentials are ever submitted."
        ),
    )
    fp.add_argument("--input", "-i", required=True, metavar="PATH", help="scan JSON")
    fp.add_argument("--output", "-o", metavar="PATH", help="write fingerprint JSON here")
    fp.add_argument("--threads", type=int, default=None, help="concurrent probes")
    fp.add_argument("--rate", type=int, default=None, help="requested probes/sec (clamped)")
    fp.add_argument("--signatures", metavar="PATH", help="signature database")
    fp.add_argument(
        "--confirm-threshold",
        type=float,
        default=None,
        help="match score at which a product counts as confirmed (ROC sweeps use this)",
    )
    fp.set_defaults(func=cmd_fingerprint)

    # -- enrich -------------------------------------------------------------
    en = subparsers.add_parser(
        "enrich",
        parents=[parent],
        help="add reverse DNS, InternetDB, WHOIS/RDAP, and RIR country data",
    )
    en.add_argument("--input", "-i", required=True, metavar="PATH")
    en.add_argument("--output", "-o", metavar="PATH")
    en.add_argument("--no-reverse-dns", action="store_true", help="skip PTR lookups")
    en.add_argument("--no-internetdb", action="store_true", help="skip Shodan InternetDB")
    en.add_argument("--no-org", action="store_true", help="skip WHOIS/RDAP attribution")
    en.add_argument(
        "--registries",
        metavar="LIST",
        default=None,
        help="comma-separated RIRs for delegation data (default: all five)",
    )
    en.add_argument(
        "--no-delegation",
        action="store_true",
        help="skip RIR delegation download; country attribution will be null",
    )
    en.set_defaults(func=cmd_enrich)

    # -- report -------------------------------------------------------------
    rp = subparsers.add_parser("report", parents=[parent], help="render a report")
    rp.add_argument("--input", "-i", required=True, metavar="PATH")
    rp.add_argument("--output", "-o", metavar="PATH")
    rp.add_argument(
        "--format",
        "-f",
        default="markdown",
        choices=list(report.FORMATS),
        help="output format (default: markdown)",
    )
    rp.add_argument(
        "--diff-against",
        metavar="PATH",
        help="also render changes relative to this earlier run",
    )
    rp.set_defaults(func=cmd_report)

    # -- monitor ------------------------------------------------------------
    mon = subparsers.add_parser(
        "monitor",
        parents=[_common_parent(include_config=False)],
        help="run the pipeline on a schedule and alert on changes",
    )
    mon.add_argument(
        "--config",
        dest="monitor_config",
        required=True,
        metavar="PATH",
        help="monitor definition (monitor.yaml)",
    )
    mon.add_argument(
        "--sentinel-config",
        dest="config",
        metavar="PATH",
        help="runtime config (sentinel.yaml); here --config is the monitor definition",
    )
    mon.add_argument("--interval", type=float, default=86400.0, help="seconds between cycles")
    mon.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="number of cycles (0 = run until interrupted)",
    )
    mon.add_argument("--once", action="store_true", help="shorthand for --iterations 1")
    mon.add_argument("--signatures", metavar="PATH", help="signature database")
    mon.set_defaults(func=cmd_monitor)

    # -- auxiliary ----------------------------------------------------------
    va = subparsers.add_parser(
        "verify-audit", parents=[parent], help="verify the audit log hash chain"
    )
    va.add_argument("--path", metavar="PATH", help="audit log (default: from config)")
    va.set_defaults(func=cmd_verify_audit)

    cs = subparsers.add_parser(
        "check-scope",
        parents=[parent],
        help="validate a scope file and test targets against it without scanning",
    )
    cs.add_argument("--scope-file", required=True, metavar="PATH")
    cs.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="CIDR",
        help="repeatable; test whether this target is authorized",
    )
    cs.set_defaults(func=cmd_check_scope)

    cr = subparsers.add_parser(
        "credentials",
        parents=[parent],
        help="print the credential policy and every endpoint the tool may contact",
    )
    cr.set_defaults(func=cmd_credentials)

    return parser


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


class Context:
    """Per-invocation state: config, audit log, HTTP client."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.config: SentinelConfig = load_config(getattr(args, "config", None))
        if args.log_level:
            self.config.log_level = args.log_level

        configure_logging(
            level=self.config.log_level,
            log_file=args.log_file or self.config.paths.log_file,
            quiet=args.quiet,
        )
        self.config.paths.ensure()

        self.guard = credguard.install()
        self.audit = AuditLog(path=args.audit_log or self.config.paths.audit_log)
        self.client = HttpClient.from_config(
            self.config,
            dry_run=bool(args.dry_run),
            fixture_dir=args.fixture_dir,
            seed=args.seed,
        )

    def signatures(self) -> fingerprint.SignatureDB:
        path = getattr(self.args, "signatures", None) or self.config.signatures_path
        db = fingerprint.SignatureDB.load(path)
        threshold = getattr(self.args, "confirm_threshold", None)
        if threshold is not None:
            db.confirm_threshold = float(threshold)
        return db

    def close(self) -> None:
        self.client.close()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_scan(ctx: Context) -> int:
    args = ctx.args
    config = ctx.config
    ports = config.resolve_ports(args.ports)

    grant: ActiveGrant | None = None
    if args.active:
        if not args.scope_file:
            raise ModeViolation(
                "--active requires --scope-file <path>. Active scanning emits "
                "packets to targets and is only permitted against ranges listed "
                "in a validated scope file."
            )
        grant = ActiveGrant.from_scope_file(args.scope_file)
        _console.print(
            f"[bold]Active authorization[/bold] accepted: {len(grant.cidrs)} range(s), "
            f"authorized by {grant.authorized_by} ({grant.authorization_ref})"
        )
    elif args.scope_file:
        # A scope file without --active is accepted but changes nothing about
        # packet emission; say so rather than letting the operator assume the
        # run was active.
        _console.print(
            "[yellow]Note:[/yellow] --scope-file given without --active. This run "
            "stays passive and sends no packets."
        )
        grant = ActiveGrant.from_scope_file(args.scope_file)

    mode = ScanMode.ACTIVE if args.active else ScanMode.PASSIVE
    allow_categories = set(grant.allowed_categories) if grant else set()

    if args.dry_run:
        # A dry run replays recorded fixtures and opens no socket at all, so the
        # denylist has nothing to protect here. RFC 5737 documentation ranges are
        # what fixtures are *supposed* to use, so permit that one category rather
        # than forcing every offline replay to carry a scope file authorizing
        # non-routable space.
        allow_categories.add("documentation")
        log_event(
            _log,
            "dry_run_documentation_allowed",
            "dry-run: permitting RFC5737/RFC3849 documentation ranges (no packets are sent)",
        )

    # -- discovery ----------------------------------------------------------
    if args.asn:
        disc = discovery.discover_asn(
            args.asn,
            ctx.client,
            config,
            expand=args.expand,
            force_expand=args.force_expand,
            allow_categories=tuple(sorted(allow_categories)),
        )
        target_asn = disc.asn
    else:
        cidrs = read_cidr_file(args.cidr_file)
        disc = discovery.discover_cidrs(
            cidrs,
            config,
            expand=args.expand or mode is ScanMode.ACTIVE,
            force_expand=args.force_expand,
            allow_categories=tuple(sorted(allow_categories)),
        )
        target_asn = None

    if disc.rejected:
        _console.print(f"[yellow]{len(disc.rejected)} target(s) refused by the denylist:[/yellow]")
        for target, reason in disc.rejected[:10]:
            _console.print(f"  · {target}: {reason}")

    if not disc.prefixes:
        _console.print("[red]No authorized target remains after validation.[/red]")
        ctx.audit.record(
            "scan_refused",
            mode.value,
            summary={"reason": "no authorized target", "rejected": len(disc.rejected)},
        )
        return EXIT_REFUSED_SCOPE

    result = ScanResult(
        target_asn=target_asn,
        mode=mode,
        tool_version=__version__,
        prefixes=list(disc.prefixes),
        scope_hash=grant.hash if grant else scope_hash(disc.prefixes),
    )

    # -- measurement --------------------------------------------------------
    if mode is ScanMode.ACTIVE:
        assert grant is not None  # guaranteed by the branch above
        outcome = scanner.run_masscan(
            grant,
            disc.prefixes,
            ports,
            config,
            requested_rate=args.rate,
            dry_run=bool(args.dry_run),
            fixture=args.scan_fixture,
        )
        result.hosts = outcome.hosts
        result.stats = {"discovery": disc.to_dict(), "scan": outcome.to_dict()}
    else:
        hosts, passive_stats = _passive_port_discovery(ctx, disc, ports)
        result.hosts = hosts
        result.stats = {"discovery": disc.to_dict(), "passive": passive_stats}

    risk.apply_to_hosts(result.hosts)

    out_path = (
        Path(args.output) if args.output else (config.paths.runs_dir / monitor.run_filename(result))
    )
    monitor.save_run(result, out_path)

    ctx.audit.record(
        "scan_complete",
        mode.value,
        scope_hash=result.scope_hash,
        summary={
            "target_asn": target_asn,
            "prefix_count": len(result.prefixes),
            "host_count": len(result.hosts),
            "ports": ports,
            "risk_histogram": result.risk_histogram(),
            "output": str(out_path),
            "dry_run": bool(args.dry_run),
            "credential_policy": ctx.guard.to_dict(),
            **result.stats,
        },
    )

    _print_summary(result, out_path)
    return EXIT_OK


def _passive_port_discovery(
    ctx: Context,
    disc: discovery.DiscoveryResult,
    ports: Sequence[int],
) -> tuple[list[Host], dict[str, Any]]:
    """Derive open ports from Shodan InternetDB without touching the targets.

    This is the passive counterpart to masscan. Without ``--expand`` there are no
    addresses to look up, so the run returns prefixes only -- which is honest
    rather than empty: the operator asked for a prefix census.
    """
    config = ctx.config
    if not disc.hosts:
        _console.print(
            "[yellow]Passive mode without --expand:[/yellow] reporting "
            f"{len(disc.prefixes)} prefix(es) only. Add --expand for per-address "
            "dataset lookups (capped at "
            f"{config.passive.max_hosts} addresses)."
        )
        return [], {"expanded": False, "queried": 0}

    wanted = set(ports)
    hosts: list[Host] = []
    queried = 0
    hits = 0

    for ip in disc.hosts:
        queried += 1
        payload = enrich.internetdb_lookup(ip, ctx.client, config)
        if not payload:
            continue
        host = Host(ip=ip, source="internetdb")
        enrich.apply_internetdb(host, payload)
        # Keep only the ports the operator asked about, so a passive run and an
        # active run over the same port preset are directly comparable.
        host.ports = [p for p in host.ports if p.port in wanted]
        if not host.ports:
            continue
        # Port-derived evidence (open_service, ot_protocol_exposed) is filled
        # in by risk.apply_to_host so the active and passive paths cannot drift.
        hits += 1
        hosts.append(host)

    log_event(
        _log,
        "passive_scan_complete",
        f"{hits} of {queried} address(es) had dataset records with requested ports",
        queried=queried,
        hits=hits,
    )
    return hosts, {
        "expanded": True,
        "queried": queried,
        "with_records": hits,
        "truncated": disc.truncated,
        "total_addresses": disc.total_addresses,
    }


def cmd_fingerprint(ctx: Context) -> int:
    args = ctx.args
    config = ctx.config
    result = monitor.load_run(args.input)
    db = ctx.signatures()

    if not result.hosts:
        _console.print("[yellow]Input contains no hosts; nothing to fingerprint.[/yellow]")

    if args.dry_run:
        hosts = fingerprint.fingerprint_from_fixtures(
            result.hosts, db, config, fixture_dir=args.fixture_dir
        )
    else:
        hosts = asyncio.run(
            fingerprint.fingerprint_hosts(
                result.hosts,
                db,
                config,
                concurrency=args.threads,
                rate_pps=args.rate,
            )
        )

    result.hosts = risk.apply_to_hosts(hosts)
    out_path = Path(args.output) if args.output else Path(args.input).with_suffix(".fp.json")
    monitor.save_run(result, out_path)

    ctx.audit.record(
        "fingerprint_complete",
        result.mode.value,
        scope_hash=result.scope_hash,
        summary={
            "input": str(args.input),
            "output": str(out_path),
            "host_count": len(result.hosts),
            "identified": sum(1 for h in result.hosts if h.vendor),
            "pre_auth_disclosure": sum(1 for h in result.hosts if h.pre_auth_disclosure),
            "risk_histogram": result.risk_histogram(),
            "confirm_threshold": db.confirm_threshold,
            "signature_source": str(db.source_path),
            "dry_run": bool(args.dry_run),
        },
    )
    _print_summary(result, out_path)
    return EXIT_OK


def cmd_enrich(ctx: Context) -> int:
    args = ctx.args
    config = ctx.config
    result = monitor.load_run(args.input)

    delegation = None
    if not args.no_delegation:
        registries = (
            [r.strip() for r in args.registries.split(",") if r.strip()]
            if args.registries
            else None
        )
        try:
            delegation = rir.load_delegation_index(ctx.client, config, registries=registries)
        except DatasetUnavailable as exc:
            _console.print(f"[yellow]RIR delegation data unavailable:[/yellow] {exc}")

    hosts, stats = enrich.enrich_hosts(
        result.hosts,
        ctx.client,
        config,
        delegation=delegation,
        do_reverse_dns=not args.no_reverse_dns,
        do_internetdb=not args.no_internetdb,
        do_org=not args.no_org,
    )
    result.hosts = risk.apply_to_hosts(hosts)
    result.stats["enrichment"] = stats.to_dict()

    out_path = Path(args.output) if args.output else Path(args.input).with_suffix(".enriched.json")
    monitor.save_run(result, out_path)

    ctx.audit.record(
        "enrich_complete",
        result.mode.value,
        scope_hash=result.scope_hash,
        summary={
            "input": str(args.input),
            "output": str(out_path),
            **stats.to_dict(),
            "dry_run": bool(args.dry_run),
        },
    )

    table = Table(title="Enrichment coverage", show_edge=False)
    table.add_column("Field")
    table.add_column("Coverage", justify="right")
    for name, value in stats.coverage().items():
        table.add_row(name, f"{value:.0%}")
    _console.print(table)
    if stats.unavailable:
        _console.print(
            "[dim]Sources unavailable (field left null, no substitution): "
            + ", ".join(f"{k}x{v}" for k, v in sorted(stats.unavailable.items()))
            + "[/dim]"
        )
    _print_summary(result, out_path)
    return EXIT_OK


def cmd_report(ctx: Context) -> int:
    args = ctx.args
    result = monitor.load_run(args.input)

    diff = None
    if args.diff_against:
        baseline = monitor.load_run(args.diff_against)
        diff = monitor.diff_runs(baseline, result)

    if args.output:
        out_path = report.write_report(result, args.output, fmt=args.format, diff=diff)
        _console.print(f"Report written to [bold]{out_path}[/bold]")
    else:
        sys.stdout.write(report.render(result, fmt=args.format, diff=diff))
        out_path = None

    ctx.audit.record(
        "report_complete",
        result.mode.value,
        scope_hash=result.scope_hash,
        summary={
            "input": str(args.input),
            "output": str(out_path) if out_path else "<stdout>",
            "format": args.format,
            "host_count": len(result.hosts),
            "risk_histogram": result.risk_histogram(),
            "diff_alerts": len(diff.alerts) if diff else 0,
        },
    )
    return EXIT_OK


def cmd_monitor(ctx: Context) -> int:
    args = ctx.args
    mon_config = monitor.MonitorConfig.load(args.monitor_config)
    db = ctx.signatures()

    iterations = 1 if args.once else max(0, int(args.iterations))
    cycles: list[monitor.MonitorCycle] = []
    index = 0

    ctx.audit.record(
        "monitor_start",
        mon_config.mode,
        summary={
            "config": str(args.monitor_config),
            "interval_seconds": args.interval,
            "iterations": iterations or "unbounded",
            "credential_policy": ctx.guard.to_dict(),
        },
    )

    try:
        while iterations == 0 or index < iterations:
            index += 1
            started = time.monotonic()
            cycle = monitor.MonitorCycle(index=index)
            try:
                cycle = _monitor_cycle(ctx, mon_config, db, index)
            except (ScopeError, DatasetUnavailable, scanner.ScannerError) as exc:
                cycle.error = f"{type(exc).__name__}: {exc}"
                log_event(
                    _log,
                    "monitor_cycle_failed",
                    f"cycle {index} failed: {exc}",
                    cycle=index,
                    level=40,
                )
                _console.print(f"[red]Cycle {index} failed:[/red] {exc}")
            cycles.append(cycle)

            if iterations and index >= iterations:
                break
            delay = monitor.sleep_until_next(args.interval, time.monotonic() - started)
            _console.print(f"[dim]Next cycle in {delay:.0f}s[/dim]")
            monitor.wait(delay)
    except KeyboardInterrupt:
        _console.print("\n[yellow]Interrupted; stopping after the current cycle.[/yellow]")
        ctx.audit.record(
            "monitor_interrupted",
            mon_config.mode,
            summary=monitor.summarise_cycles(cycles),
        )
        return EXIT_INTERRUPTED

    ctx.audit.record("monitor_complete", mon_config.mode, summary=monitor.summarise_cycles(cycles))
    return EXIT_OK


def _monitor_cycle(
    ctx: Context,
    mon_config: monitor.MonitorConfig,
    db: fingerprint.SignatureDB,
    index: int,
) -> monitor.MonitorCycle:
    """One full collect-compare-alert iteration."""
    config = ctx.config
    cycle = monitor.MonitorCycle(index=index)
    ports = config.resolve_ports(mon_config.ports)
    active = mon_config.mode.lower() == "active"

    grant: ActiveGrant | None = None
    if active:
        if not mon_config.scope_file:
            raise ModeViolation(
                "monitor config sets mode: active but no scope_file; refusing to "
                "emit packets without a validated scope file"
            )
        grant = ActiveGrant.from_scope_file(mon_config.scope_file)

    if mon_config.asn:
        disc = discovery.discover_asn(
            mon_config.asn, ctx.client, config, expand=mon_config.expand_hosts or active
        )
        target_asn = disc.asn
    else:
        disc = discovery.discover_cidrs(
            read_cidr_file(str(mon_config.cidr_file)),
            config,
            expand=mon_config.expand_hosts or active,
            allow_categories=tuple(grant.allowed_categories) if grant else (),
        )
        target_asn = None

    result = ScanResult(
        target_asn=target_asn,
        mode=ScanMode.ACTIVE if active else ScanMode.PASSIVE,
        tool_version=__version__,
        prefixes=list(disc.prefixes),
        scope_hash=grant.hash if grant else scope_hash(disc.prefixes),
    )

    if active and grant is not None:
        outcome = scanner.run_masscan(
            grant,
            disc.prefixes,
            ports,
            config,
            requested_rate=mon_config.rate,
            dry_run=mon_config.dry_run or bool(ctx.args.dry_run),
        )
        result.hosts = outcome.hosts
    else:
        result.hosts, _ = _passive_port_discovery(ctx, disc, ports)

    if result.hosts:
        if mon_config.dry_run or ctx.args.dry_run:
            result.hosts = fingerprint.fingerprint_from_fixtures(
                result.hosts, db, config, fixture_dir=ctx.args.fixture_dir
            )
        else:
            result.hosts = asyncio.run(fingerprint.fingerprint_hosts(result.hosts, db, config))
    result.hosts = risk.apply_to_hosts(result.hosts)

    diff, baseline_path = monitor.diff_against_previous(result, mon_config.runs_dir)
    cycle.run_path = monitor.save_run(
        result, Path(mon_config.runs_dir) / monitor.run_filename(result)
    )
    cycle.baseline_path = baseline_path

    if diff is not None:
        filtered = monitor.filter_alerts(diff, mon_config.min_severity)
        cycle.diff = filtered
        cycle.alerts_path = monitor.write_alerts(filtered, mon_config.alerts_dir)
        _console.print(
            f"Cycle {index}: {len(filtered.alerts)} alert(s), "
            f"max severity {filtered.max_severity.value}"
        )
        for alert in filtered.alerts[:20]:
            _console.print(
                f"  [{alert.severity.value}] {alert.ip} {alert.kind.value}: {alert.message}"
            )
    else:
        _console.print(f"Cycle {index}: baseline established ({len(result.hosts)} host(s))")

    ctx.audit.record(
        "monitor_cycle",
        result.mode.value,
        scope_hash=result.scope_hash,
        summary=cycle.to_dict() | {"risk_histogram": result.risk_histogram()},
    )
    return cycle


def cmd_verify_audit(ctx: Context) -> int:
    path = ctx.args.path or ctx.config.paths.audit_log
    ok, problems = verify_chain(path)
    if ok:
        _console.print(f"[green]Audit chain intact[/green] for {path}")
        return EXIT_OK
    _console.print(f"[red]Audit chain BROKEN[/red] for {path}:")
    for problem in problems:
        _console.print(f"  · {problem}")
    return EXIT_ERROR


def cmd_check_scope(ctx: Context) -> int:
    """Dry-validate a scope file. Mints a grant but never scans."""
    grant = ActiveGrant.from_scope_file(ctx.args.scope_file)

    table = Table(title="Scope file accepted", show_edge=False)
    table.add_column("Field")
    table.add_column("Value")
    for key, value in grant.summary().items():
        table.add_row(key, str(value))
    _console.print(table)
    _console.print("Authorized ranges: " + ", ".join(grant.cidrs))

    decision = ScopeDecision(mode="check")
    if ctx.args.target:
        allowed, rejected = grant.filter_targets(ctx.args.target)
        decision.authorized, decision.rejected = allowed, rejected
        for item in allowed:
            _console.print(f"  [green]ALLOW[/green] {item}")
        for item, reason in rejected:
            _console.print(f"  [red]REFUSE[/red] {item}: {reason}")

    ctx.audit.record_scope_decision("check", decision)
    return EXIT_OK if not decision.rejected else EXIT_REFUSED_SCOPE


def cmd_credentials(ctx: Context) -> int:
    """Print the credential policy, for audit and for the paper's appendix."""
    policy = credguard.active_policy()

    _console.print("[bold]Sentinel requires no credentials, no keys, and no accounts.[/bold]")
    _console.print(f"Policy file: {policy.path}\n")

    table = Table(title="Every endpoint this tool may contact", show_edge=False)
    table.add_column("Host")
    table.add_column("Purpose")
    table.add_column("Auth")
    for endpoint in policy.endpoints:
        table.add_row(
            str(endpoint.get("host", "")),
            str(endpoint.get("purpose", "")),
            str(endpoint.get("auth", "")),
        )
    _console.print(table)

    if ctx.guard.ignored_present:
        _console.print(
            f"\n[dim]{len(ctx.guard.ignored_present)} environment variable(s) in this "
            "shell match the credential policy and were ignored: "
            + ", ".join(ctx.guard.ignored_present)
            + "[/dim]"
        )

    findings = credguard.scan_source_tree(Path(__file__).resolve().parent)
    if findings:
        _console.print(f"\n[red]Source scan found {len(findings)} credential-shaped line(s):[/red]")
        for rel, lineno, line in findings[:20]:
            _console.print(f"  {rel}:{lineno}: {line[:100]}")
        return EXIT_REFUSED_POLICY

    _console.print("\n[green]Source scan clean:[/green] no credential-shaped identifiers.")
    sys.stdout.write(
        json.dumps(
            {
                "credentials_required": False,
                "policy_file": str(policy.path),
                "endpoints": list(policy.endpoints),
                "denied_services": sorted(policy.denied_services),
                "generated_at": utc_now_iso(),
            },
            indent=2,
        )
        + "\n"
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_summary(result: ScanResult, out_path: Path | None) -> None:
    histogram = result.risk_histogram()
    table = Table(title=f"{result.mode.value.upper()} run summary", show_edge=False)
    table.add_column("Risk")
    table.add_column("Hosts", justify="right")
    for level in RiskLevel:
        count = histogram[level.value]
        style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(level.value, "dim")
        table.add_row(f"[{style}]{level.value}[/{style}]", str(count))
    _console.print(table)
    if out_path:
        _console.print(f"Run written to [bold]{out_path}[/bold]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK

    ctx: Context | None = None
    try:
        ctx = Context(args)
        return int(args.func(ctx))

    except (ModeViolation, ScopeViolation, ScopeError) as exc:
        _console.print(f"[bold red]Refused:[/bold red] {exc}")
        if ctx is not None:
            ctx.audit.record(
                "refused",
                "unknown",
                summary={"reason": str(exc), "class": type(exc).__name__},
            )
        return EXIT_REFUSED_SCOPE

    except CredentialPolicyViolation as exc:
        _console.print(f"[bold red]Credential policy violation:[/bold red] {exc}")
        if ctx is not None:
            ctx.audit.record("policy_violation", "unknown", summary={"reason": str(exc)})
        return EXIT_REFUSED_POLICY

    except KeyboardInterrupt:
        _console.print("\n[yellow]Interrupted.[/yellow]")
        return EXIT_INTERRUPTED

    except (
        DatasetUnavailable,
        fingerprint.FingerprintError,
        discovery.DiscoveryError,
        monitor.MonitorError,
        report.ReportError,
        scanner.ScannerError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        _console.print(f"[bold red]Error:[/bold red] {exc}")
        log_event(_log, "command_failed", str(exc), level=40, error_class=type(exc).__name__)
        if ctx is not None:
            ctx.audit.record(
                "failed", "unknown", summary={"error": str(exc), "class": type(exc).__name__}
            )
        return EXIT_ERROR

    finally:
        if ctx is not None:
            ctx.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
