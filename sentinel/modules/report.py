"""Report rendering: Markdown, JSON, and HTML via Jinja2.

Security note on untrusted content
----------------------------------
Banners, page titles, and TLS subjects in a report are **attacker-controlled
strings**. They were read off a remote device that may well be compromised, and
a device operator who does not want to be fingerprinted has every incentive to
put markup in its ``Server`` header.

So the HTML template is rendered with autoescaping on, and Markdown output
escapes pipes and control characters that would otherwise break out of a table
cell. Rendering collected banners raw into an analyst's browser would turn an
exposure report into a stored-XSS delivery mechanism aimed at the defender --
an own-goal worth designing out rather than documenting.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from sentinel import __version__
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import DiffReport, RiskLevel, ScanResult, utc_now_iso

_log = get_logger("report")

TEMPLATE_DIR = Path(__file__).with_name("templates")

FORMATS: tuple[str, ...] = ("markdown", "md", "json", "html")

#: Characters that would break a Markdown table cell or inject terminal control
#: sequences into a log viewer.
_MD_UNSAFE = re.compile(r"[|\r\n\x00-\x08\x0b-\x1f\x7f]")


class ReportError(RuntimeError):
    """Unknown format, or a template that could not be rendered."""


def md_escape(value: Any) -> str:
    """Make an arbitrary collected string safe inside a Markdown table cell."""
    if value is None:
        return ""
    text = str(value)
    text = _MD_UNSAFE.sub(" ", text)
    # Escape Markdown emphasis so a banner cannot restyle the document.
    for char in ("\\", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(char, "\\" + char)
    return text.strip()


def truncate(value: Any, length: int = 120) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= length else text[: length - 1] + "…"


def build_environment(template_dir: str | Path | None = None) -> Environment:
    """Jinja2 environment with autoescaping and strict undefined names.

    ``StrictUndefined`` turns a template typo into an error instead of silently
    rendering an empty cell -- in a report that feeds a paper, a quietly missing
    column is worse than a crash.
    """
    directory = Path(template_dir or TEMPLATE_DIR)
    env = Environment(
        loader=FileSystemLoader(str(directory)),
        autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml"), default=False),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md"] = md_escape
    env.filters["truncate_text"] = truncate
    return env


def build_context(result: ScanResult, diff: DiffReport | None = None) -> dict[str, Any]:
    """Assemble the template context, including the aggregates a report needs."""
    hosts = sorted(result.hosts, key=lambda h: (-h.risk.severity, -h.confidence, h.ip))

    by_vendor: dict[str, int] = {}
    by_country: dict[str, int] = {}
    port_counts: dict[int, int] = {}
    for host in result.hosts:
        if host.vendor:
            by_vendor[host.vendor] = by_vendor.get(host.vendor, 0) + 1
        if host.country:
            by_country[host.country] = by_country.get(host.country, 0) + 1
        for port in host.open_ports:
            port_counts[port] = port_counts.get(port, 0) + 1

    histogram = result.risk_histogram()
    actionable = sum(
        histogram[level.value] for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
    )

    return {
        "result": result,
        "hosts": hosts,
        "histogram": histogram,
        "levels": [level.value for level in RiskLevel],
        "actionable": actionable,
        "by_vendor": dict(sorted(by_vendor.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_country": dict(sorted(by_country.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_port": dict(sorted(port_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "pre_auth_count": sum(1 for h in result.hosts if h.pre_auth_disclosure),
        "ot_exposed_count": sum(1 for h in result.hosts if h.evidence.ot_protocol_exposed),
        "generated_at": utc_now_iso(),
        "tool_version": __version__,
        "diff": diff,
    }


def render(
    result: ScanResult,
    fmt: str = "markdown",
    diff: DiffReport | None = None,
    template_dir: str | Path | None = None,
) -> str:
    """Render a scan result in the requested format."""
    normalized = fmt.strip().lower()
    if normalized not in FORMATS:
        raise ReportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")

    if normalized == "json":
        payload = result.to_dict()
        if diff is not None:
            payload["diff"] = diff.to_dict()
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"

    template_name = "report.html.j2" if normalized == "html" else "report.md.j2"
    env = build_environment(template_dir)
    try:
        template = env.get_template(template_name)
    except Exception as exc:  # noqa: BLE001 -- jinja raises several types
        raise ReportError(f"could not load template {template_name}: {exc}") from exc

    return template.render(**build_context(result, diff))


def write_report(
    result: ScanResult,
    path: str | Path,
    fmt: str = "markdown",
    diff: DiffReport | None = None,
    template_dir: str | Path | None = None,
) -> Path:
    """Render and write a report, creating parent directories as needed."""
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text = render(result, fmt=fmt, diff=diff, template_dir=template_dir)
    out_path.write_text(text, encoding="utf-8")
    log_event(
        _log,
        "report_written",
        f"{fmt} report written to {out_path} ({len(result.hosts)} host(s))",
        report_path=str(out_path),
        report_format=fmt,
        host_count=len(result.hosts),
    )
    return out_path


def render_diff_markdown(diff: DiffReport) -> str:
    """Compact Markdown rendering of a monitoring diff, for an alert digest."""
    lines = [
        "# Sentinel exposure change report",
        "",
        f"- Baseline: `{md_escape(diff.baseline_time)}`",
        f"- Current:  `{md_escape(diff.current_time)}`",
        f"- Changes:  **{len(diff.alerts)}**",
        f"- Highest severity: **{diff.max_severity.value}**",
        "",
    ]
    if not diff.alerts:
        lines.append("No changes detected since the baseline run.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Severity | Change | Address | Detail |",
            "| --- | --- | --- | --- |",
        ]
    )
    for alert in sorted(diff.alerts, key=lambda a: (-a.severity.severity, a.ip)):
        lines.append(
            f"| {alert.severity.value} | {alert.kind.value} | `{md_escape(alert.ip)}` "
            f"| {md_escape(alert.message)} |"
        )
    return "\n".join(lines) + "\n"
