"""YAML configuration loading, port presets, and rate-limit arithmetic.

Rate limiting is a *safety* control here, not a courtesy one. Legacy PLCs and
BMS controllers have been documented to fault, drop their scan cycle, or fail
closed under modest probe pressure; an exposure study that bricks a building
controller has done more harm than the exposure it measured. So:

* ports are classified (OT / web / other) and each class carries its own
  packets-per-second ceiling;
* a target set containing *any* OT port is governed by the OT ceiling -- the
  most restrictive class present wins;
* :func:`SentinelConfig.clamp_rate` applies ``min(requested, ceiling)``. The CLI
  can lower the rate but cannot raise it past the configured ceiling, and the
  config file itself is bounded by :data:`ABSOLUTE_MAX_PPS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from sentinel.logging_setup import get_logger, log_event
from sentinel.models import PortClass

_log = get_logger("config")

DEFAULT_CONFIG_PATH = Path(__file__).with_name("sentinel.yaml")

#: Hard ceiling no configuration file may exceed, for any port class.
ABSOLUTE_MAX_PPS = 20_000

# ---------------------------------------------------------------------------
# Port taxonomy
# ---------------------------------------------------------------------------

#: Industrial protocol and embedded-device ports. 9000 (REDY-Process / BMS web
#: UI) is deliberately classified OT rather than web: the HTTP stack is on a
#: constrained building controller, so it inherits the conservative budget.
OT_PORTS: frozenset[int] = frozenset(
    {
        102,  # Siemens S7 / ISO-TSAP
        161,  # SNMP (OT asset inventory leakage)
        502,  # Modbus/TCP
        789,  # Red Lion Crimson
        1089,  # FF HSE
        1911,  # Niagara Fox (Tridium)
        1962,  # PCWorx
        2222,  # EtherNet/IP (UDP I/O)
        2404,  # IEC 60870-5-104
        4000,  # Omron FINS (vendor-dependent)
        4840,  # OPC-UA binary
        5007,  # Mitsubishi MELSEC
        9000,  # REDY-Process / generic BMS web UI on embedded hardware
        18245,  # GE SRTP
        20000,  # DNP3
        34962,  # PROFINET RT
        34964,  # PROFINET CM
        44818,  # EtherNet/IP (TCP explicit messaging)
        47808,  # BACnet/IP
    }
)

#: Conventional HTTP(S) ports served by general-purpose stacks.
WEB_PORTS: frozenset[int] = frozenset(
    {80, 81, 443, 591, 3000, 7080, 8000, 8008, 8080, 8081, 8443, 8888, 10000}
)

#: Named port sets selectable with ``--ports <preset>``.
PORT_PRESETS: dict[str, list[int]] = {
    "web": sorted({80, 443, 8080, 8443, 8000, 8008, 8888}),
    "ics": sorted({9000, 80, 443, 8080, 8443, 102, 502, 20000, 44818, 4840, 1911, 2222, 161}),
    "ot": sorted(OT_PORTS),
    "full": sorted(OT_PORTS | WEB_PORTS),
}


def classify_port(port: int) -> PortClass:
    """Map a port number to its rate-limit class."""
    if port in OT_PORTS:
        return PortClass.OT
    if port in WEB_PORTS:
        return PortClass.WEB
    return PortClass.OTHER


def resolve_ports(
    spec: str | list[int] | None, presets: dict[str, list[int]] | None = None
) -> list[int]:
    """Resolve a ``--ports`` argument into a sorted, de-duplicated port list.

    Accepts a preset name, a comma-separated list, and ``a-b`` ranges
    (``"80,443,8000-8010"``). Ranges are bounded to 1024 ports per span so a
    typo like ``1-65535`` is a visible error rather than a multi-hour run.
    """
    table = presets or PORT_PRESETS
    if spec is None:
        return list(table["ics"])
    if isinstance(spec, list):
        return sorted({_validate_port(p) for p in spec})

    text = str(spec).strip().lower()
    if text in table:
        return list(table[text])

    ports: set[int] = set()
    for chunk in text.split(","):
        item = chunk.strip()
        if not item:
            continue
        if item in table:
            ports.update(table[item])
            continue
        if "-" in item:
            low_s, _, high_s = item.partition("-")
            low, high = _validate_port(low_s), _validate_port(high_s)
            if low > high:
                raise ValueError(f"inverted port range: {item}")
            if high - low + 1 > 1024:
                raise ValueError(
                    f"port range {item} spans {high - low + 1} ports; "
                    "cap a single range at 1024 or use a preset"
                )
            ports.update(range(low, high + 1))
            continue
        ports.add(_validate_port(item))

    if not ports:
        raise ValueError(f"could not resolve any port from {spec!r}")
    return sorted(ports)


def _validate_port(value: Any) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range 1-65535: {port}")
    return port


# ---------------------------------------------------------------------------
# Config sections
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RateLimits:
    """Packets/requests per second ceilings, per port class."""

    ot_pps: int = 100
    web_pps: int = 1000
    other_pps: int = 100

    def __post_init__(self) -> None:
        for name in ("ot_pps", "web_pps", "other_pps"):
            value = int(getattr(self, name))
            if value < 1:
                raise ValueError(f"{name} must be >= 1, got {value}")
            if value > ABSOLUTE_MAX_PPS:
                raise ValueError(
                    f"{name}={value} exceeds the absolute ceiling of {ABSOLUTE_MAX_PPS} pps"
                )
            setattr(self, name, value)

    def ceiling_for(self, port_class: PortClass) -> int:
        return {
            PortClass.OT: self.ot_pps,
            PortClass.WEB: self.web_pps,
            PortClass.OTHER: self.other_pps,
        }[port_class]


@dataclass(slots=True)
class Timeouts:
    """Network timeouts in seconds. Every outbound call is bounded."""

    connect: float = 5.0
    read: float = 8.0
    total: float = 15.0
    tls_handshake: float = 6.0
    dns: float = 3.0
    subprocess: float = 1800.0


@dataclass(slots=True)
class RetryPolicy:
    """Exponential backoff with full jitter."""

    attempts: int = 3
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    jitter: bool = True
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)

    def delay_for(self, attempt: int) -> float:
        """Delay before retry ``attempt`` (1-based), capped at ``backoff_max``."""
        raw = self.backoff_base * (2 ** max(0, attempt - 1))
        return float(min(raw, self.backoff_max))


@dataclass(slots=True)
class PassivePolicy:
    """Bounds on passive (dataset-only) expansion.

    Passive mode sends nothing to the target, but it does query third-party
    datasets. Expanding an ASN's prefixes to every host address would mean tens
    of thousands of requests to RIPEstat/Shodan per run, which is neither
    defensible nor sustainable. Expansion is therefore opt-in and capped.
    """

    expand_hosts: bool = False
    max_hosts: int = 1024
    #: Refuse to expand a prefix shorter (broader) than this without --force-expand.
    min_expand_prefix_v4: int = 20
    #: Seconds between third-party dataset requests.
    request_delay: float = 0.1
    dataset_concurrency: int = 4
    include_ipv6: bool = False


@dataclass(slots=True)
class FingerprintPolicy:
    """Banner-grab behaviour."""

    concurrency: int = 50
    max_body_bytes: int = 65536
    max_banner_bytes: int = 2048
    follow_redirects: bool = True
    max_redirects: int = 3
    #: TLS verification is OFF for fingerprinting because ICS devices almost
    #: universally present self-signed certificates; the certificate is treated
    #: as evidence to record, never as a trust decision. No credentials or
    #: confidential material is ever sent over these connections.
    verify_tls: bool = False
    collect_tls_metadata: bool = True
    #: Probe URL paths drawn from signatures.yaml. GET only, never POST.
    probe_url_patterns: bool = True
    max_url_probes_per_host: int = 6


@dataclass(slots=True)
class OutputPaths:
    """Filesystem layout for run artefacts."""

    output_dir: Path = Path("out")
    runs_dir: Path = Path("out/runs")
    report_dir: Path = Path("out/reports")
    log_file: Path = Path("logs/sentinel.jsonl")
    audit_log: Path = Path("audit/sentinel-audit.jsonl")
    #: Local cache for RIR delegation files and dataset responses. Caching is
    #: what lets the experiment suite replay a study fully offline -- and it is
    #: also the courteous way to use a free public dataset.
    cache_dir: Path = Path("labs/seed/cache")

    def ensure(self) -> None:
        for target in (self.output_dir, self.runs_dir, self.report_dir, self.cache_dir):
            Path(target).mkdir(parents=True, exist_ok=True)
        for target in (self.log_file, self.audit_log):
            Path(target).parent.mkdir(parents=True, exist_ok=True)


@dataclass(slots=True)
class Endpoints:
    """Anonymous, keyless dataset endpoints.

    Every entry here is reachable without an account, a key, or a registered
    tier, and is cross-checked at call time against the allowlist in
    ``credential_policy.yaml``. Registration-gated services (ipinfo.io, the
    Shodan REST API, Censys, and friends) are absent by policy, not by
    oversight: see ``docs/CREDENTIALS.md``.
    """

    ripestat_announced_prefixes: str = "https://stat.ripe.net/data/announced-prefixes/data.json"
    ripestat_network_info: str = "https://stat.ripe.net/data/network-info/data.json"
    ripestat_as_overview: str = "https://stat.ripe.net/data/as-overview/data.json"
    #: Free, keyless per-IP dataset. Distinct from the Shodan REST API, which
    #: requires a key and is therefore unusable here.
    shodan_internetdb: str = "https://internetdb.shodan.io"

    #: RIR delegated-extended files: plain text, anonymous. Source of country,
    #: RIR, and allocation status per range. They carry opaque organisation
    #: handles rather than organisation *names* -- name attribution comes from
    #: WHOIS/RDAP below.
    rir_delegations: dict[str, str] = field(
        default_factory=lambda: {
            "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
            "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
            "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
            "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
            "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        }
    )

    #: RDAP endpoints, queried only when the local ``whois`` binary is absent.
    #: Same registry data as WHOIS over HTTPS/JSON, operated by the RIRs,
    #: anonymous and keyless.
    rdap: dict[str, str] = field(
        default_factory=lambda: {
            "ripencc": "https://rdap.db.ripe.net",
            "arin": "https://rdap.arin.net/registry",
            "apnic": "https://rdap.apnic.net",
            "lacnic": "https://rdap.lacnic.net/rdap",
            "afrinic": "https://rdap.afrinic.net/rdap",
        }
    )


@dataclass(slots=True)
class ScannerPolicy:
    """masscan subprocess settings. masscan itself is an external dependency."""

    binary: str = "masscan"
    #: Extra arguments appended verbatim. Validated against a denylist of
    #: options that would subvert the safety controls (see scanner.py).
    extra_args: list[str] = field(default_factory=list)
    wait_seconds: int = 3
    retries: int = 0
    banners: bool = False


@dataclass(slots=True)
class SentinelConfig:
    """Fully resolved runtime configuration."""

    rate_limits: RateLimits = field(default_factory=RateLimits)
    timeouts: Timeouts = field(default_factory=Timeouts)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    passive: PassivePolicy = field(default_factory=PassivePolicy)
    fingerprint: FingerprintPolicy = field(default_factory=FingerprintPolicy)
    paths: OutputPaths = field(default_factory=OutputPaths)
    endpoints: Endpoints = field(default_factory=Endpoints)
    scanner: ScannerPolicy = field(default_factory=ScannerPolicy)
    port_presets: dict[str, list[int]] = field(
        default_factory=lambda: {k: list(v) for k, v in PORT_PRESETS.items()}
    )
    signatures_path: Path = Path("signatures.yaml")
    log_level: str = "INFO"
    source_path: Path | None = None

    # -- rate arithmetic ----------------------------------------------------

    def dominant_class(self, ports: list[int]) -> PortClass:
        """Most restrictive port class present in ``ports``.

        OT beats OTHER beats WEB. A mixed web+OT scan is paced as an OT scan.
        """
        classes = {classify_port(p) for p in ports}
        if PortClass.OT in classes:
            return PortClass.OT
        if PortClass.OTHER in classes:
            return PortClass.OTHER
        return PortClass.WEB if classes else PortClass.OT

    def clamp_rate(self, requested: int | None, ports: list[int]) -> tuple[int, PortClass, bool]:
        """Return ``(effective_rate, governing_class, was_clamped)``.

        ``requested=None`` means "use the ceiling". A request above the ceiling
        is silently lowered and the ``was_clamped`` flag lets the caller log the
        refusal -- the operator is told, but the scan proceeds safely rather
        than failing.
        """
        port_class = self.dominant_class(ports)
        ceiling = self.rate_limits.ceiling_for(port_class)
        if requested is None:
            return ceiling, port_class, False
        asked = int(requested)
        if asked < 1:
            raise ValueError(f"--rate must be >= 1, got {asked}")
        effective = min(asked, ceiling)
        return effective, port_class, effective < asked

    def resolve_ports(self, spec: str | list[int] | None) -> list[int]:
        return resolve_ports(spec, self.port_presets)

    def with_overrides(self, **overrides: Any) -> SentinelConfig:
        """Return a copy with top-level fields replaced (CLI override path)."""
        return replace(self, **{k: v for k, v in overrides.items() if v is not None})


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _coerce_section(cls: type, raw: Any, section: str) -> Any:
    """Build a config dataclass from a YAML mapping, rejecting unknown keys.

    Unknown keys are an error rather than a warning: a silently-ignored
    ``ot_pps`` typo in a rate-limit block is exactly the kind of failure that
    would let a study exceed its packet budget without anyone noticing.
    """
    if raw is None:
        return cls()
    if not isinstance(raw, dict):
        raise ValueError(f"config section '{section}' must be a mapping")

    fields = cls.__dataclass_fields__  # type: ignore[attr-defined]
    unknown = set(raw) - set(fields)
    if unknown:
        raise ValueError(
            f"unknown key(s) in config section '{section}': {', '.join(sorted(unknown))}"
        )

    kwargs: dict[str, Any] = {}
    for key, value in raw.items():
        annotation = str(fields[key].type)
        if "Path" in annotation and value is not None:
            kwargs[key] = Path(str(value)).expanduser()
        elif "tuple" in annotation and isinstance(value, list):
            kwargs[key] = tuple(value)
        else:
            kwargs[key] = value
    return cls(**kwargs)


def load_config(path: str | Path | None = None) -> SentinelConfig:
    """Load configuration from YAML, falling back to the packaged defaults.

    Resolution order: explicit ``path`` -> ``./config/sentinel.yaml`` ->
    ``./sentinel.yaml`` -> packaged ``sentinel/config/sentinel.yaml``.
    """
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser())
    else:
        candidates.extend(
            [
                Path("config/sentinel.yaml"),
                Path("sentinel.yaml"),
                DEFAULT_CONFIG_PATH,
            ]
        )

    chosen: Path | None = next((c for c in candidates if c.is_file()), None)
    if chosen is None:
        if path:
            raise FileNotFoundError(f"config file not found: {path}")
        log_event(_log, "config_defaults", "no config file found; using built-in defaults")
        return SentinelConfig()

    try:
        raw = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{chosen} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{chosen} must contain a YAML mapping at the top level")

    known_sections = {
        "rate_limits": RateLimits,
        "timeouts": Timeouts,
        "retry": RetryPolicy,
        "passive": PassivePolicy,
        "fingerprint": FingerprintPolicy,
        "paths": OutputPaths,
        "endpoints": Endpoints,
        "scanner": ScannerPolicy,
    }
    scalar_keys = {"signatures_path", "log_level", "port_presets"}
    unknown_top = set(raw) - set(known_sections) - scalar_keys
    if unknown_top:
        raise ValueError(f"unknown top-level key(s) in {chosen}: {', '.join(sorted(unknown_top))}")

    sections = {
        name: _coerce_section(cls, raw.get(name), name) for name, cls in known_sections.items()
    }

    presets = {k: list(v) for k, v in PORT_PRESETS.items()}
    for name, ports in (raw.get("port_presets") or {}).items():
        presets[str(name)] = resolve_ports(ports, presets)

    config = SentinelConfig(
        **sections,
        port_presets=presets,
        signatures_path=Path(str(raw.get("signatures_path", "signatures.yaml"))).expanduser(),
        log_level=str(raw.get("log_level", "INFO")),
        source_path=chosen,
    )
    log_event(
        _log,
        "config_loaded",
        f"configuration loaded from {chosen}",
        config_path=str(chosen),
        ot_pps=config.rate_limits.ot_pps,
        web_pps=config.rate_limits.web_pps,
    )
    return config
