"""Asynchronous banner collection and ICS signature matching.

Five-layer fingerprinting taxonomy
----------------------------------
Each layer is an independent, weighted evidence source. No single layer is
sufficient; the weighted sum produces a continuous score, and the classification
threshold is a parameter rather than a constant, which is what makes a detection
ROC curve possible (experiment E1).

======  ==================  ===========================================
Layer   Evidence            Rationale
======  ==================  ===========================================
L1      ``Server`` header   Strongest single signal; embedded HTTP stacks
                            rarely bother to disguise themselves.
L2      TLS certificate     ICS devices ship distinctive self-signed
                            certs whose subject/issuer encode the product.
L3      Page title          Survives reverse proxies that strip headers.
L4      JavaScript globals  SPA-based HMIs expose product-specific
                            globals before authentication.
L5      URL path patterns   Product-specific endpoints confirm a guess
                            that the other layers only suggest.
======  ==================  ===========================================

Probing discipline
------------------
Two rules constrain what this module is allowed to send, and both are enforced
in code rather than left to the operator:

* **OT ports are listen-only.** :func:`probe_tcp_listen` opens a TCP connection
  and reads whatever the service volunteers. It never writes a byte. Modbus, S7
  and OPC-UA are client-speaks-first protocols, so this yields "a service is
  listening" and nothing more -- which is a real limitation, honestly recorded
  in the output as ``ot_listen_confirmed`` rather than inflated into a vendor
  claim. Sending a Modbus function code to elicit a device identity would be an
  application-layer write to an industrial controller, and that is out of scope
  for this work regardless of how informative it would be.

* **HTTP probing is GET-only and unauthenticated.** No POST, no form
  submission, no credential of any kind. ``pre_auth_disclosure`` records whether
  the device *volunteered* operational content to an anonymous request; it is an
  observation about the asset's configuration, never an attempt to get past an
  authentication boundary. A 401 or a login page is recorded as
  ``auth_wall`` and the host is scored lower, not probed harder.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
import yaml

from sentinel import USER_AGENT
from sentinel.config.loader import SentinelConfig, classify_port
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import Host, PortClass, PortState, RiskEvidence

_log = get_logger("fingerprint")

try:  # pragma: no cover -- availability varies by environment
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    _HAVE_X509 = True
except ImportError:  # pragma: no cover
    _HAVE_X509 = False

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_REFRESH_RE = re.compile(r"<meta[^>]+http-equiv=['\"]?refresh", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")

#: Markers that a response is an authentication boundary rather than content.
_LOGIN_MARKERS: tuple[str, ...] = (
    'type="password"',
    "type='password'",
    'name="password"',
    "login",
    "logon",
    "sign in",
    "signin",
    "authenticate",
)

#: Ports conventionally served over TLS. Used to pick a scheme; a failed HTTPS
#: attempt falls back to plaintext, and vice versa.
_TLS_PORTS: frozenset[int] = frozenset({443, 8443, 9443, 4843, 8883})


class FingerprintError(RuntimeError):
    """Signature database is missing or malformed."""


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Signature:
    """One vendor fingerprint from ``signatures.yaml``."""

    vendor: str
    ports: tuple[int, ...] = ()
    server_header: tuple[str, ...] = ()
    title_keywords: tuple[str, ...] = ()
    js_globals: tuple[str, ...] = ()
    url_patterns: tuple[str, ...] = ()
    tls_subject_keywords: tuple[str, ...] = ()
    default_cred_risk: bool = False
    cves: tuple[str, ...] = ()
    mitre_ics: tuple[str, ...] = ()
    #: Generic signatures match industrial *vocabulary* rather than a product.
    #: They can never yield a confirmed-ICS verdict -- at most MEDIUM risk --
    #: because "the page says SCADA" is not identification.
    generic: bool = False
    notes: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Signature:
        vendor = str(raw.get("vendor", "")).strip()
        if not vendor:
            raise FingerprintError("signature entry is missing a 'vendor' field")
        return cls(
            vendor=vendor,
            ports=tuple(int(p) for p in raw.get("ports", ())),
            server_header=_lower_tuple(raw.get("server_header")),
            title_keywords=_lower_tuple(raw.get("title_keywords")),
            js_globals=tuple(str(x) for x in (raw.get("js_globals") or ())),
            url_patterns=tuple(str(x) for x in (raw.get("url_patterns") or ())),
            tls_subject_keywords=_lower_tuple(raw.get("tls_subject_keywords")),
            default_cred_risk=bool(raw.get("default_cred_risk", False)),
            cves=tuple(str(x) for x in (raw.get("cves") or ())),
            mitre_ics=tuple(str(x) for x in (raw.get("mitre_ics") or ())),
            generic=bool(raw.get("generic", False)),
            notes=(str(raw["notes"]) if raw.get("notes") else None),
        )


@dataclass(slots=True)
class MatchWeights:
    """Per-layer contribution to the match score. Sums are normalised."""

    server_header: float = 0.35
    tls_subject: float = 0.15
    title: float = 0.25
    js_globals: float = 0.15
    url_pattern: float = 0.15
    port_affinity: float = 0.05

    def total(self) -> float:
        return (
            self.server_header
            + self.tls_subject
            + self.title
            + self.js_globals
            + self.url_pattern
            + self.port_affinity
        )


@dataclass(slots=True)
class MatchResult:
    """Outcome of matching one observation against the signature database."""

    vendor: str | None = None
    score: float = 0.0
    layers: tuple[str, ...] = ()
    signature: Signature | None = None
    generic: bool = False
    runner_up: str | None = None

    @property
    def confidence(self) -> float:
        return round(min(1.0, max(0.0, self.score)), 4)


@dataclass(slots=True)
class SignatureDB:
    """Loaded signature set plus matching parameters."""

    signatures: tuple[Signature, ...] = ()
    weights: MatchWeights = field(default_factory=MatchWeights)
    #: Score at or above which a non-generic match counts as confirmed ICS.
    #: Exposed as a parameter so E1 can sweep it and plot a ROC curve.
    confirm_threshold: float = 0.45
    #: Score at or above which a generic match counts as industrial vocabulary.
    generic_threshold: float = 0.20
    source_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> SignatureDB:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            raise FingerprintError(
                f"signature database not found: {file_path}. Sentinel cannot "
                "fingerprint without it; point --signatures at signatures.yaml."
            )
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise FingerprintError(f"{file_path} is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise FingerprintError(f"{file_path} must be a YAML mapping")

        entries = raw.get("signatures")
        if not isinstance(entries, list) or not entries:
            raise FingerprintError(f"{file_path} defines no 'signatures' list")

        matching = raw.get("matching") or {}
        weights_raw = matching.get("weights") or {}
        known = set(MatchWeights.__dataclass_fields__)
        unknown = set(weights_raw) - known
        if unknown:
            raise FingerprintError(
                f"unknown matching weight(s) in {file_path}: {', '.join(sorted(unknown))}"
            )

        db = cls(
            signatures=tuple(Signature.from_dict(e) for e in entries),
            weights=MatchWeights(**weights_raw),
            confirm_threshold=float(matching.get("confirm_threshold", 0.45)),
            generic_threshold=float(matching.get("generic_threshold", 0.20)),
            source_path=file_path,
        )
        log_event(
            _log,
            "signatures_loaded",
            f"{len(db.signatures)} signature(s) loaded from {file_path}",
            signature_count=len(db.signatures),
            vendor_count=len({s.vendor for s in db.signatures}),
        )
        return db

    # -- matching -----------------------------------------------------------

    def match(self, obs: Observation) -> MatchResult:
        """Score ``obs`` against every signature and return the best match."""
        scored: list[tuple[float, tuple[str, ...], Signature]] = []
        normaliser = self.weights.total() or 1.0

        for signature in self.signatures:
            raw_score = 0.0
            layers: list[str] = []
            w = self.weights

            if signature.server_header and _any_in(signature.server_header, obs.server_header):
                raw_score += w.server_header
                layers.append("L1:server_header")
            if signature.tls_subject_keywords and _any_in(
                signature.tls_subject_keywords, obs.tls_blob
            ):
                raw_score += w.tls_subject
                layers.append("L2:tls")
            if signature.title_keywords and _any_in(signature.title_keywords, obs.title_lower):
                raw_score += w.title
                layers.append("L3:title")
            if signature.js_globals and _any_in_cs(signature.js_globals, obs.body):
                raw_score += w.js_globals
                layers.append("L4:js_global")
            if signature.url_patterns and _any_in(
                tuple(p.lower() for p in signature.url_patterns), obs.matched_paths_blob
            ):
                raw_score += w.url_pattern
                layers.append("L5:url_pattern")

            # Port affinity alone never identifies a vendor; it only reinforces
            # a match that some content layer already supports.
            if signature.ports and obs.port in signature.ports and layers:
                raw_score += w.port_affinity
                layers.append("L0:port")

            if raw_score > 0:
                scored.append((raw_score / normaliser, tuple(layers), signature))

        if not scored:
            return MatchResult()

        scored.sort(key=lambda item: (-item[0], item[2].generic, item[2].vendor))
        best_score, best_layers, best_sig = scored[0]
        runner_up = scored[1][2].vendor if len(scored) > 1 else None

        return MatchResult(
            vendor=best_sig.vendor,
            score=best_score,
            layers=best_layers,
            signature=best_sig,
            generic=best_sig.generic,
            runner_up=runner_up,
        )

    def classify(self, result: MatchResult) -> tuple[bool, bool]:
        """Return ``(ics_confirmed, generic_industrial)`` for a match result."""
        if result.signature is None:
            return False, False
        if result.generic:
            return False, result.score >= self.generic_threshold
        if result.score >= self.confirm_threshold:
            return True, False
        # A weak product match still counts as industrial vocabulary.
        return False, result.score >= self.generic_threshold

    def url_patterns(self, limit: int) -> list[str]:
        """Distinct probe paths across all signatures, deterministically ordered.

        Capped per host so that a growing signature database cannot silently
        turn one host probe into dozens of requests.
        """
        seen: list[str] = []
        for signature in self.signatures:
            for pattern in signature.url_patterns:
                if pattern.startswith("/") and pattern not in seen:
                    seen.append(pattern)
        return sorted(seen)[:limit]


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Observation:
    """What a single probe actually saw. Pure data, no inference."""

    ip: str
    port: int
    scheme: str = "tcp"
    status: int | None = None
    server_header: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    body: str = ""
    raw_banner: str = ""
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_not_after: str | None = None
    tls_self_signed: bool | None = None
    matched_paths: list[str] = field(default_factory=list)
    auth_wall: bool = False
    listening: bool = False
    error: str | None = None

    @property
    def title_lower(self) -> str:
        return self.title.lower()

    @property
    def tls_blob(self) -> str:
        return f"{self.tls_subject or ''} {self.tls_issuer or ''}".lower()

    @property
    def matched_paths_blob(self) -> str:
        return " ".join(self.matched_paths).lower()

    @property
    def banner(self) -> str:
        """Human-readable banner summary, for the report and for diffing."""
        if self.scheme in {"http", "https"}:
            parts = [f"HTTP/{self.status}" if self.status else "HTTP"]
            if self.server_header:
                parts.append(f"Server: {self.server_header}")
            if self.title:
                parts.append(f"Title: {self.title}")
            return " | ".join(parts)
        return self.raw_banner.strip() or ("listening" if self.listening else "")


# ---------------------------------------------------------------------------
# Async pacing
# ---------------------------------------------------------------------------


class AsyncPacer:
    """Minimum-interval pacer for concurrent probes.

    Converts the configured packets-per-second ceiling into a serialised
    inter-probe delay. Combined with a concurrency semaphore this gives a hard
    upper bound on probe rate regardless of how many coroutines are in flight --
    the property the rate-impact experiment (E3) measures.
    """

    __slots__ = ("_interval", "_lock", "_next")

    def __init__(self, rate_pps: float) -> None:
        self._interval = 1.0 / rate_pps if rate_pps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._interval
        if delay:
            await asyncio.sleep(delay)


def _tls_context() -> ssl.SSLContext:
    """Permissive TLS context for fingerprinting.

    Verification is disabled because effectively every ICS device presents a
    self-signed certificate; refusing to complete the handshake would make the
    TLS layer useless. The certificate is treated strictly as *evidence to
    record*, never as a basis for trust, and nothing confidential is ever sent
    over these connections.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Legacy embedded stacks frequently negotiate only old ciphers; a study that
    # cannot connect to them under-reports exposure, which is the opposite of
    # the goal here.
    context.minimum_version = ssl.TLSVersion.TLSv1
    with contextlib.suppress(ssl.SSLError):  # depends on the OpenSSL build
        context.set_ciphers("DEFAULT@SECLEVEL=0")
    return context


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


async def probe_tcp_listen(
    ip: str,
    port: int,
    config: SentinelConfig,
) -> Observation:
    """Confirm a TCP service is listening and read any volunteered banner.

    **Writes nothing.** For client-speaks-first industrial protocols this
    returns only "listening", which is the honest limit of a zero-payload
    methodology.
    """
    obs = Observation(ip=ip, port=port, scheme="tcp")
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=config.timeouts.connect,
        )
        obs.listening = True
        try:
            data = await asyncio.wait_for(
                reader.read(config.fingerprint.max_banner_bytes),
                timeout=min(config.timeouts.read, 4.0),
            )
            obs.raw_banner = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            # Expected for Modbus/S7/OPC-UA: the server waits for the client.
            obs.raw_banner = ""
    except (asyncio.TimeoutError, OSError) as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await writer.wait_closed()
    return obs


async def probe_http(
    session: aiohttp.ClientSession,
    ip: str,
    port: int,
    config: SentinelConfig,
    scheme: str | None = None,
    probe_paths: Sequence[str] = (),
) -> Observation:
    """Unauthenticated GET against one endpoint, plus optional path probes."""
    chosen = scheme or ("https" if port in _TLS_PORTS else "http")
    obs = Observation(ip=ip, port=port, scheme=chosen)
    url = f"{chosen}://{_bracket(ip)}:{port}/"
    policy = config.fingerprint

    try:
        async with session.get(
            url,
            allow_redirects=policy.follow_redirects,
            max_redirects=policy.max_redirects,
            ssl=_tls_context() if chosen == "https" else None,
        ) as response:
            obs.status = response.status
            obs.headers = {k.lower(): v for k, v in response.headers.items()}
            obs.server_header = obs.headers.get("server", "")
            raw = await response.content.read(policy.max_body_bytes)
            obs.body = raw.decode("utf-8", errors="replace")
            obs.listening = True
            if chosen == "https" and policy.collect_tls_metadata:
                _attach_tls_metadata(obs, response)
    except aiohttp.ClientConnectorSSLError:
        # Port answered but is not TLS (or the inverse). Retry the other scheme
        # once; embedded devices commonly serve HTTP on 8443 and vice versa.
        if scheme is None:
            fallback = "http" if chosen == "https" else "https"
            return await probe_http(
                session, ip, port, config, scheme=fallback, probe_paths=probe_paths
            )
        obs.error = "TLS negotiation failed"
        return obs
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, UnicodeDecodeError) as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
        return obs

    obs.title = _extract_title(obs.body)
    obs.auth_wall = _detect_auth_wall(obs)

    if policy.probe_url_patterns and probe_paths:
        obs.matched_paths = await _probe_paths(session, chosen, ip, port, probe_paths)

    return obs


async def _probe_paths(
    session: aiohttp.ClientSession,
    scheme: str,
    ip: str,
    port: int,
    paths: Sequence[str],
) -> list[str]:
    """GET each candidate path; record those that exist.

    A path "exists" when the response is 200/401/403 -- 401 and 403 count
    because an authenticated-only product endpoint still confirms the product,
    and confirming the product is the entire purpose. No attempt is made to
    reach past the 401.
    """
    found: list[str] = []
    for path in paths:
        url = f"{scheme}://{_bracket(ip)}:{port}{path}"
        try:
            async with session.get(
                url,
                allow_redirects=False,
                ssl=_tls_context() if scheme == "https" else None,
            ) as response:
                if response.status in (200, 401, 403):
                    found.append(path)
                await response.content.read(512)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            continue
    return found


def _attach_tls_metadata(obs: Observation, response: aiohttp.ClientResponse) -> None:
    """Pull certificate details off a live aiohttp connection.

    Reuses the connection already established for the GET rather than opening a
    second one, which keeps the per-host packet budget honest for the evaluation.
    """
    if not _HAVE_X509:
        return
    try:
        connection = response.connection
        transport = getattr(connection, "transport", None)
        ssl_object = transport.get_extra_info("ssl_object") if transport else None
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    except (AttributeError, ValueError, OSError):
        return
    if not der:
        return

    try:
        cert = x509.load_der_x509_certificate(der)
        obs.tls_subject = cert.subject.rfc4514_string()
        obs.tls_issuer = cert.issuer.rfc4514_string()
        obs.tls_not_after = cert.not_valid_after_utc.isoformat()
        obs.tls_self_signed = cert.subject == cert.issuer
        # Touch Encoding so the import is not flagged unused by linters while
        # remaining available for callers that need PEM export.
        _ = Encoding.DER
    except (ValueError, TypeError):  # pragma: no cover -- malformed cert
        obs.tls_subject = None


def _detect_auth_wall(obs: Observation) -> bool:
    """Whether the response represents an authentication boundary."""
    if obs.status in (401, 407):
        return True
    if "www-authenticate" in obs.headers:
        return True
    if obs.status == 403:
        return True
    lowered = obs.body.lower()
    if any(marker in lowered for marker in _LOGIN_MARKERS):
        return True
    return bool(
        obs.status in (301, 302, 303, 307, 308)
        and "login" in str(obs.headers.get("location", "")).lower()
    )


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    return _WS_RE.sub(" ", match.group(1)).strip()[:300]


# ---------------------------------------------------------------------------
# Host-level orchestration
# ---------------------------------------------------------------------------


async def fingerprint_host(
    host: Host,
    session: aiohttp.ClientSession,
    db: SignatureDB,
    config: SentinelConfig,
    pacer: AsyncPacer,
    semaphore: asyncio.Semaphore,
) -> Host:
    """Probe every open port on ``host`` and fold the evidence into the record."""
    observations: list[Observation] = []
    probe_paths = db.url_patterns(config.fingerprint.max_url_probes_per_host)

    for port_state in sorted(host.ports, key=lambda p: p.port):
        if port_state.state != "open" or port_state.proto != "tcp":
            continue
        port = port_state.port
        async with semaphore:
            await pacer.wait()
            if (
                classify_port(port) is PortClass.WEB
                or port in _TLS_PORTS
                or _is_probably_http(port)
            ):
                obs = await probe_http(session, host.ip, port, config, probe_paths=probe_paths)
            else:
                obs = await probe_tcp_listen(host.ip, port, config)
        observations.append(obs)

    _fold_observations(host, observations, db)
    log_event(
        _log,
        "host_fingerprinted",
        f"{len(observations)} probe(s); vendor={host.vendor or 'unknown'} "
        f"confidence={host.confidence:.2f}",
        target=host.ip,
        probe_count=len(observations),
        vendor=host.vendor,
        confidence=host.confidence,
    )
    return host


def _is_probably_http(port: int) -> bool:
    """Whether an OT-class port is actually an embedded web UI.

    9000 (REDY-Process) and 1911-adjacent Niagara web ports serve HTTP; the
    purely binary industrial protocols do not and must be listen-only.
    """
    return port in {9000, 8081, 5000, 7080, 8880}


def _fold_observations(
    host: Host,
    observations: Iterable[Observation],
    db: SignatureDB,
) -> None:
    """Merge probe results into the host record and run signature matching."""
    best: MatchResult = MatchResult()
    best_obs: Observation | None = None
    ot_listening = False
    any_http = False

    for obs in observations:
        if obs.listening and classify_port(obs.port) is PortClass.OT and obs.scheme == "tcp":
            ot_listening = True
            host.notes.append(
                f"port {obs.port}: TCP service listening; no payload sent, so the "
                "protocol is inferred from the port only"
            )
        if obs.scheme in {"http", "https"} and obs.status is not None:
            any_http = True

        result = db.match(obs)
        if result.score > best.score:
            best, best_obs = result, obs

    if best_obs is not None:
        host.banner = best_obs.banner or host.banner
        host.title = best_obs.title or host.title
        host.tls_subject = best_obs.tls_subject or host.tls_subject
        host.tls_issuer = best_obs.tls_issuer or host.tls_issuer
        host.auth_wall = best_obs.auth_wall
    else:
        first = next((o for o in observations if o.listening), None)
        if first is not None:
            host.banner = first.banner or host.banner
            host.auth_wall = first.auth_wall

    ics_confirmed, generic_industrial = db.classify(best)

    host.vendor = best.vendor if best.signature is not None else None
    host.confidence = best.confidence
    host.matched_signature = ",".join(best.layers) if best.layers else None
    if best.signature is not None:
        host.cves = list(best.signature.cves)
        host.mitre_ics = list(best.signature.mitre_ics)

    # Pre-auth disclosure: the device served identifiable operational content to
    # an anonymous GET. Requires a confirmed product AND no authentication
    # boundary -- a login page that merely carries vendor branding is not a
    # disclosure of operational data.
    host.pre_auth_disclosure = bool(ics_confirmed and not host.auth_wall)

    host.evidence = RiskEvidence(
        ics_confirmed=ics_confirmed,
        generic_industrial=generic_industrial,
        auth_wall=host.auth_wall,
        pre_auth_disclosure=host.pre_auth_disclosure,
        ot_protocol_exposed=ot_listening,
        default_cred_risk=bool(best.signature and best.signature.default_cred_risk),
        open_service=bool(host.ports) or any_http,
        known_cves=len(host.cves),
        match_confidence=host.confidence,
    )
    host.source = "fingerprint"


async def fingerprint_hosts(
    hosts: list[Host],
    db: SignatureDB,
    config: SentinelConfig,
    concurrency: int | None = None,
    rate_pps: float | None = None,
) -> list[Host]:
    """Fingerprint many hosts concurrently under a global rate ceiling."""
    if not hosts:
        return []

    all_ports = sorted({p.port for h in hosts for p in h.ports})
    effective_rate, port_class, clamped = config.clamp_rate(
        int(rate_pps) if rate_pps else None, all_ports or [502]
    )
    if clamped:
        log_event(
            _log,
            "rate_clamped",
            f"fingerprint rate lowered to {effective_rate} rps ({port_class.value} ceiling)",
            effective_rate=effective_rate,
            port_class=port_class.value,
            level=30,
        )

    limit = max(1, min(int(concurrency or config.fingerprint.concurrency), 500))
    pacer = AsyncPacer(float(effective_rate))
    semaphore = asyncio.Semaphore(limit)

    timeout = aiohttp.ClientTimeout(
        total=config.timeouts.total,
        connect=config.timeouts.connect,
        sock_read=config.timeouts.read,
    )
    connector = aiohttp.TCPConnector(limit=limit, ssl=False, force_close=True)
    # Exactly these headers; nothing that could carry authentication material.
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}

    async with aiohttp.ClientSession(
        timeout=timeout, connector=connector, headers=headers, trust_env=False
    ) as session:
        tasks = [fingerprint_host(host, session, db, config, pacer, semaphore) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    out: list[Host] = []
    for host, result in zip(hosts, results, strict=True):
        if isinstance(result, BaseException):
            log_event(
                _log,
                "host_probe_failed",
                f"fingerprinting raised {type(result).__name__}: {result}",
                target=host.ip,
                level=40,
            )
            out.append(host)
        else:
            out.append(result)
    return out


def fingerprint_from_fixtures(
    hosts: list[Host],
    db: SignatureDB,
    config: SentinelConfig,
    fixture_dir: str | Path,
) -> list[Host]:
    """``--dry-run`` path: match signatures against recorded banners.

    Fixture layout mirrors the live probe: ``<fixture_dir>/banners/<ip>_<port>.txt``
    holds a raw HTTP response (status line, headers, blank line, body). This is
    how the test suite and the determinism experiment exercise the full matcher
    with zero packets.
    """
    base = Path(fixture_dir)
    for host in hosts:
        observations: list[Observation] = []
        for port_state in sorted(host.ports, key=lambda p: p.port):
            path = base / "banners" / f"{host.ip}_{port_state.port}.txt"
            if not path.is_file():
                observations.append(
                    Observation(ip=host.ip, port=port_state.port, scheme="tcp", listening=True)
                )
                continue
            observations.append(
                parse_raw_http_fixture(
                    host.ip,
                    port_state.port,
                    path.read_text(encoding="utf-8"),
                    max_body_bytes=config.fingerprint.max_body_bytes,
                    max_banner_bytes=config.fingerprint.max_banner_bytes,
                )
            )
        _fold_observations(host, observations, db)
    return hosts


def parse_raw_http_fixture(
    ip: str,
    port: int,
    text: str,
    max_body_bytes: int = 65536,
    max_banner_bytes: int = 2048,
) -> Observation:
    """Parse a recorded raw HTTP response into an :class:`Observation`.

    The same truncation limits as a live probe are applied, so a dry-run match
    cannot succeed on evidence a real probe would never have read. Without that,
    the offline determinism and detection experiments would measure a more
    capable matcher than the one that actually runs.
    """
    scheme = "https" if port in _TLS_PORTS else "http"
    obs = Observation(ip=ip, port=port, scheme=scheme, listening=True)

    head, _, body = text.partition("\n\n")
    if not body:
        head, _, body = text.partition("\r\n\r\n")
    lines = [line.strip() for line in head.splitlines() if line.strip()]

    if lines and lines[0].upper().startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            obs.status = int(parts[1])
        header_lines = lines[1:]
    else:
        # Not an HTTP response: treat the whole fixture as a raw banner.
        obs.raw_banner = text.strip()[:max_banner_bytes]
        obs.scheme = "tcp"
        return obs

    for line in header_lines:
        name, sep, value = line.partition(":")
        if sep:
            obs.headers[name.strip().lower()] = value.strip()

    obs.server_header = obs.headers.get("server", "")
    obs.body = body[:max_body_bytes]
    obs.title = _extract_title(obs.body)
    obs.tls_subject = obs.headers.get("x-fixture-tls-subject")
    obs.tls_issuer = obs.headers.get("x-fixture-tls-issuer")
    if obs.headers.get("x-fixture-paths"):
        obs.matched_paths = [
            p.strip() for p in obs.headers["x-fixture-paths"].split(",") if p.strip()
        ]
    obs.auth_wall = _detect_auth_wall(obs)
    return obs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lower_tuple(value: Any) -> tuple[str, ...]:
    return tuple(str(x).lower() for x in (value or ()))


def _any_in(needles: Iterable[str], haystack: str) -> bool:
    if not haystack:
        return False
    lowered = haystack.lower()
    return any(n and n in lowered for n in needles)


def _any_in_cs(needles: Iterable[str], haystack: str) -> bool:
    """Case-sensitive containment, for JavaScript identifiers."""
    return bool(haystack) and any(n and n in haystack for n in needles)


def _bracket(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


def ensure_port_states(host: Host, ports: Sequence[int]) -> Host:
    """Ensure a host carries :class:`PortState` entries for ``ports``.

    Used by the fingerprint CLI stage when the input JSON lists addresses
    without per-port detail.
    """
    existing = {p.port for p in host.ports}
    for port in ports:
        if port not in existing:
            host.ports.append(PortState(port=port, state="open", proto="tcp"))
    host.ports.sort(key=lambda p: p.port)
    return host
