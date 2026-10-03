"""Scope validation, denylist enforcement, and the active-scan capability grant.

Threat being mitigated
----------------------
The realistic failure mode for a research scanner is not malice, it is
*operator error*: a stale shell history line, a typo'd CIDR, an ``--active``
flag left in a cron entry. Guarding that with ``if args.active and
args.scope_file:`` puts the safety property in the caller, where it can be
forgotten.

Sentinel inverts the dependency. The only function in the codebase that emits
packets (:func:`sentinel.modules.scanner.run_masscan`) requires an
:class:`ActiveGrant` instance as a positional parameter, and that class
cannot be instantiated directly -- its constructor rejects any caller that is
not :meth:`ActiveGrant.from_scope_file`. Minting one requires a scope
file that:

1. exists and parses as YAML;
2. names a human authoriser and an authorization reference;
3. has not expired;
4. lists every authorized CIDR explicitly (no default route, no short prefixes);
5. opts in, per category, to any address class on the standing denylist.

So "active scan without validated authorization" is a construction error at the
top of the call stack, not a missing branch deep inside it.

Denylist policy
---------------
Four address classes are **permanently** refused and cannot be enabled from a
scope file at all: loopback, unspecified, broadcast, and reserved/future-use.
Scanning them is either meaningless or actively harmful (``240.0.0.0/4`` traffic
is a routing-stack hazard, not a target). The remaining classes -- private,
carrier-grade NAT, link-local, multicast -- are denied by default and may be
enabled one category at a time, which is what lets the KVM lab operate on
RFC1918 while an Internet-facing study cannot silently acquire the same
permission.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from sentinel.logging_setup import get_logger, log_event

_log = get_logger("scope")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScopeError(Exception):
    """Scope file is missing, malformed, expired, or incomplete."""


class ScopeViolation(ScopeError):
    """A target is outside the authorized scope, or on the denylist."""


class ModeViolation(ScopeError):
    """An active-only operation was attempted without a capability grant."""


# ---------------------------------------------------------------------------
# Denylist
# ---------------------------------------------------------------------------

#: Address classes that may be opted into from a scope file, one at a time.
OVERRIDABLE_CATEGORIES: frozenset[str] = frozenset(
    {"private", "cgnat", "link_local", "multicast", "documentation", "special"}
)

#: Address classes refused unconditionally. No scope file can enable these:
#: there is no defensible research reason to put packets on them.
PERMANENT_DENY: frozenset[str] = frozenset({"loopback", "unspecified", "broadcast", "reserved"})

#: Absolute floor on prefix length. A scope file may be stricter, never looser.
HARD_MIN_PREFIX_V4 = 8
HARD_MIN_PREFIX_V6 = 32

#: Default floor applied when the scope file does not specify one.
DEFAULT_MIN_PREFIX_V4 = 16
DEFAULT_MIN_PREFIX_V6 = 48

# Explicit range tables. ``ipaddress.is_private`` is deliberately NOT used as
# the definition of "private": it is a coarse union that returns True for RFC
# 5737 documentation ranges, loopback, link-local, 240.0.0.0/4 and more. Relying
# on it mislabels 192.0.2.0/24 as RFC1918, which would then be refused with a
# message telling the operator to allow "private" space -- misleading, and wrong
# about what the range actually is. Categories must be precise, because the
# refusal message is the operator's only explanation for why a scan stopped.

#: RFC 1918 private address space.
_RFC1918_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
#: RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation/example ranges. IANA
#: designates these for use in documentation, which makes them the correct
#: choice for test fixtures -- so they get their own category rather than being
#: lumped in with private space.
_DOC_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_DOC_V6 = (ipaddress.ip_network("2001:db8::/32"),)
#: RFC 6598 carrier-grade NAT.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
#: RFC 2544 benchmark range. Traffic here is a routing-stack hazard.
_BENCHMARK_V4 = ipaddress.ip_network("198.18.0.0/15")
#: RFC 4193 IPv6 unique local addresses -- the IPv6 analogue of RFC1918.
_ULA_V6 = ipaddress.ip_network("fc00::/7")


def _as_network(obj: IPNetwork | IPAddress) -> IPNetwork:
    if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return obj
    return ipaddress.ip_network(f"{obj}/{obj.max_prefixlen}", strict=False)


def _within(net: IPNetwork, candidates: tuple[IPNetwork, ...]) -> bool:
    return any(net.version == c.version and net.subnet_of(c) for c in candidates)  # type: ignore[arg-type]


def classify_address(obj: IPNetwork | IPAddress) -> set[str]:
    """Return the set of denylist categories an address or network falls into.

    An empty set means "ordinary globally routable space". Categories are
    computed on the object itself, so a supernet that merely *contains* denied
    space (for example ``0.0.0.0/0``) is caught by the prefix-length floor
    rather than silently passed.
    """
    cats: set[str] = set()
    net = _as_network(obj)

    # Specific classes first, so the most informative label wins.
    if net.is_loopback:
        cats.add("loopback")
    if net.is_link_local:
        cats.add("link_local")
    if net.is_multicast:
        cats.add("multicast")
    if net.is_unspecified:
        cats.add("unspecified")
    if net.is_reserved:
        cats.add("reserved")

    if net.version == 4:
        if _within(net, _DOC_V4):
            cats.add("documentation")
        if net.subnet_of(_CGNAT_V4):
            cats.add("cgnat")
        if net.subnet_of(_BENCHMARK_V4):
            cats.add("reserved")
        if _within(net, _RFC1918_V4):
            cats.add("private")
        if str(net.broadcast_address) == "255.255.255.255":
            cats.add("broadcast")
    else:
        if _within(net, _DOC_V6):
            cats.add("documentation")
        if net.subnet_of(_ULA_V6):
            cats.add("private")

    # Catch-all: a range the standard library considers special but that none of
    # the explicit tables named. Denied by default under its own category, so an
    # unforeseen reservation is refused rather than silently scanned, and the
    # operator can still authorize it deliberately.
    if not cats and not net.is_global and not net.is_multicast:
        cats.add("special")

    return cats


def denial_reason(net: IPNetwork, allowed_categories: Iterable[str] = ()) -> str | None:
    """Return a human-readable refusal reason, or ``None`` if ``net`` is permitted.

    Single chokepoint for denylist policy; both passive and active paths call it,
    so a range refused for scanning is also refused for dataset expansion.
    """
    allowed = set(allowed_categories)
    cats = classify_address(net)

    permanent = cats & PERMANENT_DENY
    if permanent:
        return f"{net} is {'/'.join(sorted(permanent))} space (permanently refused, no override)"

    blocked = cats - allowed
    if blocked:
        return (
            f"{net} is {'/'.join(sorted(blocked))} space; "
            "add it to 'allow_categories' in the scope file to authorize"
        )
    return None


def scope_hash(cidrs: Iterable[str | IPNetwork]) -> str:
    """Stable digest of a target scope, for the audit log.

    Normalises and sorts first, so the digest identifies the *set* of authorized
    ranges regardless of file ordering or formatting -- which is what makes it
    usable as a run-correlation identifier in the reproducibility protocol.
    """
    normalised = sorted({str(ipaddress.ip_network(str(c), strict=False)) for c in cidrs})
    return hashlib.sha256(",".join(normalised).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Capability grant
# ---------------------------------------------------------------------------

#: Module-private sentinel. Possession of this object is what authorises
#: construction of a grant; it is never exported.
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class ActiveGrant:
    """Capability grant proving a validated scope file authorises active probing.

    Cannot be constructed directly -- use :meth:`from_scope_file`. Frozen, so a
    grant cannot be widened after validation.
    """

    scope_path: str
    cidrs: tuple[str, ...]
    hash: str
    authorized_by: str
    authorization_ref: str
    allowed_categories: frozenset[str]
    expires: date | None = None
    notes: str | None = None
    _issuer: Any = None

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise ModeViolation(
                "ActiveGrant cannot be constructed directly; mint one "
                "with ActiveGrant.from_scope_file(<path>). This guard "
                "exists so active scanning cannot be reached without a "
                "validated scope file."
            )

    # -- construction -------------------------------------------------------

    @classmethod
    def from_scope_file(cls, path: str | Path) -> ActiveGrant:
        """Validate a scope file and mint a grant, or raise :class:`ScopeError`."""
        scope_path = Path(path).expanduser()
        if not scope_path.is_file():
            raise ScopeError(f"scope file not found: {scope_path}")

        try:
            raw = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ScopeError(f"scope file is not valid YAML: {exc}") from exc

        if not isinstance(raw, dict):
            raise ScopeError("scope file must be a YAML mapping")

        authorized_by = str(raw.get("authorized_by", "")).strip()
        authorization_ref = str(raw.get("authorization_ref", "")).strip()
        if not authorized_by:
            raise ScopeError(
                "scope file must set 'authorized_by' -- the person accountable "
                "for this authorization"
            )
        if not authorization_ref:
            raise ScopeError(
                "scope file must set 'authorization_ref' -- ticket, engagement "
                "ID, or lab record documenting the authorization"
            )

        expires = _parse_expiry(raw.get("expires"))
        if expires is not None and expires < datetime.now(timezone.utc).date():
            raise ScopeError(
                f"authorization expired on {expires.isoformat()}; re-authorise before scanning"
            )

        categories = _parse_categories(raw)
        min_v4, min_v6 = _parse_prefix_floors(raw)

        entries = raw.get("authorized_cidrs")
        if not isinstance(entries, list) or not entries:
            raise ScopeError("scope file must set a non-empty 'authorized_cidrs' list")

        validated: list[str] = []
        for entry in entries:
            net = _parse_network(entry)
            _reject_overbroad(net, min_v4, min_v6)
            reason = denial_reason(net, categories)
            if reason:
                raise ScopeViolation(f"scope file lists a denied range: {reason}")
            validated.append(str(net))

        normalised = tuple(sorted(set(validated)))
        grant = cls(
            scope_path=str(scope_path),
            cidrs=normalised,
            hash=scope_hash(normalised),
            authorized_by=authorized_by,
            authorization_ref=authorization_ref,
            allowed_categories=frozenset(categories),
            expires=expires,
            notes=(str(raw["notes"]) if raw.get("notes") else None),
            _issuer=_ISSUER,
        )
        log_event(
            _log,
            "scope_authorized",
            f"active authorization minted for {len(normalised)} range(s)",
            run_scope_hash=grant.hash,
            authorized_by=authorized_by,
            authorization_ref=authorization_ref,
            allowed_categories=sorted(categories),
        )
        return grant

    # -- queries ------------------------------------------------------------

    @property
    def networks(self) -> tuple[IPNetwork, ...]:
        return tuple(ipaddress.ip_network(c) for c in self.cidrs)

    def contains(self, target: str | IPAddress | IPNetwork) -> bool:
        """True when ``target`` is wholly inside an authorized range."""
        try:
            candidate = _coerce_network(target)
        except ValueError:
            return False
        return any(
            candidate.version == net.version and candidate.subnet_of(net)  # type: ignore[arg-type]
            for net in self.networks
        )

    def assert_in_scope(self, target: str | IPAddress | IPNetwork) -> None:
        """Raise :class:`ScopeViolation` unless ``target`` is authorized."""
        if not self.contains(target):
            raise ScopeViolation(
                f"{target} is not inside any authorized range in {self.scope_path}"
            )

    def filter_targets(self, targets: Iterable[str]) -> tuple[list[str], list[tuple[str, str]]]:
        """Partition ``targets`` into ``(authorized, [(target, reason), ...])``."""
        allowed: list[str] = []
        rejected: list[tuple[str, str]] = []
        for target in targets:
            text = str(target).strip()
            if not text:
                continue
            try:
                net = _coerce_network(text)
            except ValueError as exc:
                rejected.append((text, f"unparseable target: {exc}"))
                continue
            reason = denial_reason(net, self.allowed_categories)
            if reason:
                rejected.append((text, reason))
                continue
            if not self.contains(net):
                rejected.append((text, f"outside authorized scope in {self.scope_path}"))
                continue
            allowed.append(str(net))
        return allowed, rejected

    def exclude_file_lines(self) -> list[str]:
        """Denylist ranges handed to masscan's ``--excludefile``.

        Belt and braces: every target has already been checked against the
        scope, but masscan is additionally told at the process level never to
        touch permanently-denied space. If a future change introduces a scope
        bug, the scanner still refuses these ranges.
        """
        lines = [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "198.18.0.0/15",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
        ]
        if "private" not in self.allowed_categories:
            lines.extend(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        if "cgnat" not in self.allowed_categories:
            lines.append("100.64.0.0/10")
        if "link_local" in self.allowed_categories:
            lines.remove("169.254.0.0/16")
        if "multicast" in self.allowed_categories:
            lines.remove("224.0.0.0/4")
        return lines

    def summary(self) -> dict[str, Any]:
        """Audit-log-safe description of the authorization."""
        return {
            "scope_path": self.scope_path,
            "scope_hash": self.hash,
            "cidr_count": len(self.cidrs),
            "authorized_by": self.authorized_by,
            "authorization_ref": self.authorization_ref,
            "allowed_categories": sorted(self.allowed_categories),
            "expires": self.expires.isoformat() if self.expires else None,
        }


# ---------------------------------------------------------------------------
# Passive-path guards
# ---------------------------------------------------------------------------


def validate_passive_targets(
    targets: Iterable[str],
    allow_categories: Iterable[str] = (),
) -> tuple[list[str], list[tuple[str, str]]]:
    """Apply the denylist to passive (dataset-only) targets.

    Passive mode sends nothing to the target, but it still must not ask a
    third-party dataset about loopback or multicast space: those lookups are
    pure noise, and a passive run that quietly accepts ``127.0.0.1`` is a sign
    the input is wrong.
    """
    allowed: list[str] = []
    rejected: list[tuple[str, str]] = []
    for target in targets:
        text = str(target).strip()
        if not text or text.startswith("#"):
            continue
        try:
            net = _coerce_network(text)
        except ValueError as exc:
            rejected.append((text, f"unparseable target: {exc}"))
            continue
        reason = denial_reason(net, allow_categories)
        if reason:
            rejected.append((text, reason))
            continue
        allowed.append(str(net))
    return allowed, rejected


def require_active(grant: ActiveGrant | None, operation: str) -> ActiveGrant:
    """Assert that ``grant`` is a real capability grant before an active operation."""
    if grant is None:
        raise ModeViolation(
            f"{operation} emits packets to targets and requires active "
            "authorization. Pass both --active and --scope-file <path>."
        )
    if not isinstance(grant, ActiveGrant):
        raise ModeViolation(
            f"{operation} received {type(grant).__name__} instead of an "
            "ActiveGrant grant; refusing to proceed."
        )
    if grant.expires is not None and grant.expires < datetime.now(timezone.utc).date():
        raise ModeViolation(
            f"authorization in {grant.scope_path} expired on {grant.expires.isoformat()}"
        )
    return grant


def read_cidr_file(path: str | Path) -> list[str]:
    """Read a newline-delimited CIDR/IP list, ignoring blanks and ``#`` comments."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ScopeError(f"target file not found: {file_path}")
    out: list[str] = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            out.append(text)
    if not out:
        raise ScopeError(f"target file {file_path} contains no targets")
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _coerce_network(target: str | IPAddress | IPNetwork) -> IPNetwork:
    if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return target
    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ipaddress.ip_network(f"{target}/{target.max_prefixlen}", strict=False)
    return ipaddress.ip_network(str(target).strip(), strict=False)


def _parse_network(entry: Any) -> IPNetwork:
    if isinstance(entry, dict):
        # Allow annotated entries: {cidr: 10.0.0.0/24, note: "lab bridge"}
        entry = entry.get("cidr") or entry.get("range") or ""
    try:
        return ipaddress.ip_network(str(entry).strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid CIDR in scope file: {entry!r} ({exc})") from exc


def _reject_overbroad(net: IPNetwork, min_v4: int, min_v6: int) -> None:
    floor = min_v4 if net.version == 4 else min_v6
    if net.prefixlen < floor:
        raise ScopeViolation(
            f"{net} is broader than the /{floor} floor for IPv{net.version}; "
            "authorise specific ranges instead of large supernets"
        )


def _parse_categories(raw: dict[str, Any]) -> set[str]:
    categories: set[str] = set()

    # Documented shorthand for the KVM lab case.
    if bool(raw.get("allow_private", False)):
        categories.add("private")

    declared = raw.get("allow_categories") or []
    if isinstance(declared, str):
        declared = [declared]
    if not isinstance(declared, list):
        raise ScopeError("'allow_categories' must be a list of category names")

    for item in declared:
        name = str(item).strip().lower()
        if name in PERMANENT_DENY:
            raise ScopeViolation(
                f"category '{name}' is permanently denied and cannot be enabled "
                "from a scope file"
            )
        if name not in OVERRIDABLE_CATEGORIES:
            raise ScopeError(
                f"unknown category '{name}'; valid categories: "
                f"{', '.join(sorted(OVERRIDABLE_CATEGORIES))}"
            )
        categories.add(name)

    return categories


def _parse_prefix_floors(raw: dict[str, Any]) -> tuple[int, int]:
    min_v4 = int(raw.get("min_prefix_len_v4", raw.get("min_prefix_len", DEFAULT_MIN_PREFIX_V4)))
    min_v6 = int(raw.get("min_prefix_len_v6", DEFAULT_MIN_PREFIX_V6))
    if min_v4 < HARD_MIN_PREFIX_V4:
        raise ScopeViolation(
            f"min_prefix_len_v4={min_v4} is below the hard floor of /{HARD_MIN_PREFIX_V4}; refusing"
        )
    if min_v6 < HARD_MIN_PREFIX_V6:
        raise ScopeViolation(
            f"min_prefix_len_v6={min_v6} is below the hard floor of /{HARD_MIN_PREFIX_V6}; refusing"
        )
    return min_v4, min_v6


def _parse_expiry(value: Any) -> date | None:
    if value in (None, "", False):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(str(value).strip()).date()
    except ValueError as exc:
        raise ScopeError(f"'expires' must be an ISO date (YYYY-MM-DD), got {value!r}") from exc


@dataclass(slots=True)
class ScopeDecision:
    """Result of a scope evaluation, for reporting and audit."""

    mode: str
    authorized: list[str] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @property
    def hash(self) -> str:
        return scope_hash(self.authorized) if self.authorized else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "authorized_count": len(self.authorized),
            "rejected_count": len(self.rejected),
            "scope_hash": self.hash,
            "rejected": [{"target": t, "reason": r} for t, r in self.rejected],
        }
