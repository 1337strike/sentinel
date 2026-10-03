"""Zero-credential policy enforcement.

Sentinel runs end to end with no accounts, no registration, and no
authentication material of any kind. Every external data source it contacts is
anonymous and keyless. This module turns that from a claim in a README into a
runtime property.

Design
------
Three enforcement surfaces, in order of strength:

1. **Runtime read guard.** :func:`install` replaces ``os.environ`` with a
   delegating mapping that raises :class:`CredentialPolicyViolation` when
   Sentinel's own code looks up a variable whose name matches a policy pattern.
   This is a tripwire, not a filter: there is no "return None instead" path,
   because quietly degrading would hide a policy regression.

2. **Source scan.** :func:`scan_source_tree` is the programmatic form of the CI
   grep gate, asserted by the test suite.

3. **Endpoint allowlist.** :func:`assert_endpoint_allowed` checks any outbound
   host against the policy's enumerated endpoints, so a future module cannot
   introduce a registration-gated data source without the check failing.

Caller attribution
------------------
The guard fires on the *reader*, not merely on the variable name. That is a
necessity, not a softening: the standard library's ``ssl`` module reads
``SSLKEYLOGFILE`` -- which matches the ``KEY`` pattern -- while building every
default TLS context. A guard that blocked the variable outright would break all
HTTPS in the tool. Equally, a normal developer workstation or CI runner exports
plenty of matching variables for unrelated software; refusing to start because
they *exist* would make Sentinel unrunnable everywhere while proving nothing.
What matters, and what is enforced, is that Sentinel never reads them.

The policy denylist itself lives in ``credential_policy.yaml`` at the project
root rather than in this file. See the comment block in that file for why.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

POLICY_FILENAME = "credential_policy.yaml"

#: Import-path prefix that identifies Sentinel's own code.
_OWN_PACKAGE = "sentinel"

#: This module, excluded when walking the stack to find the real caller.
_SELF = __name__


class CredentialPolicyViolation(RuntimeError):
    """Raised when code attempts something the zero-credential policy forbids."""


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CredentialPolicy:
    """Parsed ``credential_policy.yaml``."""

    env_patterns: tuple[re.Pattern[str], ...] = ()
    allowed_env_reads: frozenset[str] = frozenset()
    allowed_external_readers: tuple[str, ...] = ()
    source_patterns: tuple[str, ...] = ()
    source_scan_excludes: tuple[str, ...] = ()
    allowed_hosts: frozenset[str] = frozenset()
    denied_services: frozenset[str] = frozenset()
    endpoints: tuple[dict[str, str], ...] = ()
    path: Path | None = None

    def matches_env(self, name: str) -> bool:
        """True when ``name`` is a policy-matching variable that is not allowlisted."""
        if name in self.allowed_env_reads:
            return False
        return any(pattern.search(name) for pattern in self.env_patterns)

    def reader_is_exempt(self, module_name: str) -> bool:
        """True when ``module_name`` is an external module permitted to read."""
        return any(
            module_name == prefix or module_name.startswith(prefix + ".")
            for prefix in self.allowed_external_readers
        )


def find_policy_file(start: Path | None = None) -> Path:
    """Locate ``credential_policy.yaml``.

    Searches the working directory first, then walks up from this package so the
    policy is found whether Sentinel runs from a checkout or an installed tree.
    """
    candidates: list[Path] = [Path.cwd() / POLICY_FILENAME]
    base = (start or Path(__file__).resolve()).parent
    for parent in [base, *base.parents][:5]:
        candidates.append(parent / POLICY_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise CredentialPolicyViolation(
        f"{POLICY_FILENAME} not found (searched {', '.join(str(c) for c in candidates)}). "
        "Sentinel refuses to run without its credential policy: an unenforced "
        "policy is worse than a hard failure, because it looks like compliance."
    )


def load_policy(path: str | Path | None = None) -> CredentialPolicy:
    """Load and validate the credential policy."""
    policy_path = Path(path).expanduser() if path else find_policy_file()
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CredentialPolicyViolation(f"{policy_path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise CredentialPolicyViolation(f"{policy_path} must be a YAML mapping")

    endpoints = tuple(raw.get("allowed_endpoints") or ())
    for endpoint in endpoints:
        auth = str(endpoint.get("auth", "")).strip().lower()
        if auth != "none":
            raise CredentialPolicyViolation(
                f"{policy_path} lists endpoint {endpoint.get('host')!r} with "
                f"auth={auth!r}; only anonymous endpoints are permitted"
            )

    patterns = tuple(
        re.compile(str(p), re.IGNORECASE) for p in (raw.get("forbidden_env_patterns") or ())
    )
    if not patterns:
        raise CredentialPolicyViolation(
            f"{policy_path} defines no forbidden_env_patterns; refusing to run "
            "with an empty policy"
        )

    return CredentialPolicy(
        env_patterns=patterns,
        allowed_env_reads=frozenset(str(x) for x in (raw.get("allowed_env_reads") or ())),
        allowed_external_readers=tuple(str(x) for x in (raw.get("allowed_external_readers") or ())),
        source_patterns=tuple(str(x).lower() for x in (raw.get("forbidden_source_patterns") or ())),
        source_scan_excludes=tuple(str(x) for x in (raw.get("source_scan_excludes") or ())),
        allowed_hosts=frozenset(str(e.get("host", "")).lower() for e in endpoints),
        denied_services=frozenset(str(x).lower() for x in (raw.get("denied_services") or ())),
        endpoints=endpoints,
        path=policy_path,
    )


# ---------------------------------------------------------------------------
# Runtime read guard
# ---------------------------------------------------------------------------


def _calling_module(skip_depth: int = 2) -> str:
    """Name of the first module up the stack that is not this one."""
    try:
        frame: Any = sys._getframe(skip_depth)
    except ValueError:  # pragma: no cover -- shallow stack
        return "<unknown>"
    while frame is not None:
        name = str(frame.f_globals.get("__name__", ""))
        if name != _SELF:
            return name or "<unknown>"
        frame = frame.f_back
    return "<unknown>"


class GuardedEnviron(MutableMapping[str, str]):
    """``os.environ`` replacement that refuses credential-shaped reads.

    Delegates everything to the real mapping. Writes and deletions pass through
    untouched: the policy is about *consuming* authentication material, and
    Sentinel legitimately sets variables when launching subprocesses.
    """

    __slots__ = ("_wrapped", "_policy", "_violations", "_blocked_names")

    def __init__(self, wrapped: MutableMapping[str, str], policy: CredentialPolicy) -> None:
        self._wrapped = wrapped
        self._policy = policy
        self._violations: list[tuple[str, str]] = []
        self._blocked_names: set[str] = set()

    # -- the guard ----------------------------------------------------------

    def _check(self, name: str, depth: int = 3) -> None:
        if not self._policy.matches_env(name):
            return
        reader = _calling_module(depth)
        if self._policy.reader_is_exempt(reader):
            return
        if not (reader == _OWN_PACKAGE or reader.startswith(_OWN_PACKAGE + ".")):
            return
        self._violations.append((name, reader))
        self._blocked_names.add(name)
        raise CredentialPolicyViolation(
            f"{reader} attempted to read environment variable {name!r}, which "
            "matches the credential policy. Sentinel is a zero-credential tool: "
            "every data source it uses is anonymous and keyless. If a feature "
            "appears to need this, the correct resolution is to drop the feature "
            "and record it in docs/CREDENTIALS.md, not to read the variable."
        )

    # -- MutableMapping surface --------------------------------------------

    def __getitem__(self, key: str) -> str:
        self._check(key)
        return self._wrapped[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._wrapped[key] = value

    def __delitem__(self, key: str) -> None:
        del self._wrapped[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._wrapped)

    def __len__(self) -> int:
        return len(self._wrapped)

    def __contains__(self, key: object) -> bool:
        # Membership is not a read of the value, so it is allowed: code may ask
        # whether a variable exists (for diagnostics) without consuming it.
        return key in self._wrapped

    def get(self, key: str, default: Any = None) -> Any:
        self._check(key)
        return self._wrapped.get(key, default)

    def copy(self) -> dict[str, str]:
        """Full snapshot, used when building a subprocess environment.

        Not guarded: handing the inherited environment to a child process is not
        Sentinel reading a credential, and stripping variables would break
        unrelated tooling (proxy settings, locale, PATH).
        """
        return dict(self._wrapped)

    def __getattr__(self, item: str) -> Any:
        # Pass through os._Environ extras (encodekey, decodevalue, setdefault...).
        return getattr(self._wrapped, item)

    def __repr__(self) -> str:
        return f"GuardedEnviron({len(self._wrapped)} vars, policy={self._policy.path})"

    # -- introspection ------------------------------------------------------

    @property
    def violations(self) -> list[tuple[str, str]]:
        return list(self._violations)


@dataclass(slots=True)
class GuardReport:
    """Summary of guard installation, recorded in the audit log."""

    policy_path: str
    installed: bool
    patterns: int
    ignored_present: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_path": self.policy_path,
            "guard_installed": self.installed,
            "pattern_count": self.patterns,
            "ignored_env_present": self.ignored_present,
            "ignored_env_count": len(self.ignored_present),
            "allowed_endpoint_hosts": self.allowed_hosts,
            "credentials_required": False,
        }


_original_environ: MutableMapping[str, str] | None = None
_active_policy: CredentialPolicy | None = None


def install(policy: CredentialPolicy | None = None) -> GuardReport:
    """Install the read guard and return a report for the audit log.

    Idempotent. Variables that merely *exist* are enumerated by name (names are
    not confidential; values are never touched) so the audit record shows the
    tool ran in their presence and declined to use them.
    """
    global _original_environ, _active_policy  # noqa: PLW0603 -- process-wide guard

    active = policy or load_policy()
    _active_policy = active

    if not isinstance(os.environ, GuardedEnviron):
        _original_environ = os.environ
        os.environ = GuardedEnviron(os.environ, active)  # type: ignore[assignment]

    present = sorted(name for name in _original_environ or {} if active.matches_env(name))

    return GuardReport(
        policy_path=str(active.path),
        installed=True,
        patterns=len(active.env_patterns),
        ignored_present=present,
        allowed_hosts=sorted(active.allowed_hosts),
    )


def uninstall() -> None:
    """Restore the original ``os.environ`` (test teardown)."""
    global _original_environ  # noqa: PLW0603 -- process-wide guard
    if _original_environ is not None:
        os.environ = _original_environ  # type: ignore[assignment]
        _original_environ = None


def active_policy() -> CredentialPolicy:
    """Return the installed policy, loading it on first use."""
    global _active_policy  # noqa: PLW0603 -- process-wide cache
    if _active_policy is None:
        _active_policy = load_policy()
    return _active_policy


# ---------------------------------------------------------------------------
# Endpoint allowlist
# ---------------------------------------------------------------------------


def assert_endpoint_allowed(url: str, policy: CredentialPolicy | None = None) -> str:
    """Validate an outbound URL against the policy's endpoint allowlist.

    Returns the hostname. Raises :class:`CredentialPolicyViolation` for a host
    that is not enumerated, or that appears in ``denied_services``. Every
    network-touching module routes through this, so adding a registration-gated
    source is a test failure rather than a silent dependency.
    """
    from urllib.parse import urlsplit

    active = policy or active_policy()
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        raise CredentialPolicyViolation(f"cannot determine host for URL {url!r}")

    for denied in active.denied_services:
        if host == denied or host.endswith("." + denied):
            raise CredentialPolicyViolation(
                f"{host} is on the denied-services list: it requires an account "
                "or key. Sentinel has no authenticated code path to use it with."
            )

    if host in active.allowed_hosts:
        return host
    if any(host.endswith("." + allowed) for allowed in active.allowed_hosts):
        return host

    raise CredentialPolicyViolation(
        f"{host} is not in the allowed endpoint list of {active.path}. "
        "Add it there -- with auth: none -- only if it is genuinely anonymous."
    )


# ---------------------------------------------------------------------------
# Source scan (CI gate, in Python form)
# ---------------------------------------------------------------------------


def scan_source_tree(
    root: str | Path,
    policy: CredentialPolicy | None = None,
) -> list[tuple[str, int, str]]:
    """Scan a source tree for credential-shaped identifiers.

    Returns ``[(relative_path, line_number, line)]``. An empty list is the
    passing condition for the CI gate.
    """
    active = policy or active_policy()
    base = Path(root).expanduser().resolve()
    findings: list[tuple[str, int, str]] = []

    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(base).as_posix()
        if any(excl.rstrip("/") in rel for excl in active.source_scan_excludes):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            for pattern in active.source_patterns:
                if pattern in lowered:
                    findings.append((rel, lineno, line.strip()))
                    break

    return findings
