"""Append-only, hash-chained audit log.

Why a hash chain
----------------
An exposure study is only defensible if you can prove, after the fact, exactly
what was probed and under whose authorization. A plain log file satisfies that
until someone edits it. Each record therefore carries the digest of its
predecessor, so any deletion or in-place edit breaks the chain and
:func:`verify_chain` reports the first bad index.

Append-only is enforced three ways, strongest first:

1. ``os.O_APPEND`` on a raw file descriptor -- the kernel refuses to position
   writes anywhere but the end, even if this process tries.
2. No code path in Sentinel opens the audit file for writing, truncation, or
   deletion. There is no "rotate" or "clear" function by design.
3. ``docs/REPRODUCE.md`` instructs operators to set the filesystem append-only
   attribute (``chattr +a``) on the audit file for any run that will back a
   published result, which stops even a root-owned process from rewriting it.

Mode ``0o600``: the log records which ranges were examined and is treated as
sensitive output.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.logging_setup import get_logger, log_event
from sentinel.models import utc_now_iso

_log = get_logger("audit")

GENESIS_HASH = "0" * 64
_AUDIT_FILE_MODE = 0o600


def _record_digest(payload: dict[str, Any]) -> str:
    """Digest over the canonical form of a record, excluding its own hash field."""
    body = {k: v for k, v in payload.items() if k != "record_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _current_user() -> str:
    """Best-effort operator identity; never fails the run."""
    for getter in (lambda: os.environ.get("SUDO_USER"), getpass.getuser):
        try:
            value = getter()
        except Exception:  # noqa: BLE001 -- identity is advisory, never fatal
            continue
        if value:
            return str(value)
    return "unknown"


@dataclass(slots=True)
class AuditLog:
    """Writer for the per-run audit trail.

    One instance per process. ``run_id`` ties every record from a single
    invocation together, which is how the monitor correlates a diff back to the
    two collection runs that produced it.
    """

    path: Path
    tool_version: str = __version__
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user: str = field(default_factory=_current_user)
    host: str = field(default_factory=socket.gethostname)
    _last_hash: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_tail_hash()

    # -- public API ---------------------------------------------------------

    def record(
        self,
        event: str,
        mode: str,
        summary: dict[str, Any] | None = None,
        scope_hash: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Append one record and return it.

        Parameters mirror the fields the study protocol requires: timestamp,
        operator, tool version, scope hash, mode, and a result summary.
        """
        payload: dict[str, Any] = {
            "ts": utc_now_iso(),
            "run_id": self.run_id,
            "user": self.user,
            "host": self.host,
            "tool_version": self.tool_version,
            "event": event,
            "mode": mode,
            "scope_hash": scope_hash,
            "summary": summary or {},
            "prev_hash": self._last_hash or GENESIS_HASH,
        }
        payload.update({k: v for k, v in extra.items() if k not in payload})
        payload["record_hash"] = _record_digest(payload)

        self._append_line(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        self._last_hash = payload["record_hash"]

        log_event(
            _log,
            "audit_record",
            f"audit event '{event}' recorded",
            run_id=self.run_id,
            audit_event=event,
            scope_hash_=scope_hash,
        )
        return payload

    def record_scope_decision(self, mode: str, decision: Any) -> dict[str, Any]:
        """Convenience wrapper: persist a :class:`~sentinel.modules.scope.ScopeDecision`."""
        return self.record(
            event="scope_decision",
            mode=mode,
            scope_hash=getattr(decision, "hash", None) or None,
            summary=(
                decision.to_dict() if hasattr(decision, "to_dict") else {"decision": str(decision)}
            ),
        )

    # -- internals ----------------------------------------------------------

    def _append_line(self, line: str) -> None:
        """Write one line via a raw O_APPEND descriptor, then fsync.

        fsync because an audit record that is lost in the page cache when the
        lab VM is reverted to a snapshot is worse than no audit log: it is a
        gap you cannot see.
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, _AUDIT_FILE_MODE)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_tail_hash(self) -> str:
        """Recover the chain head so a new process continues an existing log."""
        if not self.path.is_file():
            return ""
        last = ""
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last = line
        except OSError:
            return ""
        if not last:
            return ""
        try:
            return str(json.loads(last).get("record_hash", ""))
        except json.JSONDecodeError:
            # A corrupt tail must not be silently chained onto; verify_chain
            # will surface it, and the new record links to GENESIS so the break
            # is visible rather than papered over.
            return ""


def read_records(path: str | Path) -> list[dict[str, Any]]:
    """Load every record from an audit log, skipping blank lines."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{file_path}:{lineno} is not valid JSON: {exc}") from exc
    return records


def verify_chain(path: str | Path) -> tuple[bool, list[str]]:
    """Verify the hash chain. Returns ``(ok, problems)``.

    Checks both links: that each record's own digest matches its contents
    (no in-place edit) and that ``prev_hash`` matches the preceding record
    (no deletion or reordering).
    """
    records = read_records(path)
    problems: list[str] = []
    expected_prev = GENESIS_HASH

    for index, record in enumerate(records):
        stored = record.get("record_hash")
        recomputed = _record_digest(record)
        if stored != recomputed:
            problems.append(
                f"record {index} has been modified (hash {stored} != recomputed {recomputed})"
            )
        if record.get("prev_hash") != expected_prev:
            problems.append(
                f"record {index} breaks the chain "
                f"(prev_hash {record.get('prev_hash')} != expected {expected_prev})"
            )
        expected_prev = stored or recomputed

    return (not problems), problems
