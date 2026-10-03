"""Structured JSON logging.

Every record is emitted as a single line of JSON with a fixed envelope::

    {"ts": ..., "level": ..., "module": ..., "event": ..., "target_hash": ..., "msg": ...}

``target_hash`` rather than a raw address: operational logs from an exposure
study are themselves sensitive, and pseudonymising the target keeps the log
correlatable across runs without turning it into a target list. The mapping is
a keyed digest, so the same address hashes identically within a study but the
log alone does not enumerate hosts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

_TARGET_SALT_ENV = "SENTINEL_TARGET_SALT"
_HASH_LEN = 16

#: Fields that :class:`JsonFormatter` must not copy out of ``record.__dict__``.
_RESERVED = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}


def target_hash(target: str | None) -> str | None:
    """Pseudonymise an IP/CIDR/hostname for log output.

    Uses a salt from ``SENTINEL_TARGET_SALT`` when present. Without a salt the
    digest is still stable but trivially reversible by dictionary attack over
    the IPv4 space -- the docs tell operators to set a salt for any study whose
    logs leave the lab.
    """
    if not target:
        return None
    salt = os.environ.get(_TARGET_SALT_ENV, "")
    digest = hashlib.sha256(f"{salt}|{target}".encode()).hexdigest()
    return digest[:_HASH_LEN]


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "module": record.name,
            "event": getattr(record, "event", record.funcName),
            "target_hash": getattr(record, "target_hash", None),
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        # Carry through any structured extras the caller attached.
        for key, value in record.__dict__.items():
            if key in _RESERVED or key in payload or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value

        return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def configure_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """Install the JSON formatter on the ``sentinel`` logger tree.

    Idempotent: repeated calls (CLI subcommand chaining, tests) replace
    handlers rather than stacking them.
    """
    logger = logging.getLogger("sentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = JsonFormatter()

    if not quiet:
        # Logs go to stderr so that stdout stays a clean machine-readable channel.
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    if log_file:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    return logger


def get_logger(module: str) -> logging.Logger:
    """Return the child logger for a Sentinel module."""
    return logging.getLogger(f"sentinel.{module}")


def log_event(
    logger: logging.Logger,
    event: str,
    msg: str,
    target: str | None = None,
    level: int = logging.INFO,
    **extra: Any,
) -> None:
    """Emit a structured event, hashing ``target`` on the way out."""
    logger.log(
        level,
        msg,
        extra={"event": event, "target_hash": target_hash(target), **extra},
    )
