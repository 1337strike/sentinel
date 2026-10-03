"""Shared outbound HTTP plumbing for anonymous dataset queries.

Single chokepoint for every synchronous call Sentinel makes to a public
dataset. Centralising it buys four properties that would otherwise have to be
re-implemented (and eventually forgotten) in each module:

* **Bounded.** Connect and read timeouts always set; no unbounded call exists.
* **Polite.** A minimum inter-request interval is enforced process-wide, and
  retries use exponential backoff with full jitter. Sentinel leans on free
  public infrastructure; hammering it would be both rude and self-defeating.
* **Anonymous.** Requests carry exactly two headers: ``User-Agent`` (honest
  self-identification -- evading defensive logging is explicitly out of scope)
  and ``Accept``. No authentication header is constructed anywhere in this
  module, and the URL host is checked against the credential policy allowlist
  before the socket is opened.
* **Replayable.** ``dry_run=True`` serves fixtures from disk instead of the
  network, which is what lets the full pipeline and the experiment suite run
  with no egress at all.
"""

from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from sentinel import USER_AGENT
from sentinel.config.loader import RetryPolicy, SentinelConfig, Timeouts
from sentinel.credguard import assert_endpoint_allowed
from sentinel.logging_setup import get_logger, log_event

_log = get_logger("http")


class DatasetUnavailable(RuntimeError):
    """A dataset could not be reached, or returned an unusable response.

    Deliberately not fatal to a run: the enrichment contract is "leave the field
    null and log ``source_unavailable``", never "substitute a source that needs
    an account".
    """


class FixtureMissing(DatasetUnavailable):
    """``--dry-run`` was requested but no fixture exists for this call."""


class RatePacer:
    """Enforces a minimum interval between outbound requests.

    Thread-safe and shared across modules, so concurrent enrichment of many
    hosts cannot collectively exceed the configured dataset request rate. A
    plain sleep-based pacer is deliberate: for the request volumes involved,
    predictability matters more than throughput, and a predictable pacer is
    what makes the packet-budget figure in the evaluation reproducible.
    """

    __slots__ = ("_min_interval", "_lock", "_last")

    def __init__(self, min_interval: float) -> None:
        self._min_interval = max(0.0, float(min_interval))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> float:
        """Block until the next request is permitted. Returns seconds slept."""
        if self._min_interval <= 0:
            return 0.0
        with self._lock:
            now = time.monotonic()
            earliest = self._last + self._min_interval
            delay = max(0.0, earliest - now)
            self._last = max(now, earliest)
        if delay:
            time.sleep(delay)
        return delay


@dataclass(slots=True)
class HttpClient:
    """Synchronous client for anonymous dataset endpoints."""

    timeouts: Timeouts
    retry: RetryPolicy
    dry_run: bool = False
    fixture_dir: Path | None = None
    cache_dir: Path | None = None
    pacer: RatePacer | None = None
    #: Deterministic jitter source; seeded by the experiment harness so retry
    #: timing does not make a run irreproducible.
    rng: random.Random = field(default_factory=random.Random)
    _session: requests.Session | None = field(default=None, init=False, repr=False)

    @classmethod
    def from_config(
        cls,
        config: SentinelConfig,
        dry_run: bool = False,
        fixture_dir: str | Path | None = None,
        seed: int | None = None,
    ) -> HttpClient:
        return cls(
            timeouts=config.timeouts,
            retry=config.retry,
            dry_run=dry_run,
            fixture_dir=Path(fixture_dir) if fixture_dir else Path("labs/seed"),
            cache_dir=Path(config.paths.cache_dir),
            pacer=RatePacer(config.passive.request_delay),
            rng=random.Random(seed) if seed is not None else random.Random(),
        )

    # -- session ------------------------------------------------------------

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            session = requests.Session()
            # Exactly these headers. Nothing that could carry a credential.
            session.headers.clear()
            session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
            self._session = session
        return self._session

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- public API ---------------------------------------------------------

    def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        fixture: str | None = None,
        allow_404: bool = False,
    ) -> Any:
        """GET and parse JSON.

        ``allow_404`` returns ``None`` for a 404 rather than raising: Shodan
        InternetDB answers 404 for "nothing known about this address", which is
        a legitimate result and not an error.
        """
        text = self.get_text(url, params=params, fixture=fixture, allow_404=allow_404)
        if text is None:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise DatasetUnavailable(f"{url} returned malformed JSON: {exc}") from exc

    def get_text(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        fixture: str | None = None,
        allow_404: bool = False,
    ) -> str | None:
        """GET and return the body as text, or ``None`` for an allowed 404."""
        host = assert_endpoint_allowed(url)

        if self.dry_run:
            name = fixture or _default_fixture_name(url, params)
            # When absence is a legitimate answer for this endpoint, a missing
            # fixture means exactly that: "the dataset knows nothing about this
            # address". Treating it as an error instead would make offline
            # replay impossible the moment a prefix is expanded beyond the
            # handful of addresses that were recorded.
            if allow_404 and not self._fixture_path(name).is_file():
                log_event(
                    _log,
                    "fixture_absent",
                    f"dry-run: no fixture for {name}; treating as 'no record'",
                    fixture=name,
                    dataset_host=host,
                )
                return None
            return self._load_fixture(name, url)

        if self.pacer is not None:
            self.pacer.wait()

        last_error: Exception | None = None
        for attempt in range(1, max(1, self.retry.attempts) + 1):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    timeout=(self.timeouts.connect, self.timeouts.read),
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                last_error = exc
                self._backoff(attempt, url, reason=type(exc).__name__)
                continue

            if response.status_code == 404 and allow_404:
                log_event(
                    _log,
                    "dataset_empty",
                    f"{host} has no record for this query",
                    status=404,
                    dataset_host=host,
                )
                return None

            if response.status_code in self.retry.retry_on_status:
                last_error = DatasetUnavailable(f"{url} returned HTTP {response.status_code}")
                self._backoff(attempt, url, reason=f"http_{response.status_code}")
                continue

            if not response.ok:
                raise DatasetUnavailable(f"{url} returned HTTP {response.status_code}")

            log_event(
                _log,
                "dataset_ok",
                f"{host} responded {response.status_code}",
                status=response.status_code,
                dataset_host=host,
                bytes=len(response.content),
                attempt=attempt,
            )
            return response.text

        raise DatasetUnavailable(
            f"{url} unreachable after {self.retry.attempts} attempt(s): {last_error}"
        )

    def download_cached(
        self,
        url: str,
        name: str,
        max_age_seconds: float = 86_400.0,
        fixture: str | None = None,
    ) -> Path:
        """Fetch a large plain-text asset once and reuse it from the cache.

        Used for RIR delegation files, which are multi-megabyte and change at
        most daily. Returns the local path. In ``dry_run`` the fixture is
        returned directly, so an offline replay never needs the download.
        """
        if self.dry_run:
            path = self._fixture_path(fixture or name)
            if not path.is_file():
                raise FixtureMissing(f"dry-run fixture not found: {path}")
            return path

        cache_root = Path(self.cache_dir or "labs/seed/cache")
        cache_root.mkdir(parents=True, exist_ok=True)
        target = cache_root / name

        if target.is_file() and (time.time() - target.stat().st_mtime) < max_age_seconds:
            log_event(_log, "cache_hit", f"using cached {name}", cache_file=str(target))
            return target

        assert_endpoint_allowed(url)
        if self.pacer is not None:
            self.pacer.wait()

        # Stream to a temporary file and rename, so an interrupted download can
        # never leave a truncated file that later looks like a valid cache hit.
        tmp = target.with_suffix(target.suffix + ".partial")
        try:
            with self.session.get(
                url, stream=True, timeout=(self.timeouts.connect, self.timeouts.total)
            ) as response:
                if not response.ok:
                    raise DatasetUnavailable(f"{url} returned HTTP {response.status_code}")
                with tmp.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=1 << 16):
                        if chunk:
                            handle.write(chunk)
            tmp.replace(target)
        except requests.RequestException as exc:
            tmp.unlink(missing_ok=True)
            raise DatasetUnavailable(f"could not download {url}: {exc}") from exc

        log_event(
            _log,
            "cache_fill",
            f"downloaded {name}",
            cache_file=str(target),
            bytes=target.stat().st_size,
        )
        return target

    # -- internals ----------------------------------------------------------

    def _backoff(self, attempt: int, url: str, reason: str) -> None:
        if attempt >= max(1, self.retry.attempts):
            return
        delay = self.retry.delay_for(attempt)
        if self.retry.jitter:
            delay = self.rng.uniform(0.0, delay)
        log_event(
            _log,
            "dataset_retry",
            f"retrying in {delay:.2f}s ({reason})",
            attempt=attempt,
            reason=reason,
            delay=round(delay, 3),
            dataset_host=urlsplit(url).hostname,
        )
        time.sleep(delay)

    def _fixture_path(self, name: str) -> Path:
        base = Path(self.fixture_dir or "labs/seed")
        return base / name

    def _load_fixture(self, name: str, url: str) -> str:
        path = self._fixture_path(name)
        if not path.is_file():
            raise FixtureMissing(
                f"--dry-run requested but fixture {path} is missing (for {url}). "
                "Record it once with labs/seed/refresh_seed.sh, or add it by hand."
            )
        log_event(_log, "fixture_read", f"dry-run served {path}", fixture=str(path))
        return path.read_text(encoding="utf-8")


def _default_fixture_name(url: str, params: dict[str, Any] | None) -> str:
    """Derive a stable fixture filename from a URL and its query parameters.

    ``https://internetdb.shodan.io/192.0.2.10`` -> ``internetdb.shodan.io/192.0.2.10.json``
    ``.../announced-prefixes/data.json?resource=AS64500``
        -> ``stat.ripe.net/announced-prefixes-AS64500.json``
    """
    parts = urlsplit(url)
    host = parts.hostname or "unknown"
    segments = [s for s in parts.path.split("/") if s and s != "data.json"]
    stem = "-".join(segments) if segments else "index"
    if params:
        suffix = "-".join(str(params[k]) for k in sorted(params) if params[k] is not None)
        if suffix:
            stem = f"{stem}-{suffix}"
    safe = "".join(c if (c.isalnum() or c in "-._") else "_" for c in stem)
    return f"{host}/{safe}.json"
