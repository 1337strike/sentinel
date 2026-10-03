#!/usr/bin/env python3
"""Lab HMI simulator: a configurable static HTTP server for the Sentinel testbed.

Why not nginx: nginx cannot override its own ``Server`` response header without
the third-party headers-more module, and the ``Server`` header is fingerprinting
layer L1 -- the single most important signal under test. A stdlib server gives
exact control over it, plus the ability to serve product-specific endpoints (L5)
and an authentication boundary, with no build step and no dependencies.

Configuration is entirely by environment variable, so one image serves every
vendor mockup:

==================  ====================================================
SERVER_HEADER       Exact ``Server`` header. Empty/unset => suppressed
                    entirely, which exercises the title/JS layers alone.
ROOT                Directory to serve (default /srv/site)
PORT                Listen port (default 80)
PRODUCT_PATHS       Comma-separated paths answering 200 (layer L5)
AUTH_PATHS          Comma-separated paths answering 401 with a
                    WWW-Authenticate challenge (authentication boundary)
AUTH_ALL            "1" => every path except PRODUCT_PATHS answers 401
BANNER_DELAY        Seconds to stall before responding (timeout testing)
==================  ====================================================

This is a passive target. It accepts GET and HEAD and nothing else; there is no
POST handler, no form processing, and no credential checking of any kind. The
401 responses are an authentication *boundary* for the detector to observe, not
an authentication *system* -- no credential is ever accepted or validated, so
there is nothing here to brute-force even in the lab.
"""

from __future__ import annotations

import os
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _csv(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


SERVER_HEADER = os.environ.get("SERVER_HEADER", "").strip()
ROOT = Path(os.environ.get("ROOT", "/srv/site"))
PORT = int(os.environ.get("PORT", "80"))
PRODUCT_PATHS = _csv("PRODUCT_PATHS")
AUTH_PATHS = _csv("AUTH_PATHS")
AUTH_ALL = os.environ.get("AUTH_ALL", "0") == "1"
BANNER_DELAY = float(os.environ.get("BANNER_DELAY", "0"))


class HmiHandler(SimpleHTTPRequestHandler):
    """Static handler with a controllable Server header and product endpoints."""

    protocol_version = "HTTP/1.1"
    # Suppress the default "Python/3.x" suffix; the header is set explicitly.
    sys_version = ""
    server_version = SERVER_HEADER or "srv"

    def version_string(self) -> str:
        return SERVER_HEADER or ""

    def send_response(self, code: int, message: str | None = None) -> None:
        """Send the status line and date, omitting Server when unset.

        Reimplemented rather than calling super() because the base class always
        emits a Server header; a mockup with no Server header is a deliberate
        test case, not an oversight.
        """
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        if SERVER_HEADER:
            self.send_header("Server", SERVER_HEADER)

    def _respond(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8",
                 extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 -- http.server API
        if BANNER_DELAY:
            time.sleep(BANNER_DELAY)

        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path in PRODUCT_PATHS or self.path.rstrip("/") in PRODUCT_PATHS:
            self._respond(200, b'{"status":"ok","endpoint":"product"}\n',
                          "application/json")
            return

        if path in AUTH_PATHS or (AUTH_ALL and path != "/"):
            self._respond(
                401,
                b"<html><head><title>Authentication required</title></head>"
                b"<body><h1>401 Unauthorized</h1></body></html>\n",
                extra={"WWW-Authenticate": 'Basic realm="Station"'},
            )
            return

        if AUTH_ALL and path == "/":
            self._respond(
                401,
                b"<html><head><title>Authentication required</title></head>"
                b"<body><h1>401 Unauthorized</h1></body></html>\n",
                extra={"WWW-Authenticate": 'Basic realm="Station"'},
            )
            return

        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 -- http.server API
        self.do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        # One line per request on stdout, which docker-compose logs collects.
        print(f"[hmi:{PORT}] {fmt % args}", flush=True)  # noqa: T201 -- lab target


def main() -> None:
    if not ROOT.is_dir():
        raise SystemExit(f"ROOT {ROOT} is not a directory")
    handler = partial(HmiHandler, directory=str(ROOT))
    server = ThreadingHTTPServer(("0.0.0.0", PORT), handler)  # noqa: S104 -- lab container
    print(
        f"[hmi] serving {ROOT} on :{PORT} "
        f"server_header={SERVER_HEADER or '<suppressed>'} "
        f"product_paths={PRODUCT_PATHS} auth_all={AUTH_ALL}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
