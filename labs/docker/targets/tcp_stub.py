#!/usr/bin/env python3
"""Lab TCP listener stub for client-speaks-first protocols.

Stands in for S7comm (TCP/102) and Niagara Fox (TCP/1911).

DECLARED LIMITATION -- this is not a protocol implementation
-----------------------------------------------------------
A real S7 or Fox server would need libsnap7 or a licensed Niagara station. For a
*listen-only* detector the two are behaviourally identical: Sentinel opens a
connection, writes nothing, reads whatever is volunteered (nothing, for these
protocols), and records "a service is listening". A stub and a real stack
produce the same observation.

That equivalence holds only because of the zero-payload constraint, and it is
why experiment E1 must not claim S7 or Fox *protocol* identification -- only
port-level ICS classification. ``experiments/ground_truth.yaml`` marks these
targets ``vendor_detectable: false`` for this reason.

If you need genuine protocol fidelity (to produce nmap ground truth, or to test
a payload-sending tool for comparison), replace these services with
snap7-server and a licensed station and re-record the ground truth. See
labs/docker/README.md.

``BANNER`` optionally emits a server-speaks-first greeting, used by the SSH
control target so that the listen-only probe path is also exercised with a
non-empty read.
"""

from __future__ import annotations

import os
import socket
import threading

PORT = int(os.environ.get("PORT", "102"))
LABEL = os.environ.get("LABEL", "tcp-stub")
BANNER = os.environ.get("BANNER", "")
BACKLOG = 32


def handle(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Accept, optionally greet, then wait for the client to speak first."""
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[{LABEL}:{PORT}] connection from {peer}", flush=True)
    try:
        conn.settimeout(20.0)
        if BANNER:
            conn.sendall(BANNER.encode() + b"\r\n")
        # Client-speaks-first: read and discard. Nothing is interpreted, and
        # nothing is ever written in response to received data -- this target
        # must not become something a scanner can be fingerprinted *by*.
        while True:
            data = conn.recv(4096)
            if not data:
                break
    except (TimeoutError, OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))  # noqa: S104 -- lab container
    server.listen(BACKLOG)
    print(
        f"[{LABEL}:{PORT}] listening (stub; writes nothing unless BANNER is set)",
        flush=True,
    )
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
