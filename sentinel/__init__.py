"""Sentinel -- defensive exposure monitoring for Internet-facing ICS/SCADA assets.

Design posture
--------------
Sentinel is *passive-first*. The default execution mode emits **zero packets to
any target**: discovery and enrichment are served exclusively from anonymous
public datasets (RIPEstat routing data, Shodan InternetDB, RIR delegation files,
RDAP), the system DNS resolver, and the local ``whois`` binary.

Sentinel is also *zero-credential*: it requires no API keys, no accounts, and no
registration of any kind. :mod:`sentinel.credguard` enforces that at runtime.

Active measurement is gated behind a capability grant
(:class:`sentinel.modules.scope.ActiveGrant`) that can only be minted
from a validated scope file. This is a structural guarantee rather than a
conditional: modules that emit packets accept the grant as a required
parameter, so "active scan without authorization" is a construction error, not
a forgotten ``if`` statement.
"""

from __future__ import annotations

__version__ = "0.1.0"
__tool_name__ = "sentinel"

#: User agent advertised on every outbound HTTP request. Sentinel identifies
#: itself honestly -- evasion of defensive logging is explicitly out of scope.
USER_AGENT = f"{__tool_name__}/{__version__} (+defensive-ics-exposure-research)"

__all__ = ["USER_AGENT", "__tool_name__", "__version__"]
