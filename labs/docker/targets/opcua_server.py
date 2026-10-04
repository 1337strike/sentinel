#!/usr/bin/env python3
"""Lab OPC-UA target (asyncua).

A real OPC-UA binary endpoint on TCP/4840. Anonymous sessions are permitted,
which mirrors how OPC-UA servers are very often deployed in practice and is
exactly the misconfiguration an exposure study wants to find.

Sentinel will NOT discover that, and the limitation is the point: confirming an
anonymous OPC-UA session requires sending a Hello message and opening a secure
channel, which is a protocol write to an industrial endpoint. The methodology
excludes that, so Sentinel reports "a service is listening on 4840" and stops.
The gap between what is true here and what Sentinel can say is a finding for the
paper's limitations section, not a bug to work around.
"""

from __future__ import annotations

import asyncio
import os

from asyncua import Server, ua

PORT = int(os.environ.get("PORT", "4840"))
NAME = os.environ.get("SERVER_NAME", "LabOpcUaServer")
URI = os.environ.get("NAMESPACE_URI", "urn:sentinel-lab:plant:opcua")


async def main() -> None:
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://0.0.0.0:{PORT}/freeopcua/server/")
    server.set_server_name(NAME)

    # Anonymous access, no encryption: the common real-world posture, and the
    # one worth measuring. Nothing sensitive is behind it.
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    idx = await server.register_namespace(URI)

    plant = await server.nodes.objects.add_object(idx, "Plant")
    line = await plant.add_object(idx, "Line1")
    await line.add_variable(idx, "PumpSpeedHz", 62.5)
    await line.add_variable(idx, "TankLevelM", 3.18)
    await line.add_variable(idx, "SupplyTempC", 21.4)
    await line.add_variable(idx, "Mode", "AUTO")

    print(f"[opcua] listening on 0.0.0.0:{PORT} ns={URI}", flush=True)
    async with server:
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
