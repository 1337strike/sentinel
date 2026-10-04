#!/usr/bin/env python3
"""Lab Modbus/TCP target (pymodbus).

A *real* Modbus server, not a stub, so the listen-only probe path is exercised
against a genuine client-speaks-first protocol implementation.

What this proves, and what it does not
--------------------------------------
Modbus/TCP has no authentication and no integrity protection by design. A
reachable TCP/502 endpoint is therefore equivalent to unauthenticated process
control, which is why risk.py grades an exposed OT port as MEDIUM even with no
product identification.

Sentinel never sends a Modbus frame, so it can only observe that something is
listening. It cannot read these registers, and the register values below exist
to make the target realistic for *other* tools (an nmap ground-truth pass, for
example), not because Sentinel will ever see them.
"""

from __future__ import annotations

import asyncio
import os

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

PORT = int(os.environ.get("PORT", "502"))
UNIT_ID = int(os.environ.get("UNIT_ID", "1"))


def build_context() -> ModbusServerContext:
    """Plausible process values for a small water-treatment skid."""
    holding = ModbusSequentialDataBlock(
        0,
        [
            625,  # 40001 pump 1 speed, 62.5 Hz scaled x10
            318,  # 40002 tank A level, 3.18 m scaled x100
            214,  # 40003 supply temperature, 21.4 C scaled x10
            1,  # 40004 auto/manual
            0,  # 40005 alarm word
        ]
        + [0] * 95,
    )
    coils = ModbusSequentialDataBlock(0, [1, 0, 1, 0] + [0] * 96)
    discrete = ModbusSequentialDataBlock(0, [1, 1, 0, 0] + [0] * 96)
    inputs = ModbusSequentialDataBlock(0, [230, 495, 12] + [0] * 97)

    slave = ModbusSlaveContext(di=discrete, co=coils, hr=holding, ir=inputs)
    return ModbusServerContext(slaves={UNIT_ID: slave}, single=False)


async def main() -> None:
    print(f"[modbus] listening on 0.0.0.0:{PORT} unit={UNIT_ID}", flush=True)
    await StartAsyncTcpServer(context=build_context(), address=("0.0.0.0", PORT))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
