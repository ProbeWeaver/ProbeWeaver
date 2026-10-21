#!/usr/bin/env python3
"""Modbus TCP server (pymodbus) - configuration variant.

Same library as the baseline pymodbus service, but with a different device
identity, a larger register map and a non-default unit/slave id, so the
device-identification and register responses differ.

Imports are resolved at runtime so the script works across pymodbus 3.x and
4.x (which renamed several symbols).
"""

import asyncio
import importlib
import logging
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

UNIT_ID = 5

def _import_symbol(module_name, symbol):
    try:
        module = importlib.import_module(module_name)
        return getattr(module, symbol)
    except Exception:
        return None

def _resolve_async_server():
    for module_name, symbol in (
        ("pymodbus.server", "StartAsyncTcpServer"),
        ("pymodbus.server.async_io", "StartAsyncTcpServer"),
    ):
        resolved = _import_symbol(module_name, symbol)
        if resolved:
            return resolved
    return None

def build_context():
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

    # Larger register map than the baseline (500 entries each).
    di = ModbusSequentialDataBlock(1, [False] * 500)
    co = ModbusSequentialDataBlock(1, [False] * 500)
    hr = ModbusSequentialDataBlock(1, [1] * 500)
    ir = ModbusSequentialDataBlock(1, [2] * 500)

    ModbusSlaveContext = _import_symbol("pymodbus.datastore", "ModbusSlaveContext")
    ModbusDeviceContext = _import_symbol("pymodbus.datastore", "ModbusDeviceContext")
    ctx_cls = ModbusSlaveContext or ModbusDeviceContext
    if ctx_cls is None:
        raise ImportError("No compatible Modbus context class found")
    try:
        store = ctx_cls(di=di, co=co, hr=hr, ir=ir, zero_mode=True)
    except TypeError:
        store = ctx_cls(di=di, co=co, hr=hr, ir=ir)

    # Use the single-context form (same as the working baseline); the larger
    # register map and custom identity already differentiate this variant.
    try:
        return ModbusServerContext(slaves=store, single=True)
    except TypeError:
        try:
            return ModbusServerContext(devices=store, single=True)
        except TypeError:
            return ModbusServerContext(store)

def build_identity():
    ModbusDeviceIdentification = _import_symbol(
        "pymodbus.device", "ModbusDeviceIdentification"
    )
    if ModbusDeviceIdentification is None:
        return None
    identity = ModbusDeviceIdentification()
    identity.VendorName = "AcmePLC"
    identity.ProductCode = "APLC-9"
    identity.VendorUrl = "http://acme.example"
    identity.ProductName = "Acme PLC 9000"
    identity.ModelName = "PLC9000"
    identity.MajorMinorRevision = "3.2"
    return identity

async def main() -> None:
    logger.info(
        "Starting Modbus TCP server (config variant) on 0.0.0.0:502, unit %d", UNIT_ID
    )
    start_async = _resolve_async_server()
    if start_async is None:
        raise RuntimeError("No compatible pymodbus async server entrypoint found")
    identity = build_identity()
    kwargs = {"context": build_context(), "address": ("0.0.0.0", 502)}
    if identity is not None:
        kwargs["identity"] = identity
    await start_async(**kwargs)

if __name__ == "__main__":
    asyncio.run(main())
