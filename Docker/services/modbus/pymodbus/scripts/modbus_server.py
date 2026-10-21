#!/usr/bin/env python3
"""
Modbus TCP Server using pymodbus
For protocol fingerprinting research
"""

import asyncio
import importlib
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def _import_symbol(module_name, symbol):
    try:
        module = importlib.import_module(module_name)
        return getattr(module, symbol)
    except Exception:
        return None

def _resolve_async_server():
    candidates = [
        ("pymodbus.server", "StartAsyncTcpServer"),
        ("pymodbus.server.async_io", "StartAsyncTcpServer"),
        ("pymodbus.server.asynchronous", "StartAsyncTcpServer"),
    ]
    for module_name, symbol in candidates:
        resolved = _import_symbol(module_name, symbol)
        if resolved:
            return resolved
    return None

def _resolve_sync_server():
    candidates = [
        ("pymodbus.server", "StartTcpServer"),
        ("pymodbus.server.sync", "StartTcpServer"),
    ]
    for module_name, symbol in candidates:
        resolved = _import_symbol(module_name, symbol)
        if resolved:
            return resolved
    return None

def _build_context_and_identity():
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

    # Create data blocks (address must be >= 1 in pymodbus >= 3.x)
    coils = ModbusSequentialDataBlock(1, [False] * 100)
    discrete_inputs = ModbusSequentialDataBlock(1, [False] * 100)
    holding_registers = ModbusSequentialDataBlock(1, [0] * 100)
    input_registers = ModbusSequentialDataBlock(1, [0] * 100)

    ModbusSlaveContext = _import_symbol("pymodbus.datastore", "ModbusSlaveContext")
    ModbusDeviceContext = _import_symbol("pymodbus.datastore", "ModbusDeviceContext")

    if ModbusSlaveContext:
        store = ModbusSlaveContext(
            di=discrete_inputs,
            co=coils,
            hr=holding_registers,
            ir=input_registers,
            zero_mode=True
        )
    elif ModbusDeviceContext:
        # Newer pymodbus (v4+) renamed the context type
        try:
            store = ModbusDeviceContext(
                di=discrete_inputs,
                co=coils,
                hr=holding_registers,
                ir=input_registers,
                zero_mode=True
            )
        except TypeError:
            store = ModbusDeviceContext(
                di=discrete_inputs,
                co=coils,
                hr=holding_registers,
                ir=input_registers
            )
    else:
        raise ImportError("No compatible Modbus context class found")

    try:
        context = ModbusServerContext(slaves=store, single=True)
    except TypeError:
        # Newer pymodbus removed the 'slaves' keyword
        try:
            context = ModbusServerContext(store)
        except TypeError:
            context = ModbusServerContext(context=store)

    ModbusDeviceIdentification = _import_symbol("pymodbus.device", "ModbusDeviceIdentification")
    if ModbusDeviceIdentification:
        identity = ModbusDeviceIdentification()
        identity.VendorName = 'ResearchModbus'
        identity.ProductCode = 'RM'
        identity.VendorUrl = 'http://localhost'
        identity.ProductName = 'Modbus Server'
        identity.ModelName = 'Modbus Server'
        identity.MajorMinorRevision = '1.0'
    else:
        identity = None

    return context, identity

async def run_modbus_server():
    """Run Modbus TCP server on port 502"""

    try:
        from pymodbus import __version__ as pymodbus_version
        logger.info(f"Using pymodbus version: {pymodbus_version}")
    except Exception:
        logger.info("Using pymodbus (version unknown)")

    try:
        context, identity = _build_context_and_identity()

        start_async = _resolve_async_server()
        if start_async:
            logger.info("Starting Modbus TCP server (async) on port 502...")
            try:
                if identity is not None:
                    await start_async(
                        context=context,
                        identity=identity,
                        address=('0.0.0.0', 502),
                        allow_reuse_address=True,
                    )
                else:
                    await start_async(
                        context=context,
                        address=('0.0.0.0', 502),
                        allow_reuse_address=True,
                    )
            except TypeError:
                # Older pymodbus does not accept allow_reuse_address
                if identity is not None:
                    await start_async(
                        context=context,
                        identity=identity,
                        address=('0.0.0.0', 502),
                    )
                else:
                    await start_async(
                        context=context,
                        address=('0.0.0.0', 502),
                    )
            return

        start_sync = _resolve_sync_server()
        if start_sync:
            logger.info("Starting Modbus TCP server (sync) on port 502...")
            if identity is not None:
                start_sync(
                    context=context,
                    identity=identity,
                    address=('0.0.0.0', 502)
                )
            else:
                start_sync(
                    context=context,
                    address=('0.0.0.0', 502)
                )
            return

        raise RuntimeError("No compatible pymodbus server entrypoint found")
    except Exception as e:
        logger.error(f"Modbus server error: {e}")
        raise

if __name__ == '__main__':
    try:
        asyncio.run(run_modbus_server())
    except KeyboardInterrupt:
        logger.info("Modbus server stopped by user")
