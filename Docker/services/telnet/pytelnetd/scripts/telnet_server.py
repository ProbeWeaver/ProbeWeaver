#!/usr/bin/env python3
"""Telnet server using telnetlib3 for protocol fingerprinting research."""

import asyncio
import telnetlib3

# Maximum concurrent connections to prevent fd / memory exhaustion
MAX_CONNECTIONS = 5000
_connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)

async def shell(reader, writer):
    """Handle a single telnet session."""
    async with _connection_semaphore:
        writer.write("Login: ")
        try:
            # Bound read time to prevent stalled connections from leaking resources
            await asyncio.wait_for(reader.read(1024), timeout=10)
        except (asyncio.TimeoutError, Exception):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

async def main():
    server = await telnetlib3.create_server(
        host="0.0.0.0",
        port=23,
        shell=shell,
        timeout=10,
    )
    print(f"Telnet server listening on 0.0.0.0:23 (max {MAX_CONNECTIONS} connections, 10s timeout)", flush=True)
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())