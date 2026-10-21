#!/usr/bin/env python3
"""telnetlib3 server, configuration variant.

Same library as the baseline pytelnetd service, but it actively negotiates a
different set of IAC options (ECHO + SGA from the server side) and uses a
different greeting and timeout, producing a distinct option-negotiation
fingerprint.
"""

import asyncio
import telnetlib3
from telnetlib3 import WILL, ECHO, SGA

MAX_CONNECTIONS = 5000
_connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)

async def shell(reader, writer):
    async with _connection_semaphore:
        # Server-initiated option negotiation (differs from the baseline,
        # which only reacts to client options).
        writer.iac(WILL, ECHO)
        writer.iac(WILL, SGA)
        writer.write("\r\nWelcome - please authenticate\r\nlogin: ")
        try:
            await asyncio.wait_for(reader.read(1024), timeout=20)
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
        timeout=20,
    )
    print("telnetlib3 (config variant) listening on 0.0.0.0:23", flush=True)
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
