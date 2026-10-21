#!/usr/bin/env python3
"""aMQTT broker (HBMQTT successor) for protocol fingerprinting research.

Python MQTT broker: its CONNACK structure and default keepalive handling
differ from Mosquitto.
"""

import asyncio

from amqtt.broker import Broker

config = {
    "listeners": {
        "default": {"type": "tcp", "bind": "0.0.0.0:1883"},
    },
    "sys_interval": 10,
    "auth": {
        "allow-anonymous": True,
    },
}

async def main() -> None:
    # Broker() calls asyncio.get_running_loop() in __init__, so it must be
    # constructed inside the running event loop, not at import time.
    broker = Broker(config)
    await broker.start()
    print("aMQTT broker listening on 0.0.0.0:1883", flush=True)
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
