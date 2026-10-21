#!/usr/bin/env python3
"""AsyncSSH server for protocol fingerprinting research.

AsyncSSH is a mature SSH2 implementation. This script only calls its
standard server API (equivalent to running sshd), it does not hand-roll
the SSH protocol.
"""

import asyncio
import os

import asyncssh

HOST_KEY = "/opt/ssh_host_key"

def ensure_host_key() -> None:
    if not os.path.exists(HOST_KEY):
        key = asyncssh.generate_private_key("ssh-rsa")
        with open(HOST_KEY, "wb") as fh:
            fh.write(key.export_private_key())

class FingerprintServer(asyncssh.SSHServer):
    def connection_made(self, conn) -> None:
        pass

    def begin_auth(self, username: str) -> bool:
        # No authentication required: the handshake/banner is what matters.
        return False

async def main() -> None:
    ensure_host_key()
    await asyncssh.create_server(
        FingerprintServer,
        "0.0.0.0",
        22,
        server_host_keys=[HOST_KEY],
    )
    print("AsyncSSH server listening on 0.0.0.0:22", flush=True)
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
