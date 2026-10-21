#!/usr/bin/env python3
"""pyftpdlib FTP server with a tuned configuration variant.

Same library as the baseline pyftpd service, but with a different banner,
login-attempt limit and passive port range so the fingerprint differs.
"""

import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

os.makedirs("/home/ftp", exist_ok=True)

authorizer = DummyAuthorizer()
authorizer.add_anonymous("/home/ftp", perm="elr")

handler = FTPHandler
handler.authorizer = authorizer
handler.banner = "220 pyftpdlib service ready (config variant)"
handler.max_login_attempts = 5
handler.passive_ports = range(50000, 50010)
handler.timeout = 120

server = FTPServer(("0.0.0.0", 21), handler)
server.max_cons = 100
server.max_cons_per_ip = 10

print("pyftpdlib (config variant) listening on 0.0.0.0:21", flush=True)
server.serve_forever()
