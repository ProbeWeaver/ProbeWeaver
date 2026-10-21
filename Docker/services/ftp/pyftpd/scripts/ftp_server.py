#!/usr/bin/env python3
"""Minimal FTP server for protocol fingerprinting research."""

import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

os.makedirs("/home/ftp", exist_ok=True)

authorizer = DummyAuthorizer()
authorizer.add_anonymous("/home/ftp", perm="elr")

handler = FTPHandler
handler.authorizer = authorizer
handler.max_login_attempts = 3
handler.banner = "220 Welcome to FTP server"

server = FTPServer(("0.0.0.0", 21), handler)
server.max_cons = 50
server.max_cons_per_ip = 20

print("FTP server listening on 0.0.0.0:21", flush=True)
server.serve_forever()