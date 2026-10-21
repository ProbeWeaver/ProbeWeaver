FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    inetutils-telnetd socat && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run && touch /var/run/utmp
EXPOSE 23
# socat listens on port 23 and forks a telnetd per connection. The inetutils
# package installs the daemon as /usr/sbin/telnetd (NOT /usr/sbin/in.telnetd),
# so exec'ing the latter failed with "No such file or directory" and every
# connection was closed with zero bytes. telnetd speaks the raw telnet protocol
# on stdin/stdout, so it must NOT be wrapped in a pty (that would mangle the IAC
# option negotiation the client expects as the opening banner).
# -d -d: verbose logging, fork: handle multiple connections, reuseaddr: fast restart
CMD ["socat", "-d", "-d", "TCP-LISTEN:23,fork,reuseaddr,max-children=50", "EXEC:/usr/sbin/telnetd"]