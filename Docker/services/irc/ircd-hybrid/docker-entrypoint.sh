#!/bin/sh
set -e

# ircd-hybrid 8.2.38 performs ident + reverse-DNS checks before accepting clients.
# Provide identd and map common Docker bridge IPs for gethostbyaddr().
for ip in 127.0.0.1 172.17.0.1 172.18.0.1 172.19.0.1 172.20.0.1; do
    grep -q "$ip" /etc/hosts 2>/dev/null || echo "$ip docker-client" >> /etc/hosts
done

/usr/sbin/nullidentd -f &
sleep 0.3

exec su -s /bin/sh irc -c \
    '/usr/sbin/ircd-hybrid -foreground -configfile /etc/ircd-hybrid/ircd.conf'
