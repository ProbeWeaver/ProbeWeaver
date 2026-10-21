#!/bin/sh
set -e
mkdir -p /run/rpcbind /var/lib/rpcbind

# rpcbind must be up before rstatd registers its program with the portmapper.
rpcbind "$@" &
sleep 0.5
/usr/sbin/rpc.rstatd -F &
wait
