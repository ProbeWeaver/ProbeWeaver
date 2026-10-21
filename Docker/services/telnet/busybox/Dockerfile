# BusyBox telnetd lives in the Alpine-based busybox image (Ubuntu's busybox
# build does not include the telnetd applet).
FROM busybox:latest
COPY config/inetd.conf /etc/inetd.conf
EXPOSE 23
# Run busybox telnetd behind busybox inetd (one telnetd process per connection)
# instead of a single long-lived `telnetd -F`. A single telnetd serializes the
# fork+pty+exec setup for every connection in one process, so a burst of
# connections drained over ~30s and the service stayed silent for 20s+ after a
# flood (flagged DEGRADED under stress). inetd's nowait mode forks an
# independent `telnetd -i` per connection, so floods are served in parallel and
# the service recovers instantly. -f keeps inetd in the foreground as PID 1.
CMD ["inetd", "-f", "/etc/inetd.conf"]
