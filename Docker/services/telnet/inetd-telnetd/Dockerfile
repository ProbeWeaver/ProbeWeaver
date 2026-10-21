FROM protocol-base-ubuntu:latest
# netbase provides /etc/services, which openbsd-inetd needs to resolve the
# "telnet" service name to port 23. Without it inetd silently fails to bind
# (logs "ADD: telnet" but never listens), so connections are reset with no data.
RUN apt-get update && apt-get install -y --no-install-recommends \
    telnetd openbsd-inetd netbase && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run && touch /var/run/utmp
# The telnetd package auto-registers a telnet line in /etc/inetd.conf via
# update-inetd; overwrite it with our own (raised invocation-rate cap) so the
# service is deterministic and survives high-concurrency bursts.
COPY config/inetd.conf /etc/inetd.conf
EXPOSE 23
CMD ["/usr/sbin/inetd", "-d", "/etc/inetd.conf"]
