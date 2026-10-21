FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    openntpd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ntpd.conf /etc/openntpd/ntpd.conf
EXPOSE 123/udp
# openntpd needs its privsep chroot dir to exist at runtime.
# -d: foreground/debug, -f: config file
CMD ["sh", "-c", "mkdir -p /var/run/openntpd && exec /usr/sbin/ntpd -d -f /etc/openntpd/ntpd.conf"]
