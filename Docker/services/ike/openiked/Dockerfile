FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    openiked && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/iked.conf /etc/iked.conf
# iked refuses to start if iked.conf is group/world readable.
RUN chmod 600 /etc/iked.conf && mkdir -p /var/empty
EXPOSE 500/udp 4500/udp
# -d: do not daemonize, -v: verbose
CMD ["iked", "-d", "-v", "-f", "/etc/iked.conf"]
