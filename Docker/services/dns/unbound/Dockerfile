FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    unbound && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/unbound.conf /etc/unbound/unbound.conf
EXPOSE 53/udp 53/tcp
# -d: do not fork (stay in foreground), -p: do not read pidfile
CMD ["unbound", "-d", "-p", "-c", "/etc/unbound/unbound.conf"]
