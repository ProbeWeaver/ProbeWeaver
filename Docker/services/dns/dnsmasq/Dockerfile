FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/dnsmasq.conf /etc/dnsmasq.conf
EXPOSE 53/udp 53/tcp
# -k: keep in foreground (do not daemonize)
CMD ["dnsmasq", "-k", "--conf-file=/etc/dnsmasq.conf"]
