FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    libreswan && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ipsec.conf /etc/ipsec.conf
RUN mkdir -p /run/pluto /var/lib/ipsec/nss && ipsec initnss --nssdir /var/lib/ipsec/nss || true
EXPOSE 500/udp 4500/udp
# Run the pluto IKE daemon in the foreground.
CMD ["/usr/libexec/ipsec/pluto", "--nofork", "--config", "/etc/ipsec.conf"]
