FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ipsec.conf /etc/ipsec.conf
EXPOSE 500/udp 4500/udp
CMD ["ipsec", "start", "--nofork"]
