FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 500/udp 500/tcp
CMD ["ipsec", "start", "--nofork"]
