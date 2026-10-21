FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    kamailio && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 5060/udp 5060/tcp
CMD ["kamailio", "-DD", "-f", "/etc/kamailio/kamailio.cfg"]
