FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    ntpsec && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ntp.conf /etc/ntpsec/ntp.conf
RUN mkdir -p /var/lib/ntpsec
EXPOSE 123/udp
# -n: do not fork
CMD ["/usr/sbin/ntpd", "-n", "-c", "/etc/ntpsec/ntp.conf"]
