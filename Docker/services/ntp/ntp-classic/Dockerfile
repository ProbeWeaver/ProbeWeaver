FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    ntp && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ntp.conf /etc/ntp.conf
RUN mkdir -p /var/lib/ntp
EXPOSE 123/udp
CMD ["/usr/sbin/ntpd", "-n", "-g", "-c", "/etc/ntp.conf"]
