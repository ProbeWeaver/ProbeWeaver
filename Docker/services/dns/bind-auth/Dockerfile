FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9 bind9utils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/cache/bind /var/run/named && \
    chown -R bind:bind /var/cache/bind /var/run/named
COPY config/named.conf.options /etc/bind/named.conf.options
COPY config/named.conf.local /etc/bind/named.conf.local
COPY config/db.example.com /etc/bind/db.example.com
EXPOSE 53/udp 53/tcp
CMD ["/bin/sh", "-c", "chown -R bind:bind /var/cache/bind && /usr/sbin/named -f -g -u bind"]
