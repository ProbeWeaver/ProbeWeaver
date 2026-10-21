FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9 bind9utils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/cache/bind /var/run/named && \
    chown -R bind:bind /var/cache/bind /var/run/named
COPY config/named.conf.options /etc/bind/named.conf.options
COPY config/db.local /etc/bind/db.local
COPY config/db.127 /etc/bind/db.127
COPY config/db.empty /etc/bind/db.empty
EXPOSE 53
CMD ["/bin/sh", "-c", "chown -R bind:bind /var/cache/bind && /usr/sbin/named -f -g -u bind"]
