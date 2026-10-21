FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    proftpd-core && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /srv/ftp \
    && id ftp >/dev/null 2>&1 || useradd -d /srv/ftp -s /usr/sbin/nologin ftp \
    && chown ftp:nogroup /srv/ftp
COPY config/proftpd.conf /etc/proftpd/proftpd.conf
EXPOSE 21
CMD ["proftpd", "--nodaemon", "-c", "/etc/proftpd/proftpd.conf"]
