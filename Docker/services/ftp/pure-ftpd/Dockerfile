FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    pure-ftpd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/ftp /var/run/pure-ftpd \
    && useradd -d /home/ftp -s /bin/false ftp 2>/dev/null || true \
    && chown ftp:ftp /home/ftp
# Enable anonymous FTP, disable auth requirements
RUN echo "yes" > /etc/pure-ftpd/conf/AnonymousOnly \
    && echo "no" > /etc/pure-ftpd/conf/NoAnonymous \
    && echo "no" > /etc/pure-ftpd/conf/PAMAuthentication \
    && echo "no" > /etc/pure-ftpd/conf/UnixAuthentication \
    && echo "1000" > /etc/pure-ftpd/conf/MinUID \
    && echo "50" > /etc/pure-ftpd/conf/MaxClientsNumber \
    && echo "10" > /etc/pure-ftpd/conf/MaxClientsPerIP \
    && echo "yes" > /etc/pure-ftpd/conf/DontResolve \
    && echo "30" > /etc/pure-ftpd/conf/MaxIdleTime
EXPOSE 21 49152-49162
# -j: auto-create home dir, -4: IPv4 only, -E: anonymous only
# -p: passive port range for data connections
# -B would daemonize (container exits). Instead use entrypoint wrapper to keep alive.
CMD ["sh", "-c", "pure-ftpd -j -4 -E -p 49152:49162 -g /var/run/pure-ftpd/pure-ftpd.pid && sleep infinity"]