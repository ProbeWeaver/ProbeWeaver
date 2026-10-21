FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    xrdp && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/log/xrdp
COPY config/xrdp.ini /etc/xrdp/xrdp.ini
EXPOSE 3389
CMD ["/usr/sbin/xrdp", "--nodaemon"]
