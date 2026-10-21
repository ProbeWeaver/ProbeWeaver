FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dropbear-bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/dropbear
EXPOSE 22
# -F: foreground, -E: log to stderr, -R: auto-generate host keys if missing
CMD ["/usr/sbin/dropbear", "-F", "-E", "-R", "-p", "22"]
