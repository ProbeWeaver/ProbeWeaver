FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dante-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/sockd.conf /etc/sockd.conf
EXPOSE 1080
CMD ["danted", "-f", "/etc/sockd.conf"]
