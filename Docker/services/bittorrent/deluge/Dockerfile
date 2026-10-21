FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    deluged deluge-web && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 8112 6881
# Start the daemon (libtorrent backend), then the web UI in the foreground.
CMD ["sh", "-c", "deluged -d -L info & sleep 5 && exec deluge-web -d"]
