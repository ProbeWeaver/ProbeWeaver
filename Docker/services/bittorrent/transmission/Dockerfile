FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    transmission-daemon && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run/transmission
EXPOSE 9091 51413
CMD ["transmission-daemon", "--foreground", "--allowed", "*.*.*.*", "--port", "9091", "--peerport", "51413", "--no-auth"]
