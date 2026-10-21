FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    microsocks && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 1080
# Minimal SOCKS5, no auth. Runs in the foreground.
CMD ["microsocks", "-i", "0.0.0.0", "-p", "1080"]
