FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/bluenviron/mediamtx/releases/download/v1.9.0/mediamtx_v1.9.0_linux_amd64.tar.gz \
    && tar -xzf mediamtx_v1.9.0_linux_amd64.tar.gz \
    && mv mediamtx /usr/local/bin/ \
    && chmod +x /usr/local/bin/mediamtx \
    && rm mediamtx_v1.9.0_linux_amd64.tar.gz
COPY config/mediamtx.yml /etc/mediamtx/mediamtx.yml
EXPOSE 8554
CMD ["/usr/local/bin/mediamtx", "/etc/mediamtx/mediamtx.yml"]
