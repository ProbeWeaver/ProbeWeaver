FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    qbittorrent-nox && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# qbittorrent-nox refuses to run as root, so use a dedicated user.
# Pre-accept the legal notice via config (newer builds reject the
# --confirm-legal-notice CLI flag).
RUN useradd -m -d /home/bt bt \
    && mkdir -p /home/bt/.config/qBittorrent \
    && printf '[LegalNotice]\nAccepted=true\n' > /home/bt/.config/qBittorrent/qBittorrent.conf \
    && chown -R bt:bt /home/bt
USER bt
ENV HOME=/home/bt
EXPOSE 9091 6881
# WebUI on 9091 (matches the baseline transmission port).
CMD ["qbittorrent-nox", "--webui-port=9091"]
