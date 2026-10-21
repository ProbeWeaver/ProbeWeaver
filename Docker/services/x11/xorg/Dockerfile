FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    xserver-xorg-core xserver-xorg-video-dummy xauth x11-utils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/xorg-dummy.conf /etc/X11/xorg-dummy.conf
EXPOSE 6000
# Real Xorg server with the dummy video driver, listening over TCP (port 6000).
CMD ["sh", "-c", "rm -f /tmp/.X0-lock; exec Xorg :0 -config /etc/X11/xorg-dummy.conf -listen tcp -ac -noreset"]
