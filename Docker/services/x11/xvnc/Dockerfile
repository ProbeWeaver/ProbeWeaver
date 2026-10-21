FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    tigervnc-standalone-server tigervnc-common && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 6000
# Xvnc provides an X11 server (TCP 6000) backed by a VNC backend; the exposed
# X11 extension list differs from Xvfb/Xorg.
CMD ["sh", "-c", "rm -f /tmp/.X0-lock; exec Xvnc :0 -SecurityTypes None -geometry 1024x768 -depth 24 -rfbport 5900 -listen tcp -ac"]
