FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
EXPOSE 6000
CMD ["sh", "-c", "rm -f /tmp/.X0-lock /tmp/.X11-unix/X0; exec Xvfb :0 -listen tcp -ac"]
