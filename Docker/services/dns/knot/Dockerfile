FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    knot && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/knot/run && chown -R knot:knot /var/lib/knot
COPY config/knot.conf /etc/knot/knot.conf
COPY config/example.com.zone /etc/knot/example.com.zone
EXPOSE 53/udp 53/tcp
CMD ["knotd", "-c", "/etc/knot/knot.conf"]
