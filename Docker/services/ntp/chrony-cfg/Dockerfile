FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    chrony && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/chrony.conf /etc/chrony/chrony.conf
RUN rm -f /run/chrony/chronyd.pid && mkdir -p /run/chrony
EXPOSE 123/udp
CMD ["sh", "-c", "rm -f /run/chrony/chronyd.pid && chronyd -d"]
