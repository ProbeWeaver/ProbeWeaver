FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    rpcbind rstatd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/rpcbind /var/lib/rpcbind
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh
EXPOSE 111/tcp 111/udp
# -w: warm start (restore registrations from disk).
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["-f", "-w"]
