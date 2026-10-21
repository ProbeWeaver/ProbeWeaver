FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    redis-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/log/redis && chown -R redis:redis /var/log/redis
COPY config/redis.conf /etc/redis/redis.conf
EXPOSE 6379
CMD ["redis-server", "/etc/redis/redis.conf", "--daemonize", "no"]
