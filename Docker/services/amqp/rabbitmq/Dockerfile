FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    rabbitmq-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run/rabbitmq && \
    rabbitmq-plugins enable rabbitmq_management || true
EXPOSE 5672
CMD ["/usr/sbin/rabbitmq-server"]
