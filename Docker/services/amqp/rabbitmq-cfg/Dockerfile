FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    rabbitmq-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run/rabbitmq /etc/rabbitmq
# Offer only PLAIN auth (baseline also offers AMQPLAIN): the Connection.Start
# "mechanisms" field in the AMQP handshake therefore differs.
COPY config/rabbitmq.conf /etc/rabbitmq/rabbitmq.conf
EXPOSE 5672
CMD ["/usr/sbin/rabbitmq-server"]
