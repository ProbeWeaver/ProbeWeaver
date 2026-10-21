FROM protocol-base-ubuntu:latest
RUN wget -qO- https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /etc/apt/keyrings/mongodb-server-7.0.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/mongodb-server-7.0.gpg] http://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends mongodb-org \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/mongodb /var/log/mongodb && \
    chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb
COPY config/mongod.conf /etc/mongod.conf
EXPOSE 27017
CMD ["mongod", "--config", "/etc/mongod.conf", "--bind_ip_all"]
