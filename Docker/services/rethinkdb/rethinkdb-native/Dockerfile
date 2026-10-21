FROM protocol-base-ubuntu:latest
RUN wget -qO- https://download.rethinkdb.com/repository/raw/pubkey.gpg | gpg --dearmor -o /etc/apt/keyrings/rethinkdb.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/rethinkdb.gpg] http://download.rethinkdb.com/repository/ubuntu-jammy jammy main" | tee /etc/apt/sources.list.d/rethinkdb.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends rethinkdb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/rethinkdb/default
EXPOSE 28015
CMD ["rethinkdb", "--bind", "all", "--directory", "/var/lib/rethinkdb/default"]
