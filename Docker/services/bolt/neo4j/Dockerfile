FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless wget gnupg2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/apt/keyrings \
    && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | gpg --dearmor -o /etc/apt/keyrings/neotechnology.gpg \
    && echo 'deb [signed-by=/etc/apt/keyrings/neotechnology.gpg] https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends neo4j \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/neo4j/logs && chown -R neo4j:neo4j /var/lib/neo4j
RUN echo "dbms.default_listen_address=0.0.0.0" >> /etc/neo4j/neo4j.conf && \
    echo "dbms.security.auth_enabled=true" >> /etc/neo4j/neo4j.conf
EXPOSE 7687
USER neo4j
ENV NEO4J_AUTH=neo4j/password123
ENV NEO4J_dbms_memory_heap_max__size=512m
CMD ["neo4j", "console"]
