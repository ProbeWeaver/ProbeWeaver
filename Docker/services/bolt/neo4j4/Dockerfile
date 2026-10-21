# Official Neo4j 4.4 image: Bolt v4 handshake / server version differ from the
# baseline neo4j (latest) service.
FROM neo4j:4.4
ENV NEO4J_AUTH=neo4j/password123 \
    NEO4J_dbms_default__listen__address=0.0.0.0 \
    NEO4J_dbms_connector_bolt_listen__address=0.0.0.0:7687
EXPOSE 7687
