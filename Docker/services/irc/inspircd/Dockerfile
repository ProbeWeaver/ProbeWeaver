# InspIRCd is fiddly to configure by hand, so use the upstream maintained image
# (same approach this repo uses for mosquitto/mongo/neo4j). It listens on 6667
# (plaintext clients) out of the box.
FROM inspircd/inspircd-docker:latest
ENV INSP_SERVER_NAME=irc.insp.example \
    INSP_NETWORK_NAME=InspNet \
    INSP_ENABLE_DNSBL=no
EXPOSE 6667
