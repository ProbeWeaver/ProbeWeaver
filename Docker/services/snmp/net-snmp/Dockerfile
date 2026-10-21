FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    snmpd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/snmpd.conf /etc/snmp/snmpd.conf
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo"]
