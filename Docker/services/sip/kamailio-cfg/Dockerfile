FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    kamailio && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Override the Server/User-Agent headers Kamailio emits (inserted into the
# global section, right after the #!KAMAILIO directive).
RUN sed -i '1a server_header="Server: Kamailio-Variant 1.0"\nuser_agent_header="User-Agent: Kamailio-Variant"' /etc/kamailio/kamailio.cfg
EXPOSE 5060/udp 5060/tcp
CMD ["kamailio", "-DD", "-f", "/etc/kamailio/kamailio.cfg"]
