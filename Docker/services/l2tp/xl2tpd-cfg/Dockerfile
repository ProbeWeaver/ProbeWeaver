FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    xl2tpd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
RUN mkdir -p /var/run/xl2tpd /etc/xl2tpd /etc/ppp
RUN touch /etc/xl2tpd/l2tp-secrets
# PPP options variant: require authentication + MPPE, changing the negotiation.
RUN printf "auth\nrequire-mschap-v2\nrequire-mppe-128\nnodefaultroute\nlock\nconnect-delay 5000\n" > /etc/ppp/options.xl2tpd
EXPOSE 1701/udp
CMD ["xl2tpd", "-D", "-c", "/etc/xl2tpd/xl2tpd.conf"]
