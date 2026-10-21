FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    ircd-hybrid nullidentd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ircd.conf /etc/ircd-hybrid/ircd.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN mkdir -p /var/lib/ircd-hybrid /var/log/ircd-hybrid /run/ircd-hybrid \
    && (id irc >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin irc) \
    && chown -R irc:irc /var/lib/ircd-hybrid /var/log/ircd-hybrid /run/ircd-hybrid \
    && sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh
EXPOSE 6667
ENTRYPOINT ["/docker-entrypoint.sh"]
