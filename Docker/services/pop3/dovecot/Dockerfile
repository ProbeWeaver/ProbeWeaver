FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dovecot-pop3d && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN echo 'protocols = pop3' > /etc/dovecot/local.conf \
    && echo 'listen = 0.0.0.0' >> /etc/dovecot/local.conf \
    && echo 'disable_plaintext_auth = no' >> /etc/dovecot/local.conf \
    && echo 'auth_mechanisms = plain' >> /etc/dovecot/local.conf
EXPOSE 110
CMD ["dovecot", "-F"]
