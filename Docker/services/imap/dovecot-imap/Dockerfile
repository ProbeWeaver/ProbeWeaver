FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dovecot-imapd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN echo 'protocols = imap' > /etc/dovecot/local.conf \
    && echo 'listen = 0.0.0.0' >> /etc/dovecot/local.conf \
    && echo 'disable_plaintext_auth = no' >> /etc/dovecot/local.conf
EXPOSE 143
CMD ["dovecot", "-F"]
