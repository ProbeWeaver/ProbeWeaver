FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dovecot-imapd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Different greeting + AUTH mechanisms => different * OK CAPABILITY fingerprint.
RUN printf '%s\n' \
    'protocols = imap' \
    'listen = 0.0.0.0' \
    'disable_plaintext_auth = no' \
    'auth_mechanisms = plain login' \
    'login_greeting = IMAP ready (dovecot config variant)' \
    > /etc/dovecot/local.conf
EXPOSE 143
CMD ["dovecot", "-F"]
