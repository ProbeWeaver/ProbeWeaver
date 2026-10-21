FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    dovecot-pop3d && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Different greeting + advertised AUTH mechanisms => different +OK banner / CAPA.
RUN printf '%s\n' \
    'protocols = pop3' \
    'listen = 0.0.0.0' \
    'disable_plaintext_auth = no' \
    'auth_mechanisms = plain login' \
    'login_greeting = POP3 ready (dovecot config variant)' \
    > /etc/dovecot/local.conf
EXPOSE 110
CMD ["dovecot", "-F"]
