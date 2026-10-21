FROM protocol-base-ubuntu:latest
# Caddy is distributed as a single static Go binary.
RUN wget -q https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz \
    && tar -xzf caddy_2.8.4_linux_amd64.tar.gz caddy \
    && mv caddy /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy \
    && rm caddy_2.8.4_linux_amd64.tar.gz
RUN mkdir -p /var/www/html \
    && echo '<!DOCTYPE html><html><body><h1>Caddy Test</h1></body></html>' > /var/www/html/index.html
COPY config/Caddyfile /etc/caddy/Caddyfile
EXPOSE 80
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
