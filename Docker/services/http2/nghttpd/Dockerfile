FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    nghttp2-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/www/html \
    && echo '<!DOCTYPE html><html><body><h1>nghttpd HTTP/2 (h2c) Test</h1></body></html>' > /var/www/html/index.html
EXPOSE 80
# nghttpd is the reference nghttp2 server; --no-tls serves cleartext HTTP/2 (h2c).
CMD ["nghttpd", "--no-tls", "-d", "/var/www/html", "80"]
