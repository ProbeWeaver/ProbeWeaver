FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    lighttpd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/www/html \
    && echo '<!DOCTYPE html><html><body><h1>Lighttpd Test</h1></body></html>' > /var/www/html/index.html
EXPOSE 80
CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
