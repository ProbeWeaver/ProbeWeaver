FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN echo '<!DOCTYPE html><html><body><h1>Apache Test</h1></body></html>' > /var/www/html/index.html
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
