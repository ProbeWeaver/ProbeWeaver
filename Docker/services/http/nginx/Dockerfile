FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/nginx.conf /etc/nginx/nginx.conf
RUN echo '<!DOCTYPE html><html><body><h1>HTTP/1.1 Test</h1></body></html>' > /var/www/html/index.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
