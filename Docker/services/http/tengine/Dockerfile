FROM protocol-base-ubuntu:latest
# Tengine is an Nginx fork from Alibaba; no apt package, so build from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcre3-dev zlib1g-dev libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/alibaba/tengine/archive/refs/tags/3.1.0.tar.gz -O tengine.tar.gz \
    && tar -xzf tengine.tar.gz \
    && cd tengine-3.1.0 \
    && ./configure --prefix=/usr/local/tengine --with-http_v2_module --with-http_ssl_module \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf tengine-3.1.0 tengine.tar.gz
RUN echo '<!DOCTYPE html><html><body><h1>Tengine Test</h1></body></html>' > /usr/local/tengine/html/index.html
EXPOSE 80
CMD ["/usr/local/tengine/sbin/nginx", "-g", "daemon off;"]
