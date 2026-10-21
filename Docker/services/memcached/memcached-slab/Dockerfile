FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    memcached && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 11211
# -f growth factor and -n min space change the slab layout (stats slabs differ).
CMD ["memcached", "-m", "64", "-p", "11211", "-u", "nobody", "-l", "0.0.0.0", "-f", "1.10", "-n", "8"]
