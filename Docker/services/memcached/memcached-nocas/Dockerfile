FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    memcached && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 11211
# -C disables CAS, changing the behaviour of gets/cas commands.
CMD ["memcached", "-m", "64", "-p", "11211", "-u", "nobody", "-l", "0.0.0.0", "-C"]
