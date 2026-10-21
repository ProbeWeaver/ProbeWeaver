FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# lshd needs a server host key. The lsh-server package may already install one,
# and lsh-writekey refuses to overwrite, so remove any existing key first.
RUN rm -f /etc/lsh_host_key /etc/lsh_host_key.pub && \
    lsh-keygen --server | lsh-writekey --server -o /etc/lsh_host_key
EXPOSE 22
# lshd may daemonize; the trailing sleep keeps the container alive in that case.
CMD ["sh", "-c", "lshd --interface=0.0.0.0 -p 22 -h /etc/lsh_host_key --no-syslog; sleep infinity"]
