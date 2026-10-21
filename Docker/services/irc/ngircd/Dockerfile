FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    ngircd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/ngircd.conf /etc/ngircd/ngircd.conf
EXPOSE 6667
CMD ["ngircd", "-n"]
