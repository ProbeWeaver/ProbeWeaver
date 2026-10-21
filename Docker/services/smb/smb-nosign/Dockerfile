FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /tmp/samba /var/log/samba && chmod 777 /tmp/samba
COPY config/smb.conf /etc/samba/smb.conf
EXPOSE 445
CMD ["/usr/sbin/smbd", "-F", "--no-process-group"]
