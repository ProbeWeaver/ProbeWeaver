FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd /root/.ssh && ssh-keygen -A
COPY config/sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
