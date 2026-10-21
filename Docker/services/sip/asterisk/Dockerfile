FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    asterisk && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY config/pjsip.conf /etc/asterisk/pjsip.conf
EXPOSE 5060/udp 5060/tcp
# -f: run in the foreground (no daemonisation), -vvv: console verbosity
CMD ["asterisk", "-f", "-vvv"]
