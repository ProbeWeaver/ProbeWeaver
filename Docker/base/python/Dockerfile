FROM protocol-base-ubuntu:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    pymodbus>=3.0.0 \
    paho-mqtt \
    pysnmp \
    pika
