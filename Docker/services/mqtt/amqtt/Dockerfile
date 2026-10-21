FROM protocol-base-python:latest
# aMQTT is the maintained successor of HBMQTT (same Python codebase lineage);
# HBMQTT itself no longer installs on Python 3.10+.
RUN pip3 install --no-cache-dir amqtt
COPY scripts/mqtt_broker.py /opt/mqtt_broker.py
EXPOSE 1883
CMD ["python3", "/opt/mqtt_broker.py"]
