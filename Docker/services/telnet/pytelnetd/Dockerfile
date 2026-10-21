FROM protocol-base-python:latest
RUN pip3 install --no-cache-dir telnetlib3
COPY scripts/telnet_server.py /opt/telnet_server.py
EXPOSE 23
CMD ["python3", "/opt/telnet_server.py"]