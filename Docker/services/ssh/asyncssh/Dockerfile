FROM protocol-base-python:latest
RUN pip3 install --no-cache-dir asyncssh
COPY scripts/ssh_server.py /opt/ssh_server.py
EXPOSE 22
CMD ["python3", "/opt/ssh_server.py"]
