FROM protocol-base-python:latest
RUN pip install --no-cache-dir pyftpdlib
COPY scripts/ftp_server.py /opt/ftp_server.py
EXPOSE 21
CMD ["python3", "/opt/ftp_server.py"]
