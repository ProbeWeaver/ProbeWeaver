FROM protocol-base-python:latest
# Pin to the classic pysnmp 4.4.x API used by the agent script below.
RUN pip3 install --no-cache-dir "pyasn1==0.4.8" "pysnmp==4.4.12"
COPY scripts/snmp_agent.py /opt/snmp_agent.py
EXPOSE 161/udp
CMD ["python3", "/opt/snmp_agent.py"]
