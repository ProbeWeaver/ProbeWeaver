FROM protocol-base-ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-gi \
    gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
    gir1.2-gst-rtsp-server-1.0 libgstrtspserver-1.0-0 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY scripts/rtsp_server.py /opt/rtsp_server.py
EXPOSE 8554
CMD ["python3", "/opt/rtsp_server.py"]
