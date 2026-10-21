# Dragonfly is a Redis/RESP-compatible server; use the official upstream image.
FROM docker.dragonflydb.io/dragonflydb/dragonfly:latest
EXPOSE 6379
# --bind exposes RESP on all interfaces inside the container.
# Limit proactor threads + cap memory so it starts on small hosts
# (Dragonfly requires ~256MiB per thread otherwise).
CMD ["dragonfly", "--bind", "0.0.0.0", "--port", "6379", "--proactor_threads=2", "--maxmemory=512mb"]
