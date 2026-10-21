# Valkey is the community fork of Redis; use the official upstream image.
FROM valkey/valkey:8.0
COPY config/valkey.conf /etc/valkey/valkey.conf
EXPOSE 6379
CMD ["valkey-server", "/etc/valkey/valkey.conf"]
