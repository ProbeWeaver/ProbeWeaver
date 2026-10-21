# KeyDB is a multithreaded Redis fork; use the official upstream image.
FROM eqalpha/keydb:latest
EXPOSE 6379
CMD ["keydb-server", "--bind", "0.0.0.0", "--protected-mode", "no", "--port", "6379", "--save", ""]
