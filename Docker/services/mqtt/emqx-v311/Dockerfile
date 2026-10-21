# EMQX 4.4 (Erlang broker) for MQTT 3.1.1. CONNACK includes server_keepalive
# and other broker-specific fields not present in Mosquitto.
FROM emqx/emqx:4.4.19
ENV EMQX_ALLOW_ANONYMOUS=true \
    EMQX_LISTENER__TCP__EXTERNAL=1883
EXPOSE 1883
