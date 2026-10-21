FROM node:20-slim
RUN npm install -g genieacs
# Different MongoDB database + debug behaviour than the baseline GenieACS.
ENV GENIEACS_CWMP_INTERFACE=0.0.0.0 \
    GENIEACS_DEBUG_FILE=/dev/stdout \
    GENIEACS_EXT_DIR=/opt/genieacs/ext
EXPOSE 7547
CMD ["genieacs-cwmp"]
