ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM $BUILD_FROM

# Python + paho-mqtt (vaste versie, zodat de API voorspelbaar is)
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir --break-system-packages paho-mqtt==2.1.0

COPY collector.py snmp.py devices.py /
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
