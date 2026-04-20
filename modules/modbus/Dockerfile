FROM python:3.11-slim

RUN useradd -m -s /bin/bash modbus && \
    mkdir -p /host-logs/modbus && \
    chown -R modbus:modbus /host-logs/modbus && \
    chmod 777 /host-logs/modbus

COPY modules/modbus/server/server.py /opt/modbus/server.py
RUN chmod +x /opt/modbus/server.py && \
    chown modbus:modbus /opt/modbus/server.py

USER modbus

EXPOSE 502

WORKDIR /opt/modbus
CMD ["python", "server.py", "siemens"]
