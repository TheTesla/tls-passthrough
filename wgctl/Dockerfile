# Basis: Python Alpine für kleine Größe
FROM python:3.12-alpine

# Labels (optional)
LABEL maintainer="Stefan Helmert <you@example.com>"
LABEL description="WireGuard sync sidecar container"

# Installiere benötigte Pakete: wg (WireGuard CLI) + redis-py Abhängigkeiten
RUN apk add --no-cache wireguard-tools bash

# Arbeitsverzeichnis
WORKDIR /app

# Copy Python Skript
COPY wg_sync.py /app/wg_sync.py
COPY run_sync.sh /app/run_sync.sh

# Installiere Python-Abhängigkeiten
RUN pip install --no-cache-dir redis

# Default Kommando
CMD ["/bin/sh", "/app/run_sync.sh"]

