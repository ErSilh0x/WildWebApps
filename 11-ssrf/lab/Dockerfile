# WildWebApps lab base image. Build once (needs network); runs fully offline.
FROM python:3.12-slim

WORKDIR /opt/wildfetch

# iproute2 gives us the `ip` command, used at startup to add the link-local
# metadata address (169.254.169.254) to the loopback interface so the mock
# cloud metadata service can bind it. Nothing else is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The public listener binds 0.0.0.0 inside the container; docker-compose
# publishes ONLY 127.0.0.1:8000 on the host. The internal (8080) and metadata
# (169.254.169.254:80) listeners are never published, which is what makes them
# "internal" and reachable only through the SSRF. The container runs as root so
# the flag can be planted into /etc/passwd and the link-local IP can be added.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    INTERNAL_HOST=127.0.0.1 \
    INTERNAL_PORT=8080 \
    METADATA_HOST=169.254.169.254 \
    METADATA_PORT=80 \
    PASSWD_FILE=/etc/passwd

EXPOSE 8000

# Add the metadata IP to loopback (best effort), then start the app.
CMD ["sh", "-c", "ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true; exec python app.py"]
