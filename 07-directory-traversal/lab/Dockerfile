# WildWebApps lab base image. Build once (needs network); runs fully offline.
FROM python:3.12-slim

# WORKDIR doubles as DATA_ROOT, so the in-container paths match the ones quoted
# in the writeup (e.g. /opt/wildfiles/secret/.env_backup).
WORKDIR /opt/wildfiles

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    DATA_ROOT=/opt/wildfiles

EXPOSE 8000

CMD ["python", "app.py"]
