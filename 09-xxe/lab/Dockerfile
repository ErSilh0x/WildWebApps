# WildWebApps lab base image. Build once (needs network); runs fully offline.
FROM python:3.12-slim

WORKDIR /opt/wildparts

# lxml ships manylinux wheels, so no system build tools are required.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
# The container runs as root, which is what lets the app plant the flag line
# into /etc/passwd at startup (the file the XXE reads).
ENV HOST=0.0.0.0 \
    PORT=8000 \
    PASSWD_FILE=/etc/passwd

EXPOSE 8000

CMD ["python", "app.py"]
