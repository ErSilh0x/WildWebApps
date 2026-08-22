# WildWebApps lab base image. Build once (needs network); runs fully offline.
FROM python:3.12-slim

WORKDIR /opt/wildtools

# The lab shells out to `ping`, which is not in the slim base image. Install it
# (iputils-ping) so the intended command actually runs; nothing else is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
# The container runs as root, which is what puts /root/secret.txt (the flag)
# out of a normal user's reach and makes chaining a command the way to read it.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    SECRET_FILE=/root/secret.txt

EXPOSE 8000

CMD ["python", "app.py"]
