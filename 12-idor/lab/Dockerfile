# WildWebApps lab base image. Build once (needs network); runs fully offline.
FROM python:3.12-slim

WORKDIR /opt/wildvault

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The app binds 0.0.0.0 inside the container; docker-compose publishes ONLY
# 127.0.0.1:8000 on the host. No root, no extra packages: the flaw is a missing
# authorization check, and the flag lives in memory (the admin's recovery key).
ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["python", "app.py"]
