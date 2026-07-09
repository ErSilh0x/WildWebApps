# WildWebApps SQLi lab - web portal image. Build once (needs network); runs
# fully offline afterwards. Only the Flask app runs here; the four database
# engines are separate services in docker-compose.yml.
FROM python:3.12-slim

WORKDIR /app

# All four drivers ship manylinux wheels (PyMySQL and oracle thin mode are pure
# Python; psycopg2-binary and pymssql bundle their native bits), so no apt build
# deps are needed.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["python", "app.py"]
