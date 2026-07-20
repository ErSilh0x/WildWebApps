# WildWebApps lab base image. Build once (needs network to fetch npm deps);
# runs fully offline afterwards.
FROM node:20-slim

# WORKDIR is the app root. The container runs as root, so HOME is /root and the
# flag is planted in /root/.bashrc, matching the paths quoted in the writeup.
WORKDIR /opt/wildportal

# Install dependencies first so the layer is cached when only source changes.
COPY package.json ./
RUN npm install --omit=dev

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    BASHRC_PATH=/root/.bashrc

EXPOSE 8000

CMD ["node", "server.js"]
