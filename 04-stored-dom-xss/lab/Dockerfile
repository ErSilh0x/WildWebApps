# WildWebApps lab - Stored XSS (Client-Side / DOM-based).
#
# Base on the official Playwright image: it ships Chromium + all of its system
# libraries, already version-matched to Playwright 1.44. This avoids the brittle
# `playwright install --with-deps` apt step, whose dependency list names
# Ubuntu-only font packages (ttf-unifont, ttf-ubuntu-font-family) that don't
# exist on a Debian `slim` base and break the build.
#
# Build once (needs network to pull the image); the running lab makes no external
# calls - the admin bot only ever browses 127.0.0.1.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

COPY requirements.txt .
# Chromium is already in the image; this pins Flask and guarantees the Playwright
# Python binding is importable. No browser download happens here.
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app binds 0.0.0.0; docker-compose publishes the port
# as 127.0.0.1:8000 on the host, so it stays reachable only from localhost.
ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["python", "app.py"]
